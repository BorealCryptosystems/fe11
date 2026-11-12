// SPDX-License-Identifier: Apache-2.0
//! Empty candidates only; the resident reference retains all observed data.
use super::*;

pub(crate) enum Candidate {
    Search(SearchCandidate),
    Metadata(ReadStorage, Credit),
    MetadataValue(crate::attributes::owned::resident::ValueCandidate),
    ValueStart(Credit),
    Value(crate::SecretBytes),
    FingerprintStart(ReadStorage, Credit),
    Fingerprint(fingerprint::Candidate),
}
fn reserve(
    bytes: usize,
    policy: &crate::ResourceAdmission,
    waiter: &Waiting<'_>,
) -> Result<Credit> {
    match waiter.budget().reserve_controlled_retaining(
        bytes,
        crate::session::lifecycle_diagnostics::Store::allocation_bytes(),
        policy,
        || {
            waiter.check()?;
            Ok(None::<()>)
        },
        || Ok(None),
    )? {
        ControlledReservation::Acquired(credit) => Ok(credit),
        ControlledReservation::Redirect(()) => unreachable!("no redirect requested"),
    }
}
fn metadata(
    recipe: Recipe<'_>,
    fixed: usize,
    _session: &Session,
    policy: &crate::ResourceAdmission,
    waiter: &Waiting<'_>,
) -> Result<(ReadStorage, Credit)> {
    let mut required =
        ReadStorage::requested(recipe)?
            .checked_add(fixed)
            .ok_or(Error::Rejected(crate::RejectionReason::ObjectReferences(
                crate::ObjectReferencesRejection::ReferenceStorageSize,
            )))?;
    loop {
        let mut credit = reserve(required, policy, waiter)?;
        let storage = ReadStorage::allocate(recipe)?;
        let actual = storage
            .allocated_bytes()?
            .checked_add(fixed)
            .ok_or(Error::Rejected(crate::RejectionReason::ObjectReferences(
                crate::ObjectReferencesRejection::ReferenceStorageSize,
            )))?;
        if actual > required {
            drop(storage);
            drop(credit);
            required = actual;
            continue;
        }
        credit.release(required - actual);
        return Ok((storage, credit));
    }
}
pub(crate) fn prepare(
    need: Need,
    selection: &ObjectReferencePlan,
    content: Option<ContentReadPlan>,
    session: &Session,
    policy: &crate::ResourceAdmission,
    waiter: &Waiting<'_>,
) -> Result<Candidate> {
    match need {
        Need::Search(need) => {
            match SearchCandidate::prepare(need, waiter.budget(), policy, || {
                waiter.check()?;
                Ok(None::<()>)
            })? {
                SearchPreparation::Ready(candidate) => Ok(Candidate::Search(candidate)),
                SearchPreparation::Redirect(()) => unreachable!("no redirect requested"),
            }
        }
        Need::Metadata => {
            let (storage, credit) =
                metadata(Recipe::Reference(selection), 0, session, policy, waiter)?;
            Ok(Candidate::Metadata(storage, credit))
        }
        Need::MetadataValue(need) => {
            crate::attributes::owned::resident::prepare_value(need, waiter.budget(), policy, || {
                waiter.check()
            })
            .map(Candidate::MetadataValue)
        }
        Need::ValueStart(_) => {
            reserve(ContentOwner::fixed_bytes(), policy, waiter).map(Candidate::ValueStart)
        }
        Need::Value(length) => crate::content_controls::owned::resident::prepare_value(
            length,
            waiter.budget(),
            policy,
            || waiter.check(),
        )
        .map(Candidate::Value),
        Need::FingerprintStart(plan) => {
            let (storage, credit) = metadata(
                fingerprint_recipe(plan),
                std::mem::size_of::<fingerprint::FingerprintOwner>(),
                session,
                policy,
                waiter,
            )?;
            Ok(Candidate::FingerprintStart(storage, credit))
        }
        Need::Fingerprint(need) => {
            let Some(ContentReadPlan::PublicFingerprintV1 { read }) = content else {
                return Err(Error::Rejected(crate::RejectionReason::ObjectReferences(
                    crate::ObjectReferencesRejection::ReferenceFingerprintSelection,
                )));
            };
            fingerprint::prepare_candidate(need, read, waiter.budget(), policy, || waiter.check())
                .map(Candidate::Fingerprint)
        }
    }
}

enum InitialSearch {
    Absent,
    Storage {
        plan: SearchPlan,
        storage: Option<SearchStorage>,
    },
    Bound(SearchOwner),
    Consumed,
}
/// Unpublished reference child. Counting and allocation use the same immutable
/// source metadata; the enclosing owner prepays this entire graph together.
pub(crate) struct Initial {
    search: InitialSearch,
    bound: Vec<(IdentityAttribute, AttributeValue)>,
}
impl Initial {
    pub(crate) fn has_search(&self) -> bool {
        matches!(
            self.search,
            InitialSearch::Storage { .. } | InitialSearch::Bound(_)
        )
    }

    /// Native work or retained bound copies require the prepared owner.
    pub(crate) fn requires_preparation(
        selection: &ObjectReferencePlan,
        object: &ManagedObjectRef,
        content: Option<ContentReadPlan>,
    ) -> Result<bool> {
        Ok(
            evaluation::template::<TemplateSize>(selection, object)?.is_some()
                // Even an unavailable search operand can leave other bound
                // values selected. Their copies also require preparation.
                || evaluation::bound_requested_bytes(selection, object)? != 0
                || !selection.attributes.is_empty()
                || content.is_some(),
        )
    }

    pub(crate) fn requested(
        selection: &ObjectReferencePlan,
        object: &ManagedObjectRef,
    ) -> Result<usize> {
        let bound = evaluation::bound_requested_bytes(selection, object)?;
        evaluation::template::<TemplateSize>(selection, object)?
            .map(|(plan, template)| SearchStorage::requested_bytes(template.owned_bytes()?, plan))
            .transpose()?
            .unwrap_or(0)
            .checked_add(std::mem::size_of::<ReferenceOwner>())
            .and_then(|bytes| bytes.checked_add(bound))
            .ok_or(Error::Rejected(crate::RejectionReason::ObjectReferences(
                crate::ObjectReferencesRejection::ReferenceStorageSize,
            )))
    }
    pub(crate) fn allocate(
        selection: &ObjectReferencePlan,
        object: &ManagedObjectRef,
    ) -> Result<Self> {
        let search = match evaluation::template::<Template>(selection, object)? {
            Some((plan, template)) => InitialSearch::Storage {
                plan,
                storage: Some(SearchStorage::allocate_owned(template, plan)?),
            },
            None => InitialSearch::Absent,
        };
        Ok(Self {
            search,
            bound: evaluation::bound(selection, object)?,
        })
    }
    pub(crate) fn allocated_bytes(&self) -> Result<usize> {
        let search = match &self.search {
            InitialSearch::Absent => 0,
            InitialSearch::Storage { storage, .. } => storage
                .as_ref()
                .ok_or(Error::Rejected(crate::RejectionReason::ObjectReferences(
                    crate::ObjectReferencesRejection::ReferenceSearchPreparationAbsent,
                )))?
                .allocated_bytes()?,
            InitialSearch::Bound(_) | InitialSearch::Consumed => {
                return Err(Error::Rejected(crate::RejectionReason::ObjectReferences(
                    crate::ObjectReferencesRejection::ReferencePreparationAlreadyBound,
                )));
            }
        };
        let bound = evaluation::bound_allocated_bytes(&self.bound)?;
        search
            .checked_add(std::mem::size_of::<ReferenceOwner>())
            .and_then(|bytes| bytes.checked_add(bound))
            .ok_or(Error::Rejected(crate::RejectionReason::ObjectReferences(
                crate::ObjectReferencesRejection::ReferenceStorageSize,
            )))
    }
    pub(crate) fn bind(
        mut self,
        session: &Session,
        access: &SessionAccess<'_>,
        object: &ManagedObjectRef,
        selection: ObjectReferencePlan,
        content: ContentObservation,
        epoch: u64,
        protection: ObservationProtection,
        prepaid: &mut Credit,
    ) -> Result<ReferenceOwner> {
        self.bind_retained(
            session,
            access,
            object,
            &selection,
            &mut Some(content),
            epoch,
            &mut Some(protection),
            prepaid,
        )
    }

    pub(crate) fn bind_retained(
        &mut self,
        session: &Session,
        access: &SessionAccess<'_>,
        object: &ManagedObjectRef,
        selection: &ObjectReferencePlan,
        content: &mut Option<ContentObservation>,
        epoch: u64,
        protection: &mut Option<ObservationProtection>,
        prepaid: &mut Credit,
    ) -> Result<ReferenceOwner> {
        if self.has_search() {
            session
                .entry
                .recovery
                .observations
                .check_search_available()?;
        }
        self.bind_prechecked_retained(
            session, access, object, selection, content, epoch, protection, prepaid,
        )
    }

    /// Keep bound metadata, optional search, expected content and protection
    /// with their original owners until all activation checks have succeeded.
    pub(crate) fn bind_prechecked_retained(
        &mut self,
        session: &Session,
        access: &SessionAccess<'_>,
        object: &ManagedObjectRef,
        selection: &ObjectReferencePlan,
        content: &mut Option<ContentObservation>,
        epoch: u64,
        protection: &mut Option<ObservationProtection>,
        prepaid: &mut Credit,
    ) -> Result<ReferenceOwner> {
        if matches!(self.search, InitialSearch::Consumed)
            || content.is_none()
            || protection.is_none()
        {
            return Err(Error::Rejected(crate::RejectionReason::ObjectReferences(
                crate::ObjectReferencesRejection::ReferencePreparationAlreadyConsumed,
            )));
        }
        let handle = session.managed_handle(access, object)?;
        let owner_bytes = evaluation::bound_allocated_bytes(&self.bound)?
            .checked_add(std::mem::size_of::<ReferenceOwner>())
            .ok_or(Error::Rejected(crate::RejectionReason::ObjectReferences(
                crate::ObjectReferencesRejection::ReferenceStorageSize,
            )))?;
        let absent = if matches!(self.search, InitialSearch::Absent) {
            Some(SearchEvidence::observe(selection, None, handle)?)
        } else {
            None
        };
        if let InitialSearch::Storage { plan, storage } = &mut self.search {
            SearchOwner::check_functions(access)?;
            let search = SearchStorage::bind_retained(storage, *plan, epoch, access, prepaid)?;
            self.search = InitialSearch::Bound(search);
        }
        let credit = prepaid.split(owner_bytes)?;
        let stage = match std::mem::replace(&mut self.search, InitialSearch::Consumed) {
            InitialSearch::Absent => {
                Stage::NeedMetadata(absent.expect("prepared absent-search evidence"))
            }
            InitialSearch::Bound(search) => Stage::Search(search),
            InitialSearch::Storage { .. } | InitialSearch::Consumed => {
                unreachable!("validated reference preparation")
            }
        };
        Ok(ReferenceOwner {
            stage,
            bound: std::mem::take(&mut self.bound),
            selection: selection.clone(),
            content: content.take().expect("validated reference content"),
            handle,
            authentication: Some(epoch),
            protection: protection.take().expect("validated reference protection"),
            _credit: credit,
        })
    }
}
