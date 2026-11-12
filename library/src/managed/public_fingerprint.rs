// SPDX-License-Identifier: Apache-2.0
//! Public-key selection and its fingerprint share one catalogue protection.
use super::*;
use crate::{
    attributes::{
        owned::resident::{ReadStorage, Recipe},
        TemplateSink, TemplateSize,
    },
    content_controls::fingerprint_observation::resident as fingerprint,
    session::{
        observation_protection::ObservationProtection,
        recovery::observations::{context, Prepared, Waiting},
        SessionAccess,
    },
    symmetric::memory::{ControlledReservation, Credit},
};
use search::{
    SearchCandidate, SearchNeed, SearchOwner, SearchPreparation, SearchStorage, SearchWithdrawal,
};

enum Phase {
    Search(SearchOwner),
    NeedHeader {
        handle: CK_OBJECT_HANDLE,
        report: crate::ObjectSearchReport,
    },
    Fingerprint {
        handle: CK_OBJECT_HANDLE,
        report: crate::ObjectSearchReport,
        read: Box<fingerprint::FingerprintOwner>,
    },
    Complete {
        content: crate::ProtectedContent,
        report: crate::ObjectSearchReport,
    },
    Stopped,
}
#[derive(Clone, Copy, PartialEq, Eq)]
enum Need {
    Search(SearchNeed),
    Header,
    Fingerprint(fingerprint::Need),
}
pub(crate) struct PublicFingerprintOwner {
    phase: Phase,
    selection: crate::ObjectSearchSelection,
    read: crate::AttributeReadPlan,
    epoch: u64,
    protection: ObservationProtection,
    _credit: Credit,
}
impl PublicFingerprintOwner {
    pub(crate) fn pending(&self) -> bool {
        match &self.phase {
            Phase::Search(search) => search.pending(),
            Phase::Fingerprint { read, .. } => read.pending(),
            _ => false,
        }
    }
    pub(crate) fn search_claimed(&self) -> bool {
        matches!(&self.phase, Phase::Search(search) if search.claimed())
    }
    fn complete(&self) -> bool {
        matches!(self.phase, Phase::Complete { .. })
    }
    fn need(&mut self) -> Result<Option<Need>> {
        Ok(match &mut self.phase {
            Phase::Search(search) => search.need()?.map(Need::Search),
            Phase::NeedHeader { .. } => Some(Need::Header),
            Phase::Fingerprint { read, .. } => read.need().map(Need::Fingerprint),
            _ => None,
        })
    }
    fn advance(&mut self, session: &Session, access: &SessionAccess<'_>) -> Result<()> {
        context(session, Some(self.epoch), self.epoch)?;
        match &mut self.phase {
            Phase::Search(search) => {
                search.advance(session, access)?;
                if !search.complete() {
                    return Ok(());
                }
            }
            Phase::Fingerprint { handle, read, .. } => {
                read.advance(session, access, *handle)?;
                if !read.complete() {
                    return Ok(());
                }
            }
            Phase::NeedHeader { .. } | Phase::Complete { .. } => return Ok(()),
            Phase::Stopped => {
                return Err(Error::Rejected(crate::RejectionReason::ObjectReferences(
                    crate::ObjectReferencesRejection::PublicFingerprintStopped,
                )))
            }
        }
        self.phase = match std::mem::replace(&mut self.phase, Phase::Stopped) {
            Phase::Search(search) => {
                let found = search.into_collection()?;
                let (handle, report) = self.selection.select(&found)?;
                Phase::NeedHeader { handle, report }
            }
            Phase::Fingerprint { read, report, .. } => Phase::Complete {
                content: read.result(session, access, Ok)?,
                report,
            },
            _ => {
                return Err(Error::Rejected(crate::RejectionReason::ObjectReferences(
                    crate::ObjectReferencesRejection::PublicFingerprintCompletionPhase,
                )))
            }
        };
        Ok(())
    }
    fn attach(&mut self, need: Need, candidate: Candidate) -> Result<()> {
        if self.need()? != Some(need) {
            return Err(Error::Rejected(crate::RejectionReason::ObjectReferences(
                crate::ObjectReferencesRejection::PublicFingerprintContinuationChanged,
            )));
        }
        match (need, candidate) {
            (Need::Search(_), Candidate::Search(candidate)) => match &mut self.phase {
                Phase::Search(search) => search.attach(candidate),
                _ => Err(Error::Rejected(crate::RejectionReason::ObjectReferences(
                    crate::ObjectReferencesRejection::PublicFingerprintSearchPhase,
                ))),
            },
            (Need::Fingerprint(need), Candidate::Fingerprint(candidate)) => match &mut self.phase {
                Phase::Fingerprint { read, .. } => read.attach(need, candidate),
                _ => Err(Error::Rejected(crate::RejectionReason::ObjectReferences(
                    crate::ObjectReferencesRejection::PublicFingerprintContentPhase,
                ))),
            },
            (Need::Header, Candidate::Header(storage, mut credit)) => {
                let Phase::NeedHeader { handle, .. } = &self.phase else {
                    unreachable!("need checked")
                };
                let handle = *handle;
                let header = storage.bind_with_protection(
                    &mut credit,
                    recipe(self.read),
                    handle,
                    Some(self.epoch),
                    self.protection.duplicate()?,
                )?;
                let read = Box::new(fingerprint::FingerprintOwner::bind_protected(
                    header,
                    self.read,
                    handle,
                    Some(self.epoch),
                    self.protection.duplicate()?,
                    &mut credit,
                )?);
                let Phase::NeedHeader { report, .. } =
                    std::mem::replace(&mut self.phase, Phase::Stopped)
                else {
                    unreachable!("need checked")
                };
                self.phase = Phase::Fingerprint {
                    handle,
                    report,
                    read,
                };
                Ok(())
            }
            _ => Err(Error::Rejected(crate::RejectionReason::ObjectReferences(
                crate::ObjectReferencesRejection::PublicFingerprintCandidateKind,
            ))),
        }
    }
    fn finish_search(&mut self, session: &Session, access: &SessionAccess<'_>) -> Result<()> {
        match &mut self.phase {
            Phase::Search(search) => search.finish(session, access),
            _ => Ok(()),
        }
    }
    fn result(
        self,
        session: &Session,
        access: &SessionAccess<'_>,
    ) -> Result<(SecretBytes, crate::ObjectSearchReport)> {
        let Phase::Complete { content, report } = self.phase else {
            return Err(Error::Rejected(crate::RejectionReason::ObjectReferences(
                crate::ObjectReferencesRejection::PublicFingerprintIncomplete,
            )));
        };

        session.metadata_result(
            access,
            Some(self.epoch),
            content.into_bytes().map(|bytes| (bytes, report)),
        )
    }
}
fn recipe(read: crate::AttributeReadPlan) -> Recipe<'static> {
    Recipe::Fingerprint {
        fields: &[
            crate::attributes::FingerprintAttribute::Class,
            crate::attributes::FingerprintAttribute::KeyType,
        ],
        plan: read,
    }
}
fn template<T: TemplateSink>(id: &[u8]) -> T {
    let mut template = T::empty();
    template.integer(CKA_CLASS, CKO_PUBLIC_KEY);
    template.bytes(CKA_ID, id);
    template
}
enum Candidate {
    Search(SearchCandidate),
    Header(ReadStorage, Credit),
    Fingerprint(fingerprint::Candidate),
}
fn prepare(
    need: Need,
    read: crate::AttributeReadPlan,
    policy: &crate::ResourceAdmission,
    waiter: &Waiting<'_>,
) -> Result<Candidate> {
    match need {
        Need::Search(need) => {
            match SearchCandidate::prepare(need, waiter.budget(), policy, || {
                waiter.check()?;
                Ok(None::<()>)
            })? {
                SearchPreparation::Ready(value) => Ok(Candidate::Search(value)),
                SearchPreparation::Redirect(()) => unreachable!("no redirect requested"),
            }
        }
        Need::Fingerprint(need) => {
            fingerprint::prepare_candidate(need, read, waiter.budget(), policy, || waiter.check())
                .map(Candidate::Fingerprint)
        }
        Need::Header => {
            let fixed = std::mem::size_of::<fingerprint::FingerprintOwner>();
            let mut required = ReadStorage::requested(recipe(read))?
                .checked_add(fixed)
                .ok_or(Error::Rejected(crate::RejectionReason::ObjectReferences(
                    crate::ObjectReferencesRejection::PublicFingerprintStorageSize,
                )))?;
            loop {
                let mut credit = match waiter.budget().reserve_controlled_retaining(
                    required,
                    crate::session::lifecycle_diagnostics::Store::allocation_bytes(),
                    policy,
                    || {
                        waiter.check()?;
                        Ok(None::<()>)
                    },
                    || Ok(None),
                )? {
                    ControlledReservation::Acquired(credit) => credit,
                    ControlledReservation::Redirect(()) => unreachable!("no redirect requested"),
                };
                let storage = ReadStorage::allocate(recipe(read))?;
                let actual =
                    storage
                        .allocated_bytes()?
                        .checked_add(fixed)
                        .ok_or(Error::Rejected(crate::RejectionReason::ObjectReferences(
                            crate::ObjectReferencesRejection::PublicFingerprintStorageSize,
                        )))?;
                if actual > required {
                    drop(storage);
                    drop(credit);
                    required = actual;
                    continue;
                }
                credit.release(required - actual);
                return Ok(Candidate::Header(storage, credit));
            }
        }
    }
}

pub(super) fn observe(
    session: &Session,
    id: &[u8],
    search_plan: SearchPlan,
    read: crate::AttributeReadPlan,
    selection: crate::ObjectSearchSelection,
) -> Result<(SecretBytes, crate::ObjectSearchReport)> {
    id_valid(id)?;
    let reference = session.reference_admission(
        crate::session::ReferenceMode::Synchronous,
        Session::reference_search_functions,
    )?;
    let progress = reference.progress();
    let epoch = session.snapshot.authentication_stamp();
    let policy = crate::admission_wait::current();
    let fixed = Prepared::allocation_bytes()
        .checked_add(std::mem::size_of::<PublicFingerprintOwner>())
        .and_then(|n| n.checked_add(crate::error::PreparedCleanupDiagnostic::allocation_bytes()))
        .and_then(|bytes| bytes.checked_add(ObservationProtection::selection_bytes()))
        .ok_or(Error::Rejected(crate::RejectionReason::ObjectReferences(
            crate::ObjectReferencesRejection::PublicFingerprintStorageSize,
        )))?;
    let selection_bytes = ManagedSelectionStorage::requested_key_bytes(id)?;
    let mut required =
        SearchStorage::requested_bytes(template::<TemplateSize>(id).owned_bytes()?, search_plan)?
            .checked_add(fixed)
            .and_then(|bytes| bytes.checked_add(selection_bytes))
            .ok_or(Error::Rejected(crate::RejectionReason::ObjectReferences(
                crate::ObjectReferencesRejection::PublicFingerprintStorageSize,
            )))?;
    let (mut search_cleanup, coordination, first_access) = loop {
        context(session, Some(epoch), epoch)?;
        policy.check_available()?;
        session.admission().check_available()?;
        let mut credit =
            crate::advanced::reserve_preparation_with_progress(session, required, progress)?;
        let storage = SearchStorage::allocate_owned(template::<Template>(id), search_plan)?;
        let prepared_selection =
            ManagedSelectionStorage::allocate_key(ManagedClass::PublicKey, id)?;
        let actual = storage
            .allocated_bytes()?
            .checked_add(fixed)
            .and_then(|bytes| bytes.checked_add(prepared_selection.allocated_bytes()))
            .ok_or(Error::Rejected(crate::RejectionReason::ObjectReferences(
                crate::ObjectReferencesRejection::PublicFingerprintStorageSize,
            )))?;
        if actual > required {
            drop(prepared_selection);
            drop(storage);
            drop(credit);
            required = actual;
            continue;
        }
        credit.release(required - actual);
        credit.observation_budget()?;
        let search_cleanup = crate::error::PreparedCleanupDiagnostic::prepare(&mut credit)?;
        let registry = Prepared::allocate(&session.inner.symmetric_budget, &mut credit)?;
        let prepared_selection = prepared_selection.bind(session, &mut credit)?;
        let access = match session.try_operation_access_progress(false, progress) {
            Ok(access) => access,
            Err(Error::Busy(_)) => {
                drop(search_cleanup);
                drop(prepared_selection);
                drop(storage);
                drop(registry);
                drop(credit);
                drop(session.access_progress(progress)?);
                continue;
            }
            Err(error) => return Err(error),
        };
        context(session, Some(epoch), epoch)?;
        reference.check(&access)?;
        SearchOwner::check_functions(&access)?;
        session
            .entry
            .recovery
            .observations
            .check_search_available()?;
        let selected = prepared_selection
            .select(session)?
            .into_owned(&session.inner, &session.entry)?;
        let protection = ObservationProtection::selection(session, selected, &mut credit)?;
        let owner = PublicFingerprintOwner {
            phase: Phase::Search(storage.bind(search_plan, epoch, &access, &mut credit)?),
            selection,
            read,
            epoch,
            protection,
            _credit: credit.split(std::mem::size_of::<PublicFingerprintOwner>())?,
        };
        let coordination = session
            .entry
            .recovery
            .observations
            .publish(registry.bind_public_fingerprint(owner))?;
        break (search_cleanup, coordination, access);
    };
    let waiter = Waiting::new(session, coordination, Some(epoch), epoch);
    let search_open = std::cell::Cell::new(false);
    let _withdrawal = SearchWithdrawal::new(session, &search_open);
    let mut access = Some(first_access);
    let result = (|| loop {
        waiter.check()?;
        let owned_access =
            access
                .take()
                .ok_or(Error::Rejected(crate::RejectionReason::ObjectReferences(
                    crate::ObjectReferencesRejection::PublicFingerprintPossessionAbsent,
                )))?;
        let slot = session
            .entry
            .recovery
            .observations
            .get(&waiter.coordination)?;
        let mut payload = slot.owner.lock().map_err(|_| Error::Poisoned)?;
        let owner = payload
            .as_mut()
            .ok_or(Error::Rejected(crate::RejectionReason::ObjectReferences(
                crate::ObjectReferencesRejection::PublicFingerprintOwnerAbsent,
            )))?
            .public_fingerprint_mut()?;
        search_open.set(owner.search_claimed());
        let advanced = owner.advance(session, &owned_access);
        search_open.set(owner.search_claimed() && owner.pending());
        advanced?;
        if owner.complete() {
            return payload
                .take()
                .expect("completed public fingerprint")
                .into_public_fingerprint()?
                .result(session, &owned_access);
        }
        let need =
            owner
                .need()?
                .ok_or(Error::Rejected(crate::RejectionReason::ObjectReferences(
                    crate::ObjectReferencesRejection::PublicFingerprintNeedAbsent,
                )))?;
        drop(payload);
        drop(slot);
        drop(owned_access);
        loop {
            let candidate = prepare(need, read, &policy, &waiter)?;
            let resumed = match session.try_operation_access_progress(false, progress) {
                Ok(access) => access,
                Err(Error::Busy(_)) => {
                    drop(candidate);
                    drop(session.access_progress(progress)?);
                    continue;
                }
                Err(error) => return Err(error),
            };
            waiter.check()?;
            let slot = session
                .entry
                .recovery
                .observations
                .get(&waiter.coordination)?;
            let mut payload = slot.owner.lock().map_err(|_| Error::Poisoned)?;
            payload
                .as_mut()
                .ok_or(Error::Rejected(crate::RejectionReason::ObjectReferences(
                    crate::ObjectReferencesRejection::PublicFingerprintOwnerAbsent,
                )))?
                .public_fingerprint_mut()?
                .attach(need, candidate)?;
            drop(payload);
            drop(slot);
            access = Some(resumed);
            break;
        }
    })();
    drop(access);
    let result = crate::managed::search::finish_failed_search(
        session,
        &waiter.coordination,
        &search_open,
        result,
        &mut search_cleanup,
        None,
        || session.try_advanced_access_progress(progress),
        |owner, access| {
            let owner = owner.public_fingerprint_mut()?;
            let cleanup = owner.finish_search(session, access);
            search_open.set(owner.search_claimed() && owner.pending());
            cleanup
        },
    );
    result
}
