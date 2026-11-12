// SPDX-License-Identifier: Apache-2.0
//! Empty candidates only; the resident discovery retains all observed data.
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
            .ok_or(Error::Rejected(crate::RejectionReason::ObjectSearch(
                crate::ObjectSearchRejection::ManagedDiscoveryStorageSize,
            )))?;
    loop {
        let mut credit = reserve(required, policy, waiter)?;
        let storage = ReadStorage::allocate(recipe)?;
        let actual = storage
            .allocated_bytes()?
            .checked_add(fixed)
            .ok_or(Error::Rejected(crate::RejectionReason::ObjectSearch(
                crate::ObjectSearchRejection::ManagedDiscoveryStorageSize,
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
    class: ManagedClass,
    admission: &crate::ObjectAdmission,
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
        Need::Required | Need::Properties => {
            let recipe = if matches!(need, Need::Required) {
                required_recipe(class, admission)
            } else {
                Recipe::Controls(admission)
            };
            let (storage, credit) = metadata(recipe, 0, session, policy, waiter)?;
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
                return Err(Error::Rejected(crate::RejectionReason::ObjectSearch(
                    crate::ObjectSearchRejection::ManagedDiscoveryFingerprintSelection,
                )));
            };
            fingerprint::prepare_candidate(need, read, waiter.budget(), policy, || waiter.check())
                .map(Candidate::Fingerprint)
        }
    }
}

/// Admission of an already selected handle. It carries no search evidence and
/// performs the same required class/type reads and caller-selected observations.
pub(crate) struct SelectedInitial(ReadStorage);
impl SelectedInitial {
    pub(crate) fn requested(
        class: ManagedClass,
        admission: &crate::ObjectAdmission,
    ) -> Result<usize> {
        ReadStorage::requested(required_recipe(class, admission))?
            .checked_add(std::mem::size_of::<DiscoveryOwner>())
            .ok_or(Error::Rejected(crate::RejectionReason::ObjectSearch(
                crate::ObjectSearchRejection::SelectedAdmissionStorageSize,
            )))
    }
    pub(crate) fn allocate(
        class: ManagedClass,
        admission: &crate::ObjectAdmission,
    ) -> Result<Self> {
        ReadStorage::allocate(required_recipe(class, admission)).map(Self)
    }
    pub(crate) fn allocated_bytes(&self) -> Result<usize> {
        self.0
            .allocated_bytes()?
            .checked_add(std::mem::size_of::<DiscoveryOwner>())
            .ok_or(Error::Rejected(crate::RejectionReason::ObjectSearch(
                crate::ObjectSearchRejection::SelectedAdmissionStorageSize,
            )))
    }
    pub(crate) fn bind(
        self,
        class: ManagedClass,
        handle: CK_OBJECT_HANDLE,
        admission: crate::ObjectAdmission,
        content: ContentObservation,
        content_stage: &'static str,
        permit: crate::registry::Reservation<crate::managed::NativeIdentity>,
        epoch: u64,
        protection: ObservationProtection,
        prepaid: &mut Credit,
    ) -> Result<DiscoveryOwner> {
        if matches!(class, ManagedClass::Other(_)) {
            return Err(Error::Rejected(crate::RejectionReason::ObjectSearch(
                crate::ObjectSearchRejection::ManagedClassUnsupported,
            )));
        }
        let read = self.0.bind_with_protection(
            prepaid,
            required_recipe(class, &admission),
            handle,
            Some(epoch),
            protection.duplicate()?,
        )?;
        Ok(DiscoveryOwner {
            native: None,
            phase: Phase::Required {
                selected: Selected {
                    handle,
                    report: None,
                },
                read,
            },
            class,
            admission,
            content,
            content_stage,
            permit: Some(permit),
            epoch,
            protection,
            _credit: prepaid.split(std::mem::size_of::<DiscoveryOwner>())?,
        })
    }
}
