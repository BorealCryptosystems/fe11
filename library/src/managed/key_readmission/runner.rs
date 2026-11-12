// SPDX-License-Identifier: Apache-2.0
//! Only scalar resource needs leave the resident key readmission.
use super::*;
use crate::{
    attributes::{Template, TemplateSink, TemplateSize},
    crypto::integer_key::PublicDerStorage,
    session::{
        recovery::observations::{context, Prepared, Waiting},
        AdmissionProgress,
    },
};
fn add(a: usize, b: usize) -> Result<usize> {
    a.checked_add(b)
        .ok_or(Error::Rejected(crate::RejectionReason::ObjectReferences(
            crate::ObjectReferencesRejection::KeyReadmissionStorageSize,
        )))
}
fn selector<T: TemplateSink>(class: ManagedClass, id: &[u8]) -> T {
    let mut value = T::empty();
    value.integer(CKA_CLASS, class.raw());
    value.bytes(CKA_ID, id);
    value
}
pub(crate) fn observe<T>(
    session: &Session,
    id: &[u8],
    admission: &ObjectAdmission,
    evidence: key_evidence::Spec<'_>,
    publication: &[u8],
    contextual: bool,
    references: &crate::session::ReferenceAdmission<'_>,
    progress: &AdmissionProgress,
    check: impl Fn(&SessionAccess<'_>) -> Result<()>,

    finish: impl FnOnce(ManagedObjectRef, key_evidence::Evidence, PublicDer) -> Result<T>,
) -> Result<T> {
    run(
        session,
        id,
        admission,
        preparation::Plan::Signing { evidence },
        publication,
        contextual,
        references,
        progress,
        check,
        |key, evidence, public| {
            let Evidence::Signing(evidence) = evidence else {
                return Err(Error::Rejected(crate::RejectionReason::ObjectReferences(
                    crate::ObjectReferencesRejection::SigningEvidenceAbsent,
                )));
            };
            finish(key, evidence, public)
        },
    )
}

pub(crate) fn observe_public<T>(
    session: &Session,
    id: &[u8],
    admission: &ObjectAdmission,
    evidence: crate::crypto::public_import::observation::Spec<'_>,
    publication: &[u8],
    references: &crate::session::ReferenceAdmission<'_>,
    progress: &AdmissionProgress,
    check: impl Fn(&SessionAccess<'_>) -> Result<()>,
    finish: impl FnOnce(ManagedObjectRef, crate::MechanismObservationReport, PublicDer) -> Result<T>,
) -> Result<T> {
    run(
        session,
        id,
        admission,
        preparation::Plan::Public(evidence),
        publication,
        false,
        references,
        progress,
        check,
        |key, evidence, public| {
            let Evidence::Public(mechanisms) = evidence else {
                return Err(Error::Rejected(crate::RejectionReason::ObjectReferences(
                    crate::ObjectReferencesRejection::PublicKeyEvidenceAbsent,
                )));
            };
            finish(key, mechanisms, public)
        },
    )
}

pub(crate) fn observe_private_rsa<T>(
    session: &Session,
    id: &[u8],
    admission: &ObjectAdmission,
    evidence: crate::crypto::rsa_evidence::Spec<'_>,
    references: &crate::session::ReferenceAdmission<'_>,
    progress: &AdmissionProgress,
    check: impl Fn(&SessionAccess<'_>) -> Result<()>,
    finish: impl FnOnce(ManagedObjectRef, key_evidence::Evidence, PublicDer) -> Result<T>,
) -> Result<T> {
    run(
        session,
        id,
        admission,
        preparation::Plan::PrivateRsa(evidence),
        &[],
        false,
        references,
        progress,
        check,
        |key, evidence, public| {
            let Evidence::PrivateRsa(evidence) = evidence else {
                return Err(Error::Rejected(crate::RejectionReason::ObjectReferences(
                    crate::ObjectReferencesRejection::RsaPrivateEvidenceAbsent,
                )));
            };
            finish(key, evidence, public)
        },
    )
}

fn run<T>(
    session: &Session,
    id: &[u8],
    admission: &ObjectAdmission,
    plan: preparation::Plan<'_>,
    publication: &[u8],
    contextual: bool,
    references: &crate::session::ReferenceAdmission<'_>,
    progress: &AdmissionProgress,
    check: impl Fn(&SessionAccess<'_>) -> Result<()>,

    finish: impl FnOnce(ManagedObjectRef, Evidence, PublicDer) -> Result<T>,
) -> Result<T> {
    let class = plan.class();
    let epoch = session.snapshot.authentication_stamp();
    let policy = crate::admission_wait::current();
    let fixed = add(
        add(Prepared::allocation_bytes(), std::mem::size_of::<Owner>())?,
        ObservationProtection::selection_bytes(),
    )?;
    let fixed = add(
        fixed,
        crate::error::PreparedCleanupDiagnostic::allocation_bytes(),
    )?;
    let search_bytes = search::SearchStorage::requested_bytes(
        selector::<TemplateSize>(class, id).owned_bytes()?,
        admission.search,
    )?;
    let selection_bytes = crate::managed::ManagedSelectionStorage::requested_key_bytes(id)?;
    let mut required = add(
        add(
            add(
                add(add(fixed, selection_bytes)?, search_bytes)?,
                plan.requested()?,
            )?,
            discovery::preparation::SelectedInitial::requested(class, admission)?,
        )?,
        publication.len(),
    )?;
    if plan.two_searches() {
        required = add(
            required,
            add(
                add(search_bytes, selection_bytes)?,
                ObservationProtection::selection_bytes(),
            )?,
        )?;
    }
    let acquire = || {
        if contextual {
            session.context_operation_access_progress(progress)
        } else {
            session.access_progress(progress)
        }
    };
    let (mut search_cleanup, coordination, first_access) = loop {
        context(session, Some(epoch), epoch)?;
        let (permit, mut credit) =
            references.managed_with_observation_storage(1, required, || {
                context(session, Some(epoch), epoch)
            })?;
        let search = search::SearchStorage::allocate_owned(
            selector::<Template>(class, id),
            admission.search,
        )?;
        let second_search = if plan.two_searches() {
            Some(search::SearchStorage::allocate_owned(
                selector::<Template>(class, id),
                admission.search,
            )?)
        } else {
            None
        };
        let selection = crate::managed::ManagedSelectionStorage::allocate_key(class, id)?;
        let second_selection = if plan.two_searches() {
            Some(crate::managed::ManagedSelectionStorage::allocate_key(
                class, id,
            )?)
        } else {
            None
        };
        let evidence = plan.allocate()?;
        let reference = discovery::preparation::SelectedInitial::allocate(class, admission)?;
        let public = if plan.two_searches() {
            None
        } else {
            Some(PublicDerStorage::allocate(publication.len())?)
        };
        let mut actual = add(
            add(
                add(
                    add(
                        add(fixed, selection.allocated_bytes())?,
                        search.allocated_bytes()?,
                    )?,
                    evidence.allocated_bytes()?,
                )?,
                reference.allocated_bytes()?,
            )?,
            public.as_ref().map_or(0, |value| value.allocated()),
        )?;
        if let Some(second) = &second_search {
            actual = add(
                actual,
                add(
                    second.allocated_bytes()?,
                    ObservationProtection::selection_bytes(),
                )?,
            )?;
        }
        if let Some(second) = &second_selection {
            actual = add(actual, second.allocated_bytes())?;
        }
        if actual > required {
            drop((selection, second_selection));
            drop((search, second_search, evidence, reference, public));
            drop(credit);
            drop(permit);
            required = actual;
            continue;
        }
        credit.release(required - actual);
        credit.observation_budget()?;
        let search_cleanup = crate::error::PreparedCleanupDiagnostic::prepare(&mut credit)?;
        let registry = Prepared::allocate(&session.inner.symmetric_budget, &mut credit)?;
        let selection = selection.bind(session, &mut credit)?;
        let second_selection = second_selection
            .map(|selection| selection.bind(session, &mut credit))
            .transpose()?;
        let access = match session.try_operation_access_progress(contextual, progress) {
            Ok(access) => access,
            Err(Error::Busy(_)) => {
                drop(search_cleanup);
                drop((selection, second_selection));
                drop((search, second_search, evidence, reference, public, registry));
                drop(credit);
                drop(permit);
                drop(acquire()?);
                continue;
            }
            Err(error) => return Err(error),
        };
        context(session, Some(epoch), epoch)?;
        check(&access)?;
        search::SearchOwner::check_functions(&access)?;
        session
            .entry
            .recovery
            .observations
            .check_search_available()?;
        let selection = selection
            .select(session)?
            .into_owned(&session.inner, &session.entry)?;
        let protection = ObservationProtection::selection(session, selection, &mut credit)?;
        let search = search.bind(admission.search, epoch, &access, &mut credit)?;
        let public = public
            .map(|value| value.bind(publication, &mut credit))
            .transpose()?;
        let owner_credit = credit.split(std::mem::size_of::<Owner>())?;
        let owner = Owner {
            phase: Phase::Search(search),
            prepared_evidence: Some(evidence),
            class,
            prepared_reference: Some(reference),
            permit: Some(permit),
            publication: public,
            second_search,
            second_selection,
            admission: admission.clone(),
            protection: Some(protection),
            epoch,
            prepaid: credit,
            _credit: owner_credit,
        };
        let coordination = session
            .entry
            .recovery
            .observations
            .publish(registry.bind_key_readmission(owner))?;
        break (search_cleanup, coordination, access);
    };
    let waiter = Waiting::new(session, coordination, Some(epoch), epoch);
    let search_open = std::cell::Cell::new(false);
    let _withdrawal = search::SearchWithdrawal::new(session, &search_open);
    let mut access = Some(first_access);
    let mut finish = Some(finish);
    let result = (|| loop {
        waiter.check()?;
        let held =
            access
                .as_ref()
                .ok_or(Error::Rejected(crate::RejectionReason::ObjectReferences(
                    crate::ObjectReferencesRejection::KeyReadmissionPossessionAbsent,
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
                crate::ObjectReferencesRejection::KeyReadmissionOwnerAbsent,
            )))?
            .key_readmission_mut()?;
        search_open.set(owner.search_claimed());
        let advanced = owner.advance(session, held);
        search_open.set(owner.search_claimed() && owner.pending());
        advanced?;
        if owner.complete() {
            // Preserve original selection through all local final reactions.
            let _protection = owner.protection()?;
            let owner = payload
                .take()
                .expect("completed key readmission")
                .into_key_readmission()?;
            let (key, evidence, public) = owner.result(session, held)?;
            drop(payload);
            drop(slot);
            return finish.take().expect("single key readmission result")(key, evidence, public);
        }
        let need =
            owner
                .need()?
                .ok_or(Error::Rejected(crate::RejectionReason::ObjectReferences(
                    crate::ObjectReferencesRejection::KeyReadmissionNeedAbsent,
                )))?;
        if need == Need::SecondSelection {
            // The original two-stage contract releases its first selection
            // and possession before selecting again. Only observed DER and
            // already prepared next-stage storage remain resident.
            drop(payload);
            drop(slot);
            drop(access.take());
            let resumed = acquire()?;
            waiter.check()?;
            check(&resumed)?;
            session
                .entry
                .recovery
                .observations
                .check_search_available_except(Some(&waiter.coordination))?;
            let slot = session
                .entry
                .recovery
                .observations
                .get(&waiter.coordination)?;
            let mut payload = slot.owner.lock().map_err(|_| Error::Poisoned)?;
            let owner = payload
                .as_mut()
                .ok_or(Error::Rejected(crate::RejectionReason::ObjectReferences(
                    crate::ObjectReferencesRejection::KeyReadmissionOwnerAbsent,
                )))?
                .key_readmission_mut()?;
            let selection = owner
                .second_selection
                .take()
                .ok_or(Error::Rejected(crate::RejectionReason::ObjectReferences(
                    crate::ObjectReferencesRejection::SecondSelectionPreparationAbsent,
                )))?
                .select(session)?
                .into_owned(&session.inner, &session.entry)?;
            owner.select_again(session, &resumed, selection)?;
            access = Some(resumed);
            continue;
        }

        drop(payload);
        drop(slot);
        drop(access.take());
        loop {
            let candidate = prepare(need, class, admission, session, &policy, &waiter)?;
            let resumed = match session.try_operation_access_progress(contextual, progress) {
                Ok(access) => access,
                Err(Error::Busy(_)) => {
                    drop(candidate);
                    drop(acquire()?);
                    continue;
                }
                Err(error) => return Err(error),
            };
            waiter.check()?;
            check(&resumed)?;
            let slot = session
                .entry
                .recovery
                .observations
                .get(&waiter.coordination)?;
            let mut payload = slot.owner.lock().map_err(|_| Error::Poisoned)?;
            let owner = payload
                .as_mut()
                .ok_or(Error::Rejected(crate::RejectionReason::ObjectReferences(
                    crate::ObjectReferencesRejection::KeyReadmissionOwnerAbsent,
                )))?
                .key_readmission_mut()?;
            attach(owner, need, candidate)?;
            access = Some(resumed);
            break;
        }
    })();
    // A started search must be finalized, or remain resident for proven close.
    // Cleanup never waits for a new possession and never retries the search.
    let result = crate::managed::search::finish_failed_search(
        session,
        &waiter.coordination,
        &search_open,
        result,
        &mut search_cleanup,
        access.take(),
        || session.try_advanced_access_progress(progress),
        |owner, access| {
            let owner = owner.key_readmission_mut()?;
            let cleanup = owner.finish_search(session, access);
            search_open.set(owner.search_claimed() && owner.pending());
            cleanup
        },
    );
    drop(access);
    result
}
enum Candidate {
    RsaDiscovery(crate::crypto::rsa_observation::Candidate),
    Search(search::SearchCandidate),
    Metadata(crate::attributes::owned::resident::ValueCandidate),
    Admission(discovery::preparation::Candidate),
}
fn prepare(
    need: Need,
    class: ManagedClass,
    admission: &ObjectAdmission,
    session: &Session,
    policy: &crate::ResourceAdmission,
    waiter: &Waiting<'_>,
) -> Result<Candidate> {
    match need {
        Need::SecondSelection => Err(Error::Rejected(crate::RejectionReason::ObjectReferences(
            crate::ObjectReferencesRejection::SelectionIsNotAStorageRequest,
        ))),
        Need::RsaDiscovery(need) => {
            use crate::crypto::{
                integer_key::{PublicDerCandidate, PublicDerPreparation},
                rsa_observation as rsa,
            };
            let candidate = match need {
                rsa::Need::Metadata(need) => rsa::Candidate::Metadata(
                    need,
                    crate::attributes::owned::resident::prepare_value(
                        need,
                        waiter.budget(),
                        policy,
                        || waiter.check(),
                    )?,
                ),
                rsa::Need::Encoding(need) => {
                    match PublicDerCandidate::prepare(need, waiter.budget(), policy, || {
                        waiter.check()?;
                        Ok(None::<()>)
                    })? {
                        PublicDerPreparation::Ready(candidate) => {
                            rsa::Candidate::Encoding(candidate)
                        }
                        PublicDerPreparation::Redirect(()) => unreachable!("no redirect requested"),
                    }
                }
            };
            Ok(Candidate::RsaDiscovery(candidate))
        }
        Need::Search(need) => {
            match search::SearchCandidate::prepare(need, waiter.budget(), policy, || {
                waiter.check()?;
                Ok(None::<()>)
            })? {
                search::SearchPreparation::Ready(candidate) => Ok(Candidate::Search(candidate)),
                search::SearchPreparation::Redirect(()) => unreachable!("no redirect requested"),
            }
        }
        Need::Metadata(need) => {
            crate::attributes::owned::resident::prepare_value(need, waiter.budget(), policy, || {
                waiter.check()
            })
            .map(Candidate::Metadata)
        }
        Need::Admission(need) => {
            discovery::preparation::prepare(need, class, admission, None, session, policy, waiter)
                .map(Candidate::Admission)
        }
    }
}
fn attach(owner: &mut Owner, need: Need, candidate: Candidate) -> Result<()> {
    if owner.need()? != Some(need) {
        return Err(Error::Rejected(crate::RejectionReason::ObjectReferences(
            crate::ObjectReferencesRejection::KeyReadmissionContinuationChanged,
        )));
    }
    match (&mut owner.phase, need, candidate) {
        (
            Phase::RsaDiscovery { read, .. },
            Need::RsaDiscovery(_),
            Candidate::RsaDiscovery(candidate),
        ) => read.attach(candidate),
        (Phase::SecondSearch { read, .. }, Need::Search(_), Candidate::Search(candidate)) => {
            read.attach(candidate)
        }
        (Phase::RsaEvidence { read, .. }, Need::Metadata(need), Candidate::Metadata(value)) => {
            read.attach(need, value)
        }
        (
            Phase::RsaAdmission { read, .. },
            Need::Admission(need),
            Candidate::Admission(candidate),
        ) => read.attach(need, candidate),
        (Phase::PublicEvidence { read, .. }, Need::Metadata(need), Candidate::Metadata(value)) => {
            read.attach(need, value)
        }
        (
            Phase::PublicAdmission { read, .. },
            Need::Admission(need),
            Candidate::Admission(candidate),
        ) => read.attach(need, candidate),
        (Phase::Search(read), Need::Search(_), Candidate::Search(candidate)) => {
            read.attach(candidate)
        }
        (Phase::Evidence { read, .. }, Need::Metadata(need), Candidate::Metadata(value)) => {
            read.attach(need, value)
        }
        (Phase::Admission { read, .. }, Need::Admission(need), Candidate::Admission(candidate)) => {
            read.attach(need, candidate)
        }
        _ => Err(Error::Rejected(crate::RejectionReason::ObjectReferences(
            crate::ObjectReferencesRejection::KeyReadmissionCandidateKind,
        ))),
    }
}
