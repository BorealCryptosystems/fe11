// SPDX-License-Identifier: Apache-2.0
//! Private creation preparation ends before the caller erases transferred input.
use super::*;
use crate::{
    crypto::{
        integer_key::{PublicDer, PublicDerStorage},
        key_evidence,
    },
    transport::secret_template::NativeSecretStorage,
};

pub(super) mod observation;

pub(crate) struct PreparedPrivateCreation<'a> {
    // Field order also covers abandonment before finish consumes the candidate:
    // release possession before returning diagnostic credits and waking waiters.
    access: SessionAccess<'a>,
    waiter: Waiting<'a>,
    cleanup: crate::error::PreparedCleanupStorage,
    diagnostic: crate::error::PreparedCompletion,
    epoch: u64,
    class: ManagedClass,
    contextual: bool,
}
fn add(a: usize, b: usize) -> Result<usize> {
    a.checked_add(b)
        .ok_or(Error::Rejected(crate::RejectionReason::ObjectCreation(
            crate::ObjectCreationRejection::PrivateCreationObservationStorageSize,
        )))
}
pub(crate) fn prepare_private_creation<'a>(
    session: &'a Session,
    class: ManagedClass,
    id: &[u8],
    label: &[u8],
    admission: &crate::ObjectAdmission,
    evidence: key_evidence::Spec<'_>,
    public_plan: &crate::attributes::TemplateSize,
    components: &[(CK_ATTRIBUTE_TYPE, &[u8])],
    publication: &[u8],
    template: impl FnMut() -> Result<crate::attributes::Template>,
    references: &crate::session::ReferenceAdmission<'_>,
    epoch: u64,
    transferred: Option<&crate::crypto::private_material::PreparedPrivateInput>,
    check: impl Fn(&SessionAccess<'_>) -> Result<()>,
) -> Result<PreparedPrivateCreation<'a>> {
    prepare_creation(
        session,
        class,
        id,
        label,
        admission,
        observation::Plan::Key(evidence),
        false,
        public_plan,
        components,
        publication,
        template,
        references,
        epoch,
        transferred,
        check,
    )
}
pub(crate) fn prepare_signing_creation<'a>(
    session: &'a Session,
    class: ManagedClass,
    id: &[u8],
    label: &[u8],
    admission: &crate::ObjectAdmission,
    evidence: key_evidence::Spec<'_>,
    contextual: bool,
    public_plan: &crate::attributes::TemplateSize,
    components: &[(CK_ATTRIBUTE_TYPE, &[u8])],
    publication: &[u8],
    template: impl FnMut() -> Result<crate::attributes::Template>,
    references: &crate::session::ReferenceAdmission<'_>,
    epoch: u64,
    transferred: Option<&crate::crypto::private_material::PreparedPrivateInput>,
    check: impl Fn(&SessionAccess<'_>) -> Result<()>,
) -> Result<PreparedPrivateCreation<'a>> {
    prepare_creation(
        session,
        class,
        id,
        label,
        admission,
        observation::Plan::Signing { evidence },
        contextual,
        public_plan,
        components,
        publication,
        template,
        references,
        epoch,
        transferred,
        check,
    )
}
pub(crate) fn prepare_rsa_creation<'a>(
    session: &'a Session,
    class: ManagedClass,
    id: &[u8],
    label: &[u8],
    admission: &crate::ObjectAdmission,
    evidence: crate::crypto::rsa_evidence::Spec<'_>,
    public_plan: &crate::attributes::TemplateSize,
    components: &[(CK_ATTRIBUTE_TYPE, &[u8])],
    publication: &[u8],
    template: impl FnMut() -> Result<crate::attributes::Template>,
    references: &crate::session::ReferenceAdmission<'_>,
    epoch: u64,
    transferred: Option<&crate::crypto::private_material::PreparedPrivateInput>,
    check: impl Fn(&SessionAccess<'_>) -> Result<()>,
) -> Result<PreparedPrivateCreation<'a>> {
    prepare_creation(
        session,
        class,
        id,
        label,
        admission,
        observation::Plan::Rsa(evidence),
        false,
        public_plan,
        components,
        publication,
        template,
        references,
        epoch,
        transferred,
        check,
    )
}
fn prepare_creation<'a>(
    session: &'a Session,
    class: ManagedClass,
    id: &[u8],
    label: &[u8],
    admission: &crate::ObjectAdmission,
    evidence: observation::Plan<'_>,
    contextual: bool,
    public_plan: &crate::attributes::TemplateSize,
    components: &[(CK_ATTRIBUTE_TYPE, &[u8])],
    publication: &[u8],
    mut template: impl FnMut() -> Result<crate::attributes::Template>,
    references: &crate::session::ReferenceAdmission<'_>,
    epoch: u64,
    transferred: Option<&crate::crypto::private_material::PreparedPrivateInput>,
    check: impl Fn(&SessionAccess<'_>) -> Result<()>,
) -> Result<PreparedPrivateCreation<'a>> {
    let progress = references.progress();
    let identity = DestinationIdentity::KeyOrCertificate { class, id, label };
    let recipes = [DestinationRecipe::new(session, class, &[id])?];
    let input_bytes = transferred
        .map(|input| input.allocation_bytes())
        .transpose()?
        .unwrap_or(0);
    let fixed = add(
        add(
            Initial::fixed_bytes()?,
            ObjectCreation::private_frame_bytes(),
        )?,
        add(
            input_bytes,
            crate::error::PreparedCompletion::allocation_bytes(),
        )?,
    )?;
    let mut required = add(
        fixed,
        NativeSecretStorage::allocation_bytes(public_plan, components)?,
    )?;
    required = add(
        required,
        Initial::requested(class, admission, &admission.destination, &identity, false)?,
    )?;
    required = add(required, evidence.requested()?)?;
    required = add(required, publication.len())?;
    let (((diagnostic, call, observations, registry, permit, mut prepaid), reservation), access) =
        Reservation::prepare_mutation_prepaid(
            session,
            &recipes,
            1,
            None,
            [],
            contextual,
            epoch,
            progress,
            |overhead, current| loop {
                context(session, Some(epoch), epoch)?;
                let admitted = required.checked_add(overhead).ok_or(Error::Rejected(
                    crate::RejectionReason::ObjectReferences(
                        crate::ObjectReferencesRejection::DestinationAggregateAccounting,
                    ),
                ))?;
                let group = references.managed_with_observation_storage(1, admitted, || {
                    context(session, Some(epoch), epoch)?;
                    if !current()? {
                        return Err(Error::Busy(crate::BusyReason::ObjectCreation(
                            crate::ObjectCreationBusy::PrivateImportCreationPlanChanged,
                        )));
                    }
                    Ok(())
                });
                let (permit, mut prepaid) = match group {
                    Ok(group) => group,
                    Err(Error::Busy(crate::BusyReason::ObjectCreation(
                        crate::ObjectCreationBusy::PrivateImportCreationPlanChanged,
                    ))) => return Ok(None),
                    Err(error) => return Err(error),
                };
                let template = NativeSecretStorage::allocate(template()?, components)?;
                let mut observations =
                    Initial::allocate(class, admission, &admission.destination, &identity, false)?;
                let key = evidence.allocate()?;
                let public = PublicDerStorage::allocate(publication.len())?;
                let mut actual = add(fixed, template.allocated_bytes()?)?;
                actual = add(actual, observations.allocated_bytes()?)?;
                actual = add(actual, key.allocated_bytes()?)?;
                actual = add(actual, public.allocated())?;
                let actual = actual.checked_add(overhead).ok_or(Error::Rejected(
                    crate::RejectionReason::ObjectReferences(
                        crate::ObjectReferencesRejection::DestinationAggregateAccounting,
                    ),
                ))?;
                if actual > admitted {
                    drop((template, observations, key, public));
                    drop((prepaid, permit));
                    required = actual.checked_sub(overhead).ok_or(Error::Rejected(
                        crate::RejectionReason::ObjectReferences(
                            crate::ObjectReferencesRejection::DestinationAggregateAccounting,
                        ),
                    ))?;
                    continue;
                }
                prepaid.release(admitted - actual);
                prepaid.observation_budget()?;
                let diagnostic =
                    crate::error::PreparedCompletion::prepare("C_CreateObject", &mut prepaid)?;
                let call =
                    ObjectCreation::private_prepaid(template.bind(&mut prepaid)?, &mut prepaid)?;
                observations.post = PostCreation::Private {
                    read: key,
                    public: public.bind(publication, &mut prepaid)?,
                };
                let registry = Prepared::allocate(&session.inner.symmetric_budget, &mut prepaid)?;
                let coordination = prepaid.split(overhead)?;
                return Ok(Some((
                    (diagnostic, call, observations, registry, permit, prepaid),
                    coordination,
                )));
            },
            |access| check(access),
        )?;
    check(&access)?;
    if let Some(input) = transferred {
        input.charge_prepaid(&mut prepaid)?;
    }
    let (coordination, access, cleanup) = observations.publish(
        session,
        access,
        call,
        &reservation,
        class,
        admission.clone(),
        crate::ContentObservation::NotRequested,
        admission.destination.clone(),
        permit,
        epoch,
        registry,
        prepaid,
    )?;
    drop(reservation);
    Ok(PreparedPrivateCreation {
        cleanup,
        diagnostic,
        access,
        waiter: Waiting::new(session, coordination, Some(epoch), epoch),
        epoch,
        class,
        contextual,
    })
}
impl<'a> PreparedPrivateCreation<'a> {
    /// The root has now dropped its transferred private input. Resident copies
    /// remain with the one native call and are erased by their existing owners.
    pub(crate) fn finish<T>(
        self,
        session: &'a Session,
        admission: &crate::ObjectAdmission,
        progress: &crate::session::AdmissionProgress,
        invocation: &mut crate::error::ObjectCreationDiagnostics,
        finish: impl FnOnce(ManagedObjectRef, key_evidence::Evidence, PublicDer) -> Result<T>,
    ) -> Result<crate::CreatedObjects<T>> {
        let Self {
            cleanup,
            diagnostic,
            access,
            waiter,
            epoch,
            class,
            contextual,
        } = self;
        let (diagnostic, cleanup) = invocation.insert((diagnostic, cleanup));
        runner::run_with_effect(
            session,
            admission,
            class,
            None,
            progress,
            epoch,
            waiter.coordination.clone(),
            access,
            diagnostic,
            cleanup,
            contextual,
            |reference, evidence| {
                let Evidence::Private { key, public } = evidence else {
                    return Err(Error::Rejected(crate::RejectionReason::ObjectCreation(
                        crate::ObjectCreationRejection::PrivateImportEvidenceAbsent,
                    )));
                };
                let observation::Evidence::Key(key) = key else {
                    return Err(Error::Rejected(crate::RejectionReason::ObjectCreation(
                        crate::ObjectCreationRejection::UnexpectedSigningEvidence,
                    )));
                };
                finish(reference, key, public)
            },
        )
    }
    /// Publish the private signer and its completed native observations.
    pub(crate) fn finish_signing<T>(
        self,
        session: &'a Session,
        admission: &crate::ObjectAdmission,
        progress: &crate::session::AdmissionProgress,
        invocation: &mut crate::error::ObjectCreationDiagnostics,

        finish: impl FnOnce(
            ManagedObjectRef,
            crate::crypto::key_evidence::Evidence,
            PublicDer,
        ) -> Result<T>,
    ) -> Result<crate::CreatedObjects<T>> {
        let Self {
            cleanup,
            diagnostic,
            access,
            waiter,
            epoch,
            class,
            contextual,
        } = self;
        let (diagnostic, cleanup) = invocation.insert((diagnostic, cleanup));
        runner::run_with_effect(
            session,
            admission,
            class,
            None,
            progress,
            epoch,
            waiter.coordination.clone(),
            access,
            diagnostic,
            cleanup,
            contextual,
            |reference, evidence| {
                let Evidence::Private {
                    key: observation::Evidence::Signing(key),
                    public,
                } = evidence
                else {
                    return Err(Error::Rejected(crate::RejectionReason::ObjectCreation(
                        crate::ObjectCreationRejection::SigningImportEvidenceAbsent,
                    )));
                };
                finish(reference, key, public)
            },
        )
    }
}
