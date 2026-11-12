// SPDX-License-Identifier: Apache-2.0
//! Exact Create/Copy templates with no prerequisite or post-creation attributes.
use super::{copy, DestinationRecipe, Reservation};
use crate::{
    attribute_values::InputTemplate,
    managed::SinglePublication,
    native::creation::ObjectCreation,
    session::{
        activity::AccessMode,
        observation_protection::{MutationProtection, ObservationProtection},
    },
    AttributeInput, AttributeTemplateLimits, Error, NativeObjectRef, Result, Session,
};

enum Call {
    Create(ObjectCreation),
    Copy(copy::CopyCall),
}

enum OperationDiagnostic {
    Create(crate::error::PreparedCompletion),
    Copy(copy::PreparedCopyDiagnostics),
}

// One public invocation retains its operation and cleanup credits while private
// dispatch/publication helpers return an error containing their prepared leaves.
type Diagnostics = Option<(OperationDiagnostic, crate::error::PreparedCleanupStorage)>;
// The creation ticket outlives registry publication even when creation provenance
// is no longer needed by a subsequently observed persistent object.
enum Completed {
    Create(crate::native::creation::CreatedObject),
    Copy(copy::CreatedCopy),
}
impl Completed {
    fn handle(&self) -> fe11_sys::CK_OBJECT_HANDLE {
        match self {
            Self::Create(value) => value.handle,
            Self::Copy(value) => value.handle,
        }
    }
}

fn execute<'a>(
    session: &Session,
    source: Option<&NativeObjectRef>,
    input: &'a [AttributeInput<'a>],
    limits: AttributeTemplateLimits,
    diagnostics: &mut Diagnostics,
) -> Result<NativeObjectRef> {
    let plan = InputTemplate::plan_scoped(input, limits, &session.inner)?;
    let epoch = session.snapshot.authentication_stamp();
    let admission = session.reference_admission_at_epoch(
        crate::session::ReferenceMode::Synchronous,
        epoch,
        |state| {
            if source.is_some() {
                state.native.table.C_CopyObject.ok_or(Error::Unsupported(
                    crate::UnsupportedReason::NativeFunction {
                        function: "C_CopyObject",
                    },
                ))?;
            } else {
                state.native.table.C_CreateObject.ok_or(Error::Unsupported(
                    crate::UnsupportedReason::NativeFunction {
                        function: "C_CreateObject",
                    },
                ))?;
            }
            Ok(())
        },
    )?;
    let progress = admission.progress();
    // Unknown attributes imply a token-wide local mutation exclusion. They are
    // never translated into fabricated CKA_CLASS/CKA_TOKEN template entries.
    let recipes = [DestinationRecipe::token_scope(session)];
    let frame = if source.is_some() {
        copy::CopyCall::typed_frame_bytes()
    } else {
        ObjectCreation::typed_frame_bytes()
    };
    let diagnostic_bytes = if source.is_some() {
        copy::PreparedCopyDiagnostics::allocation_bytes()
    } else {
        crate::error::PreparedCompletion::allocation_bytes()
    };
    let fixed = frame
        .checked_add(diagnostic_bytes)
        .ok_or(Error::Rejected(crate::RejectionReason::ObjectCreation(
            crate::ObjectCreationRejection::NativeCreationStorageAccounting,
        )))?
        .checked_add(crate::managed::NativeIdentity::allocation_bytes())
        .and_then(|value| value.checked_add(MutationProtection::allocation_bytes()))
        .ok_or(Error::Rejected(crate::RejectionReason::ObjectCreation(
            crate::ObjectCreationRejection::NativeCreationStorageAccounting,
        )))?;
    let cleanup_bytes = crate::error::CleanupStorage::requested(1)?;
    let mut required = fixed
        .checked_add(plan.prepared_allocation_bytes()?)
        .and_then(|bytes| bytes.checked_add(cleanup_bytes))
        .ok_or(Error::Rejected(crate::RejectionReason::ObjectCreation(
            crate::ObjectCreationRejection::NativeCreationStorageAccounting,
        )))?;
    let (((cleanup, prepared_diagnostic, call, mut permit, mut prepaid), reservation), access) =
        Reservation::prepare_mutation_prepaid(
            session,
            &recipes,
            1,
            None,
            [(source, AccessMode::Read)],
            false,
            epoch,
            progress,
            |overhead, current| loop {
                session.snapshot.check_authentication_unchanged(epoch)?;
                let admitted = required.checked_add(overhead).ok_or(Error::Rejected(
                    crate::RejectionReason::ObjectCreation(
                        crate::ObjectCreationRejection::NativeCreationAggregateAccounting,
                    ),
                ))?;
                let group = admission.managed_with_storage(1, admitted, || {
                    crate::session::recovery::observations::context(session, Some(epoch), epoch)?;
                    if !current()? {
                        return Err(Error::Busy(crate::BusyReason::ObjectCreation(
                            crate::ObjectCreationBusy::NativeObjectCreationPlanChanged,
                        )));
                    }
                    Ok(())
                });
                let (permit, mut prepaid) = match group {
                    Ok(group) => group,
                    Err(Error::Busy(crate::BusyReason::ObjectCreation(
                        crate::ObjectCreationBusy::NativeObjectCreationPlanChanged,
                    ))) => return Ok(None),
                    Err(error) => return Err(error),
                };
                let template = plan.allocate()?;
                let cleanup = crate::error::CleanupStorage::allocate(1)?;
                let cleanup_bytes = cleanup.allocated_bytes()?;
                let actual = fixed
                    .checked_add(template.allocated_bytes()?)
                    .and_then(|bytes| bytes.checked_add(cleanup_bytes))
                    .and_then(|bytes| bytes.checked_add(overhead))
                    .ok_or(Error::Rejected(crate::RejectionReason::ObjectCreation(
                        crate::ObjectCreationRejection::NativeCreationStorageAccounting,
                    )))?;
                if actual > admitted {
                    drop(cleanup);
                    drop(template);
                    drop((prepaid, permit));
                    required = actual.checked_sub(overhead).ok_or(Error::Rejected(
                        crate::RejectionReason::ObjectCreation(
                            crate::ObjectCreationRejection::NativeCreationAggregateAccounting,
                        ),
                    ))?;
                    continue;
                }
                prepaid.release(admitted - actual);
                let cleanup = crate::error::PreparedCleanupStorage::bind(cleanup, &mut prepaid)?;
                let diagnostic = if source.is_none() {
                    OperationDiagnostic::Create(crate::error::PreparedCompletion::prepare(
                        "C_CreateObject",
                        &mut prepaid,
                    )?)
                } else {
                    OperationDiagnostic::Copy(copy::PreparedCopyDiagnostics::prepare(&mut prepaid)?)
                };
                let template = template.bind(&mut prepaid)?;
                template.check_extensions(&session.inner)?;
                let call = if source.is_some() {
                    Call::Copy(copy::CopyCall::typed_prepaid(template, &mut prepaid)?)
                } else {
                    Call::Create(ObjectCreation::typed_prepaid(template, &mut prepaid)?)
                };
                let coordination = prepaid.split(overhead)?;
                return Ok(Some((
                    (cleanup, diagnostic, call, permit, prepaid),
                    coordination,
                )));
            },
            |access| admission.check(access),
        )?;
    let (operation, cleanup) = diagnostics.insert((prepared_diagnostic, cleanup));
    // On preparation or publication refusal, release possession before the
    // partially prepared identity, protection and creation ticket. Native call
    // storage keeps its existing dispatch/quarantine ownership below.
    let mut publication;
    let protection;
    let mut creation;
    let completed;
    let diagnostic;
    let access = access;
    admission.check(&access)?;
    publication = SinglePublication::prepare(session, epoch, &mut permit, &mut prepaid)?;
    protection = MutationProtection::take(session, &access, &mut prepaid)?;
    creation = reservation.prepare_creation_ticket(session)?;
    let copy_source = if matches!(&call, Call::Copy(_)) {
        Some(
            source.ok_or(Error::Rejected(crate::RejectionReason::ObjectCreation(
                crate::ObjectCreationRejection::CopySourceAbsent,
            )))?,
        )
    } else {
        None
    };
    (completed, diagnostic) = match call {
        Call::Create(call) => {
            let OperationDiagnostic::Create(create_diagnostic) = operation else {
                return Err(Error::Rejected(crate::RejectionReason::ObjectCreation(
                    crate::ObjectCreationRejection::CreationDiagnosticAbsent,
                )));
            };
            let (created, diagnostic) = call
                .with_protection(ObservationProtection::mutation(&protection))
                .execute_resident(
                    session,
                    &access,
                    &mut creation,
                    create_diagnostic.take()?,
                    || {},
                    cleanup.storage(),
                )?
                .into_parts();
            (Completed::Create(created), diagnostic)
        }
        Call::Copy(call) => {
            let OperationDiagnostic::Copy(copy_diagnostics) = operation else {
                return Err(Error::Rejected(crate::RejectionReason::ObjectCreation(
                    crate::ObjectCreationRejection::CopyDiagnosticsAbsent,
                )));
            };
            let (created, diagnostic) = copy::dispatch_resident(
                session,
                &access,
                copy_source.expect("validated copy source"),
                call.with_protection(ObservationProtection::mutation(&protection)),
                &mut creation,
                copy_diagnostics.take()?,
            )?
            .into_parts();
            (Completed::Copy(created), diagnostic)
        }
    };
    let handle = completed.handle();
    if let Err(error) = publication.publish(session, &access, handle, &mut permit) {
        // Only an intrinsic lifetime-registration failure enters cleanup. There
        // is no optional observation on this primitive route.
        return diagnostic.finish(Err(crate::managed::cleanup_prepared(
            session,
            &access,
            session.entry.handle,
            handle,
            error,
            cleanup.storage(),
        )));
    }
    diagnostic.finish(publication.reference(session))
}

impl Session {
    /// Submit the exact template to C_CreateObject and return its native owner.
    /// No class, key type, visibility or protection attribute is read or inferred.
    /// The module decides template completeness, duplicates and native policy.
    pub fn create_native_object<'a>(
        &self,
        input: &'a [AttributeInput<'a>],
        limits: AttributeTemplateLimits,
    ) -> Result<NativeObjectRef> {
        let mut diagnostics = None;
        execute(self, None, input, limits, &mut diagnostics)
    }
    /// Submit C_CopyObject with exact caller changes and native inheritance.
    /// No attribute read is required before or after the single copy call.
    pub fn copy_native_object<'a>(
        &self,
        source: &NativeObjectRef,
        input: &'a [AttributeInput<'a>],
        limits: AttributeTemplateLimits,
    ) -> Result<NativeObjectRef> {
        let mut diagnostics = None;
        execute(self, Some(source), input, limits, &mut diagnostics)
    }
}
impl crate::AdvancedSession {
    /// Synchronous native creation with no descriptive reads or native asynchronous mode dispatch.
    pub fn create_native_object<'a>(
        &self,
        input: &'a [AttributeInput<'a>],
        limits: AttributeTemplateLimits,
    ) -> Result<NativeObjectRef> {
        let mut diagnostics = None;
        execute(&self.session, None, input, limits, &mut diagnostics)
    }
    /// Synchronous native copy preserving the generic source lifetime.
    pub fn copy_native_object<'a>(
        &self,
        source: &NativeObjectRef,
        input: &'a [AttributeInput<'a>],
        limits: AttributeTemplateLimits,
    ) -> Result<NativeObjectRef> {
        let mut diagnostics = None;
        execute(&self.session, Some(source), input, limits, &mut diagnostics)
    }
}
