// SPDX-License-Identifier: Apache-2.0
//! Generic SetAttributeValue, sharing native ownership with specialized setters.
use super::{identity_recipe, Destination, DestinationRecipe, Reservation};
use crate::attribute_values::InputTemplate;
use crate::native::frame::{NativeFrame, SessionFrame};
use crate::native_return::MutationCall;
use crate::session::SessionAccess;
use crate::{Error, ManagedClass, ManagedObjectRef, Result, Session};
use fe11_sys::{CK_OBJECT_HANDLE, CK_RV};
use std::sync::Arc;
mod preparation;
mod resident;
pub(crate) use resident::SetAttributesOwner;

/// One-use mutation input: the template and its passive alias snapshot are
/// prepared together and stay owned across every preceding observation.
pub(super) struct PreparedSetInput {
    pub(super) template: InputTemplate,
    pub(super) targets: crate::managed::RevocationTargets,
}

/// Requested observations following a completed native attribute mutation.
/// A returned report does not refresh or reactivate any old object reference.
pub struct AttributeMutationReport {
    mutation: crate::ObjectMutationReport,
    content: crate::ContentReport,
    destination: crate::DestinationReport,
}
impl AttributeMutationReport {
    /// Before/after observations and the caller-selected stability controls.
    pub fn mutation(&self) -> &crate::ObjectMutationReport {
        &self.mutation
    }
    /// The explicitly selected post-mutation content observation or comparison.
    pub fn content(&self) -> &crate::ContentReport {
        &self.content
    }
    /// Caller-selected destination observations made before the mutation.
    /// Requested values describe a target, not an observed native result.
    pub fn destination(&self) -> &crate::DestinationReport {
        &self.destination
    }
}

enum InputIntegrity {
    Unchanged,
    Changed,
    CompletionUnknown,
}
pub(super) struct SetReturn {
    pub(super) code: CK_RV,
    integrity: InputIntegrity,
}
impl SetReturn {
    pub(super) fn storage_returned(&self) -> bool {
        matches!(self.integrity, InputIntegrity::Unchanged)
    }

    pub(super) fn inputs_changed(&self) -> bool {
        matches!(self.integrity, InputIntegrity::Changed)
    }
}

// Errors here precede native dispatch. Every actual return carries its code;
// the caller applies mutation failure scope before publishing a diagnostic.
pub(super) fn call_set(
    frame: &mut NativeFrame<SessionFrame<'_, InputTemplate>>,
    session: &Session,
    object: CK_OBJECT_HANDLE,
    targets: crate::managed::RevocationTargets,
) -> Result<SetReturn> {
    let (returned, body) = frame.session_parts();
    let access = &body.access;
    session.entry(access)?;
    let call = access
        .native
        .table
        .C_SetAttributeValue
        .ok_or(Error::Rejected(crate::RejectionReason::ObjectMutation(
            crate::ObjectMutationRejection::CSetAttributeValueUnavailable,
        )))?;
    body.data.check_extensions(&session.inner)?;
    let data = &mut *body.data;
    let count = data.count();

    access.native.record("C_SetAttributeValue")?;
    let pending = targets.arm();
    returned.arm();
    // SAFETY: session possession serializes dispatch. The frame or its
    // enclosing resident owner retains reservation and exclusive object activity. Every descriptor and nested referent belongs to InputTemplate.
    let code = returned.observe(
        unsafe { call(session.entry.handle, object, data.as_mut_ptr(), count) },
        &access.native,
    );
    let integrity = if MutationCall::Set.template_completion_known(code) {
        if data.unchanged() {
            returned.terminated();
            InputIntegrity::Unchanged
        } else {
            returned.quarantine(&access.native);
            InputIntegrity::Changed
        }
    } else {
        returned.recoverable();
        session.poison(access);
        InputIntegrity::CompletionUnknown
    };
    if matches!(integrity, InputIntegrity::Changed) {
        drop(pending);
    } else if count == 0 && matches!(integrity, InputIntegrity::Unchanged) {
        pending.preserve_unmodified();
    } else {
        pending.finish(MutationCall::Set, code);
    }
    Ok(SetReturn { code, integrity })
}

fn changes_identity(class: ManagedClass, input: &[crate::AttributeInput<'_>]) -> bool {
    use crate::StandardAttribute as Attribute;
    input.iter().any(|value| {
        value.attribute == Attribute::CLASS
            || if class == ManagedClass::Data {
                [
                    Attribute::APPLICATION,
                    Attribute::OBJECT_ID,
                    Attribute::LABEL,
                ]
                .iter()
                .any(|attribute| value.attribute == *attribute)
            } else {
                value.attribute == Attribute::ID
            }
    })
}

impl Session {
    /// Set a typed template, including nested standard attributes, exactly once.
    /// The provider determines which attributes may change. No application key
    /// profile or policy is imposed beyond the controls explicitly supplied here.
    ///
    /// A nonempty success revokes existing aliases; it returns observations, not a renewed
    /// reference. Use find_managed explicitly to obtain a new reference. Native
    /// partial or uncertain failures also revoke aliases. ACTION_PROHIBITED,
    /// SESSION_READ_ONLY and TOKEN_WRITE_PROTECTED preserve them only when input
    /// integrity is intact; native context loss is handled independently.
    /// A completed empty template preserves aliases when input integrity is intact.
    ///
    /// A post-success observation/control failure is OperationCompleted, with
    /// C_SetAttributeValue as its function. Do not retry it: the mutation already
    /// returned CKR_OK. A native error never implies an atomic rollback. No read
    /// or comparison omitted by the caller is silently added to this report.
    /// Destination queries use the admitted, immutable object class and requested
    /// identity bytes, retaining previously observed bytes for omitted fields.
    /// Duplicate operands are unavailable to the query; they are still sent to
    /// the provider. Destination observations do not establish final attributes.
    pub fn set_attributes<'a>(
        &self,
        object: &ManagedObjectRef,
        input: &'a [crate::AttributeInput<'a>],
        limits: crate::AttributeTemplateLimits,
        mutation: crate::ObjectMutationPlan,
        content: crate::ContentMutationPlan,
    ) -> Result<AttributeMutationReport> {
        let template_plan = InputTemplate::plan_scoped(input, limits, &self.inner)?;
        if resident::required(object, input, &mutation, &content)? {
            return resident::set(self, object, input, template_plan, mutation, content);
        }
        let authentication = self.snapshot.authentication_stamp();
        let identity_changes = changes_identity(object.identity.class, input);
        let visibility_changes = input
            .iter()
            .any(|value| value.attribute == crate::StandardAttribute::PRIVATE);
        let destination = if identity_changes {
            DestinationRecipe::class_scope(self, object.identity.class)?
        } else {
            identity_recipe(self, &object.identity)?
        };
        let admission_progress = crate::session::AdmissionProgress::default();
        let (mut completion_owner, mut failures, template, reservation, state, targets) =
            preparation::prepare(
                self,
                &[destination],
                object,
                &template_plan,
                &admission_progress,
                authentication,
            )?;
        let destination = reservation.destination(&destination)?;

        let handle = self.managed_handle(&state, object)?;
        if state.native.table.C_SetAttributeValue.is_none() {
            return Err(Error::Rejected(crate::RejectionReason::ObjectMutation(
                crate::ObjectMutationRejection::CSetAttributeValueUnavailable,
            )));
        }
        let destination_report =
            self.local_attribute_destination(&state, object, input, mutation.destination.clone())?;
        let reference = crate::ObjectReferenceReport::observe_local(
            mutation.source.clone(),
            &state,
            self,
            object,
            content.before,
        )?;
        let before =
            crate::ObjectMutationReport::prepare(mutation, reference, &state, self, handle)?;
        let metadata = reservation.prepare_attribute_mutation(
            self,
            &object.identity,
            identity_changes.then_some(&destination),
            visibility_changes,
        )?;
        let completion = completion_owner.take()?;
        let mut frame = NativeFrame::session(state.clone(), template)?;
        destination_report.check_context(self)?;
        let returned = call_set(&mut frame, self, handle, targets)?;
        let bookkeeping = if !returned.inputs_changed()
            && MutationCall::Set.definite_object_refusal(returned.code)
        {
            Ok(())
        } else {
            metadata.finish()
        };
        if bookkeeping.is_err() {
            // A failed registry invariant is structural, unlike an unavailable
            // optional observation. Its native outcome still remains visible.
            self.poison(&state);
        }
        let native_result = self.mutation_result(&state, MutationCall::Set, returned.code);
        if let Err(cause) = bookkeeping {
            return if returned.inputs_changed() {
                Err(completion.boundary_failure(
                    returned.code,
                    failures.finish(
                        Error::Rejected(crate::RejectionReason::ObjectMutation(
                            crate::ObjectMutationRejection::AttributeMutationInputChanged,
                        )),
                        cause,
                    ),
                ))
            } else {
                completion.finish_native(returned.code, Err(cause))
            };
        }
        if returned.inputs_changed() {
            return Err(completion.boundary_failure(
                returned.code,
                Error::Rejected(crate::RejectionReason::ObjectMutation(
                    crate::ObjectMutationRejection::AttributeMutationInputChanged,
                )),
            ));
        }
        native_result?;
        drop(frame);
        completion.finish(self.finish_attribute_observations(
            &state,
            handle,
            authentication,
            before,
            content.after,
            destination_report,
        ))
    }

    fn local_attribute_destination(
        &self,
        state: &SessionAccess<'_>,
        object: &ManagedObjectRef,
        input: &[crate::AttributeInput<'_>],
        plan: crate::DestinationPlan,
    ) -> Result<crate::DestinationReport> {
        super::input_identity::InputIdentity::new(
            object.identity.class,
            input,
            Some(&object.identity),
        )
        .observe_local(plan, state, self)
    }

    fn finish_attribute_observations(
        &self,
        state: &SessionAccess<'_>,
        object: CK_OBJECT_HANDLE,
        authentication: u64,
        before: crate::ObjectMutationReport,
        content: crate::ContentObservation,
        destination: crate::DestinationReport,
    ) -> Result<AttributeMutationReport> {
        self.entry(state)?;
        let mutation = before.finish(state, self, object)?;
        let content = content.observe_local()?;
        destination.check_context(self)?;
        // The requested template may change visibility. Bind reports to the
        // retained authentication epoch without imposing any USER login.
        self.metadata_result(
            state,
            Some(authentication),
            Ok(AttributeMutationReport {
                mutation,
                content,
                destination,
            }),
        )
    }
}
impl crate::AdvancedSession {
    /// Synchronous metadata mutation with the same contract as Session.
    /// This operation does not use cooperative pacing or PKCS#11 native asynchronous mode.
    pub fn set_attributes<'a>(
        &self,
        object: &ManagedObjectRef,
        input: &'a [crate::AttributeInput<'a>],
        limits: crate::AttributeTemplateLimits,
        mutation: crate::ObjectMutationPlan,
        content: crate::ContentMutationPlan,
    ) -> Result<AttributeMutationReport> {
        self.session
            .set_attributes(object, input, limits, mutation, content)
    }
}

impl Session {
    /// Pass the exact template to C_SetAttributeValue without attribute reads.
    /// The module determines mutability and returns its native refusal unchanged.
    /// A nonempty successful or possibly partial mutation invalidates old views;
    /// an empty completed template preserves them. No automatic retry occurs.
    pub fn set_native_attributes<'a>(
        &self,
        object: &crate::NativeObjectRef,
        input: &'a [crate::AttributeInput<'a>],
        limits: crate::AttributeTemplateLimits,
    ) -> Result<()> {
        let plan = InputTemplate::plan_scoped(input, limits, &self.inner)?;
        let authentication = self.snapshot.authentication_stamp();
        let recipe = DestinationRecipe::token_scope(self);
        let progress = crate::session::AdmissionProgress::default();
        let (mut completion_owner, mut failures, template, reservation, state, targets) =
            preparation::prepare(self, &[recipe], object, &plan, &progress, authentication)?;
        let destination = reservation.destination(&recipe)?;
        let handle = self.native_object_handle(&state, object)?;
        state
            .native
            .table
            .C_SetAttributeValue
            .ok_or(Error::Unsupported(
                crate::UnsupportedReason::NativeFunction {
                    function: "C_SetAttributeValue",
                },
            ))?;
        // Without a descriptive class, conservatively invalidate identity and
        // visibility knowledge after any nonempty possibly effective template.
        // This affects local aliases; no attributes are injected into the call.
        let metadata = reservation.prepare_attribute_mutation(
            self,
            &object.identity,
            (!input.is_empty()).then_some(&destination),
            !input.is_empty(),
        )?;
        let completion = completion_owner.take()?;
        let mut frame = NativeFrame::session(state.clone(), template)?;
        let returned = call_set(&mut frame, self, handle, targets)?;
        let bookkeeping = if !returned.inputs_changed()
            && MutationCall::Set.definite_object_refusal(returned.code)
        {
            Ok(())
        } else {
            metadata.finish()
        };
        if bookkeeping.is_err() {
            self.poison(&state);
        }
        let native = self.mutation_result(&state, MutationCall::Set, returned.code);
        if let Err(cause) = bookkeeping {
            return if returned.inputs_changed() {
                Err(completion.boundary_failure(
                    returned.code,
                    failures.finish(
                        Error::Rejected(crate::RejectionReason::ObjectMutation(
                            crate::ObjectMutationRejection::AttributeMutationInputChanged,
                        )),
                        cause,
                    ),
                ))
            } else {
                completion.finish_native(returned.code, Err(cause))
            };
        }
        if returned.inputs_changed() {
            return Err(completion.boundary_failure(
                returned.code,
                Error::Rejected(crate::RejectionReason::ObjectMutation(
                    crate::ObjectMutationRejection::AttributeMutationInputChanged,
                )),
            ));
        }
        native
    }
}
impl crate::AdvancedSession {
    /// Synchronous exact attribute mutation, with no implicit observations.
    pub fn set_native_attributes<'a>(
        &self,
        object: &crate::NativeObjectRef,
        input: &'a [crate::AttributeInput<'a>],
        limits: crate::AttributeTemplateLimits,
    ) -> Result<()> {
        self.session.set_native_attributes(object, input, limits)
    }
}
