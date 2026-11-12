// SPDX-License-Identifier: Apache-2.0
use super::*;
mod resolved_call;
use crate::{
    bounds, crypto::derivation::kem_output, managed, native_return::MutationCall,
    symmetric::memory::Buffer, Error, ManagedClass, Result, Session,
};
use fe11_sys::*;

pub(crate) struct KemCall {
    template: crate::attributes::OwnedTemplate,
    mechanism: CK_MECHANISM,
    bytes: Buffer,
    length: CK_ULONG,
    created: CK_OBJECT_HANDLE,
    _credit: crate::symmetric::memory::Credit,
}
// SAFETY: the mechanism is parameterless; OwnedTemplate and Buffer own all
// referents. Native scalar addresses are fixed by CallData before dispatch.
unsafe impl Send for KemCall {}

pub(crate) struct CompletedKem {
    pub(crate) created: crate::native::creation::CreatedObject,
    pub(crate) bytes: Buffer,
    pub(crate) length: CK_ULONG,
    pub(crate) expected_length: CK_ULONG,
}

enum Direction<'a> {
    Encapsulate(&'a KemEncapsulationKey),
    Decapsulate(&'a KemDecapsulationKey, &'a KemCiphertext),
}

impl Direction<'_> {
    fn variant(&self) -> MlKemParameterSet {
        match self {
            Self::Encapsulate(key) => key.public.parameter_set(),
            Self::Decapsulate(key, _) => key.parameter_set,
        }
    }

    fn key(&self) -> &ManagedObjectRef {
        match self {
            Self::Encapsulate(key) => &key.managed,
            Self::Decapsulate(key, _) => &key.managed,
        }
    }

    fn call(&self) -> MutationCall {
        match self {
            Self::Encapsulate(_) => MutationCall::Encapsulate,
            Self::Decapsulate(_, _) => MutationCall::Decapsulate,
        }
    }

    fn validate(&self) -> Result<()> {
        match self {
            Self::Encapsulate(_) => Ok(()),
            Self::Decapsulate(key, ciphertext) => {
                if ciphertext.parameter_set() != key.parameter_set {
                    return Err(Error::Rejected(crate::RejectionReason::KeyEncapsulation(
                        crate::KeyEncapsulationRejection::MlKemCiphertextParameterMismatch,
                    )));
                }
                Ok(())
            }
        }
    }
}

impl Session {
    fn kem_native(
        &self,
        direction: Direction<'_>,
        output: KemSharedKeySpec,
        diagnostics: &mut crate::error::ObjectCreationDiagnostics,
    ) -> Result<crate::CreatedObjects<(KemSharedKey, Buffer)>> {
        direction.validate()?;
        kem_output::validate(&output)?;
        let variant = direction.variant();

        let reference_admission =
            self.reference_admission(crate::session::ReferenceMode::Synchronous, |state| {
                let functions = state.native.kem.ok_or(Error::Rejected(
                    crate::RejectionReason::KeyEncapsulation(
                        crate::KeyEncapsulationRejection::MlKemRequiresSelected32Interface,
                    ),
                ))?;
                // Resolve the exact required entry before reserving creation effects.
                match &direction {
                    Direction::Encapsulate(_) if functions.encapsulate.is_none() => {
                        return Err(Error::Rejected(crate::RejectionReason::KeyEncapsulation(
                            crate::KeyEncapsulationRejection::CEncapsulateKeyUnavailable,
                        )))
                    }
                    Direction::Decapsulate(_, _) if functions.decapsulate.is_none() => {
                        return Err(Error::Rejected(crate::RejectionReason::KeyEncapsulation(
                            crate::KeyEncapsulationRejection::CDecapsulateKeyUnavailable,
                        )))
                    }
                    _ => {}
                }
                Ok(())
            })?;
        let reservation = std::sync::Arc::new(managed::reserve_key(
            self,
            ManagedClass::SecretKey,
            kem_output::id(&output),
        )?);
        use managed::kem_creation::InitialKem;
        let admission = kem_output::admission(&output).clone();
        let epoch = self.snapshot.authentication_stamp();
        // CallData and its enclosing SessionFrame are separate stable allocations.
        let frame_bytes = std::mem::size_of::<KemCall>()
            + crate::native::frame::SessionFrame::<'_, KemCall>::allocation_bytes()
            - std::mem::size_of::<crate::attributes::OwnedTemplate>();
        let fixed = frame_bytes
            .checked_add(InitialKem::fixed_bytes()?)
            .and_then(|bytes| {
                bytes.checked_add(crate::error::PreparedCompletion::allocation_bytes())
            })
            .ok_or(Error::Rejected(crate::RejectionReason::KeyEncapsulation(
                crate::KeyEncapsulationRejection::MlKemNativeGraphOverflow,
            )))?;
        let length = variant.ciphertext_length();
        let expected_length = bounds::ck_length(length)?;
        let observation_spec = kem_output::observation_spec(&output);
        let observation_bytes = InitialKem::requested(
            &admission,
            kem_output::id(&output),
            kem_output::label(&output),
            observation_spec,
        )?;
        let mut required = kem_output::template_as::<crate::attributes::TemplateSize>(&output)?
            .owned_bytes()?
            .checked_add(length)
            .and_then(|bytes| bytes.checked_add(fixed))
            .and_then(|bytes| bytes.checked_add(observation_bytes))
            .ok_or(Error::Rejected(crate::RejectionReason::KeyEncapsulation(
                crate::KeyEncapsulationRejection::MlKemNativeGraphOverflow,
            )))?;
        let ((completion, permits, prepared, observations, registry, prepaid), state) = reservation
            .prepare_with_roles_prepaid(
                self,
                [(
                    Some(direction.key()),
                    crate::session::activity::AccessMode::Read,
                )],
                false,
                reference_admission.progress(),
                |overhead| loop {
                    let admitted = required.checked_add(overhead).ok_or(Error::Rejected(
                        crate::RejectionReason::KeyEncapsulation(
                            crate::KeyEncapsulationRejection::MlKemNativeGraphOverflow,
                        ),
                    ))?;
                    self.snapshot.check_authentication_unchanged(epoch)?;
                    let (permits, mut prepaid) = reference_admission
                        .managed_with_observation_storage(1, admitted, || {
                            self.snapshot.observe_authentication_unchanged(epoch)
                        })?;
                    let template = crate::attributes::OwnedTemplateStorage::allocate(
                        kem_output::template(&output)?,
                    )?;
                    let bytes = crate::symmetric::memory::UnboundBuffer::allocate(length)?;
                    let observations = InitialKem::allocate(
                        &admission,
                        kem_output::id(&output),
                        kem_output::label(&output),
                        observation_spec,
                    )?;
                    let observation_bytes = observations.allocated_bytes()?;
                    let actual = template
                        .allocated_bytes()?
                        .checked_add(bytes.allocated())
                        .and_then(|bytes| bytes.checked_add(fixed))
                        .and_then(|bytes| bytes.checked_add(observation_bytes))
                        .and_then(|bytes| bytes.checked_add(overhead))
                        .ok_or(Error::Rejected(crate::RejectionReason::KeyEncapsulation(
                            crate::KeyEncapsulationRejection::MlKemNativeGraphOverflow,
                        )))?;
                    if actual > admitted {
                        drop((bytes, template, observations));
                        drop(prepaid);
                        drop(permits);
                        required = actual.checked_sub(overhead).ok_or(Error::Rejected(
                            crate::RejectionReason::KeyEncapsulation(
                                crate::KeyEncapsulationRejection::MlKemNativeGraphOverflow,
                            ),
                        ))?;
                        continue;
                    }
                    prepaid.release(admitted - actual);
                    prepaid.observation_budget()?;
                    let template = template.bind(&mut prepaid)?;
                    let mut bytes = bytes.bind(&mut prepaid)?;
                    if let Direction::Decapsulate(_, ciphertext) = &direction {
                        bytes.as_mut().copy_from_slice(ciphertext.as_bytes());
                    }
                    let prepared = KemCall {
                        template,
                        mechanism: CK_MECHANISM {
                            mechanism: CKM_ML_KEM,
                            pParameter: std::ptr::null_mut(),
                            ulParameterLen: 0,
                        },
                        bytes,
                        length: expected_length,
                        created: CK_INVALID_HANDLE,
                        _credit: prepaid.split(frame_bytes)?,
                    };
                    let registry = crate::session::recovery::observations::Prepared::allocate(
                        &self.inner.symmetric_budget,
                        &mut prepaid,
                    )?;
                    let completion = crate::error::PreparedCompletion::prepare(
                        direction.call().function(),
                        &mut prepaid,
                    )?;
                    let coordination = prepaid.split(overhead)?;
                    return Ok((
                        (
                            completion,
                            permits,
                            prepared,
                            observations,
                            registry,
                            prepaid,
                        ),
                        coordination,
                    ));
                },
                |access| reference_admission.check(access),
            )?;
        reference_admission.check(&state)?;
        self.managed_handle(&state, direction.key())?;
        let continuation = observations.publish(
            self,
            state,
            prepared,
            &reservation,
            admission.clone(),
            permits,
            epoch,
            registry,
            prepaid,
        )?;
        drop(reservation);
        continuation.finish(
            self,
            &admission,
            reference_admission.progress(),
            diagnostics,
            completion,
            |access, dispatch, cleanup, diagnostic| {
                reference_admission.check(access)?;
                execute_kem(
                    self,
                    access,
                    &direction,
                    dispatch.call,
                    dispatch.creation,
                    cleanup,
                    diagnostic,
                )
            },
            |access, reference, evidence, bytes| {
                let key = kem_output::finish_observed(reference, output, evidence)?;
                self.snapshot.check_authentication_unchanged(epoch)?;
                self.entry(access)?;
                let bytes = bytes.take().ok_or(Error::Rejected(
                    crate::RejectionReason::KeyEncapsulation(
                        crate::KeyEncapsulationRejection::KemCiphertextOwnerAbsent,
                    ),
                ))?;
                Ok((key, bytes))
            },
        )
    }

    /// Create one protected32-byte secret and public ciphertext. The requested
    /// usage is verified; no sizing call, retry, fallback or implicit KDF occurs.
    /// If the module reports CKR_BUFFER_TOO_SMALL despite the parameter-set
    /// capacity, its length is preserved in OutputBufferTooSmall, enclosed by
    /// ObjectsMayRemain. With an integrity failure, NativeOutputAndLocalFailure
    /// preserves the observation and its local cause. No output is published
    /// and the observation does not permit replay.
    pub fn encapsulate_kem(
        &self,
        key: &KemEncapsulationKey,
        output: KemSharedKeySpec,
    ) -> Result<crate::CreatedObjects<KemEncapsulation>> {
        let mut diagnostics = None;
        let variant = key.public.parameter_set();
        Ok(self
            .kem_native(Direction::Encapsulate(key), output, &mut diagnostics)?
            .map(|(shared_key, bytes)| KemEncapsulation {
                ciphertext: KemCiphertext::from_native(variant, bytes),
                shared_key,
            }))
    }

    /// Create one protected secret from an exact-width public ciphertext.
    /// ML-KEM implicit rejection is preserved: success does not authenticate the
    /// ciphertext or the sender and supplies no secret-dependent validity flag.
    pub fn decapsulate_kem(
        &self,
        key: &KemDecapsulationKey,
        ciphertext: &KemCiphertext,
        output: KemSharedKeySpec,
    ) -> Result<crate::CreatedObjects<KemSharedKey>> {
        let mut diagnostics = None;
        self.kem_native(
            Direction::Decapsulate(key, ciphertext),
            output,
            &mut diagnostics,
        )
        .map(|outcome| outcome.map(|(key, _)| key))
    }
}

fn execute_kem(
    session: &Session,
    state: &crate::session::SessionAccess<'_>,
    direction: &Direction<'_>,
    prepared: KemCall,
    mut creation: managed::PreparedCreation,
    cleanup: &mut crate::error::CleanupStorage,
    diagnostic: &mut Option<crate::error::CompletionDiagnostic>,
) -> Result<CompletedKem> {
    let expected_length = bounds::ck_length(direction.variant().ciphertext_length())?;
    let count = prepared.template.count()?;
    let entry = session.entry(state)?;

    let handle = session.managed_handle(state, direction.key())?;

    let functions =
        state
            .native
            .kem
            .ok_or(Error::Rejected(crate::RejectionReason::KeyEncapsulation(
                crate::KeyEncapsulationRejection::MlKemRequiresSelected32Interface,
            )))?;
    // Resolve the exact required entry before reserving creation effects.
    let native_call = resolved_call::Call::resolve(functions, direction)?;
    let mut frame = crate::native::frame::NativeFrame::session(state.clone(), prepared)?;
    // No creation is registered while local preconditions or frame allocation
    // can still fail. prepare_dispatch owns exact restitution until emission.
    let creation = creation.begin()?;
    let call = direction.call();
    let (created, length) = {
        let (returned, body) = frame.session_parts();
        let data = &mut *body.data;

        creation.prepare_dispatch(state, || {
            session.entry(state)?;
            state.native.record(call.function())
        })?;
        returned.arm();
        // SAFETY: exact selected interface; stable owned template, buffers,
        // mechanism and outputs, with retained source/destination activity.
        let rv = returned.observe(
            unsafe {
                match native_call {
                    resolved_call::Call::Encapsulate(native) => native(
                        entry.handle,
                        &mut data.mechanism,
                        handle,
                        data.template.as_mut_ptr(),
                        count,
                        data.bytes.as_mut().as_mut_ptr(),
                        &mut data.length,
                        &mut data.created,
                    ),
                    resolved_call::Call::Decapsulate(native) => native(
                        entry.handle,
                        &mut data.mechanism,
                        handle,
                        data.template.as_mut_ptr(),
                        count,
                        data.bytes.as_mut().as_mut_ptr(),
                        expected_length,
                        &mut data.created,
                    ),
                }
            },
            &state.native,
        );
        let inspection = session.inspect_native_inputs(state, call.function(), rv, || {
            data.mechanism.mechanism == CKM_ML_KEM
                && data.mechanism.pParameter.is_null()
                && data.mechanism.ulParameterLen == 0
                && data.template.unchanged()
                && match direction {
                    Direction::Decapsulate(_, ciphertext) => {
                        data.bytes.as_slice() == ciphertext.as_bytes()
                    }
                    Direction::Encapsulate(_) => true,
                }
        });
        let completed = inspection.memory_returned();
        let unchanged = !inspection.violated();
        // BUFFER_TOO_SMALL may legitimately return a larger required size;
        // only success claims that the advertised output was written.
        let overflow = rv == CKR_OK && data.length > expected_length;
        if !unchanged || overflow {
            returned.quarantine(&state.native);
        } else if completed {
            returned.terminated();
        } else {
            returned.recoverable();
            session.poison(state);
        }
        if completed
            && rv == CKR_BUFFER_TOO_SMALL
            && matches!(&direction, Direction::Encapsulate(_))
        {
            let local = (!unchanged).then(|| {
                Error::Rejected(crate::RejectionReason::KeyEncapsulation(
                    crate::KeyEncapsulationRejection::MlKemNativeInputOrOutputCapacityViolation,
                ))
            });
            return Err(crate::error::encapsulation::capacity_failure(
                data.length,
                data.bytes.as_mut().len(),
                local,
                diagnostic
                    .take()
                    .ok_or(Error::Rejected(crate::RejectionReason::Diagnostics(
                        crate::DiagnosticsRejection::CompletionDiagnosticAlreadyConsumed,
                    )))?,
                cleanup,
            ));
        }
        if !unchanged || overflow {
            let diagnostic =
                diagnostic
                    .take()
                    .ok_or(Error::Rejected(crate::RejectionReason::Diagnostics(
                        crate::DiagnosticsRejection::CompletionDiagnosticAlreadyConsumed,
                    )))?;
            return Err(cleanup.mark_remaining(diagnostic.boundary_failure(
                rv,
                Error::Rejected(crate::RejectionReason::KeyEncapsulation(
                    crate::KeyEncapsulationRejection::MlKemNativeInputOrOutputCapacityViolation,
                )),
            )));
        }
        let native = inspection.check(!call.definite_object_refusal(rv));
        if native.is_err()
            && inspection.no_objects(crate::native_return::protocol::CreationContract::Function(
                call,
            ))
        {
            creation.refused(state, call, rv);
        }
        native?;
        let identity = (|| -> Result<()> {
            if data.created == handle {
                managed::revoke_returned_source(
                    state,
                    direction.key().identity.resource(),
                    |cause| cleanup.mark_remaining(cause),
                )?;
                return Err(cleanup.mark_remaining(Error::Rejected(
                    crate::RejectionReason::KeyEncapsulation(
                        crate::KeyEncapsulationRejection::MlKemReturnedBaseHandle,
                    ),
                )));
            }
            creation.handles_prepared(state, &[data.created], |cause| {
                cleanup.mark_remaining(cause)
            })?;
            Ok(())
        })();
        if let Err(cause) = identity {
            let completed = diagnostic
                .take()
                .expect("creation completion prepared before dispatch");
            return completed.finish(Err(cause));
        }
        (data.created, data.length)
    };
    let bytes = frame.into_inner()?.data.into_inner().bytes;
    Ok(CompletedKem {
        created: crate::native::creation::CreatedObject::accepted(created, creation),
        bytes,
        length,
        expected_length,
    })
}
