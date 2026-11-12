// SPDX-License-Identifier: Apache-2.0
//! Execute native derivation with prepared parameters and destination ownership.
//! Returned handles are observed and published through the creation protocol.

use super::*;

impl Session {
    pub(super) fn derive_native(
        &self,
        base: &ManagedObjectRef,
        spec: BaseSpec<'_>,
        path: DerivationPath,
        parameters: ParameterPlan<'_>,
        output: Output,
        requirements: DerivationObservationPlan,
        diagnostics: &mut crate::error::ObjectCreationDiagnostics,
    ) -> Result<crate::CreatedObjects<Derived>> {
        let parent = resident::ParentSelection::Ordinary {
            shape: observation::Spec {
                identity: observation::Identity::from_base(&spec),
                maximum: spec.object_admission().metadata.maximum_bytes,
                history: requirements.parent,
            },
            path,
        };
        self.derive_with(
            base,
            parameters,
            output,
            parent,
            &requirements.child,
            diagnostics,
            |managed, output, evidence| {
                let resident::Provenance::Ordinary(provenance) = evidence.provenance else {
                    return Err(Error::Rejected(crate::RejectionReason::KeyDerivation(
                        crate::KeyDerivationRejection::OrdinaryDerivationProvenanceKind,
                    )));
                };

                match (output, evidence.output) {
                    (
                        Output::Symmetric(spec),
                        output_observation::Evidence::Symmetric {
                            protection,
                            mechanisms,
                        },
                    ) => Ok(Derived::Symmetric(DerivedSymmetricKey {
                        key: SymmetricKey {
                            managed,
                            algorithm: spec.algorithm,
                            protection,
                            allowed: mechanisms,
                        },
                        provenance,
                    })),
                    (
                        Output::Hkdf(spec, _),
                        output_observation::Evidence::Hkdf {
                            protection,
                            mechanisms,
                            ..
                        },
                    ) => Ok(Derived::Hkdf(DerivedHkdfKey {
                        key: HkdfKey {
                            managed,
                            spec,
                            protection,
                            mechanism_report: mechanisms,
                        },
                        provenance,
                    })),
                    _ => Err(Error::Rejected(crate::RejectionReason::KeyDerivation(
                        crate::KeyDerivationRejection::DerivedOutputEvidenceKind,
                    ))),
                }
            },
        )
    }

    // A single resident protocol preserves the distinct parent, first child and
    // output observations. Only pure publication remains in the caller closure.
    pub(in crate::crypto::derivation) fn derive_with<T>(
        &self,
        base: &ManagedObjectRef,
        parameters: ParameterPlan<'_>,
        output: Output,
        parent: resident::ParentSelection,
        child: &HistoryObservationPlan,
        diagnostics: &mut crate::error::ObjectCreationDiagnostics,
        finish: impl FnOnce(ManagedObjectRef, Output, resident::Evidence) -> Result<T>,
    ) -> Result<crate::CreatedObjects<T>> {
        output.validate(self)?;
        let reference_admission =
            self.reference_admission(crate::session::ReferenceMode::Synchronous, |state| {
                state.native.table.C_DeriveKey.ok_or(Error::Rejected(
                    crate::RejectionReason::NativeDerivation(
                        crate::NativeDerivationRejection::CDeriveKeyUnavailable,
                    ),
                ))?;
                Ok(())
            })?;
        let reservation = std::sync::Arc::new(managed::reserve_key(
            self,
            ManagedClass::SecretKey,
            output.id(),
        )?);
        let salt_reference = parameters.salt_reference();
        let salt_key = salt_reference
            .as_ref()
            .map(|salt| salt.reference())
            .transpose()?;
        let admission = output.admission().clone();
        let epoch = self.snapshot.authentication_stamp();
        let output_spec = match &output {
            Output::Symmetric(spec) => output_observation::Spec::symmetric(spec),
            Output::Hkdf(spec, _) => output_observation::Spec::hkdf(spec, *child),
        };
        // CallData and its enclosing SessionFrame are separate stable allocations.
        let frame_bytes = std::mem::size_of::<DeriveCall>()
            + crate::native::frame::SessionFrame::<'_, DeriveCall>::allocation_bytes()
            - std::mem::size_of::<Parameters>()
            - std::mem::size_of::<crate::attributes::OwnedTemplate>();
        let observation_fixed = resident::Initial::fixed_bytes()?;
        let fixed = frame_bytes
            .checked_add(observation_fixed)
            .and_then(|bytes| {
                bytes.checked_add(crate::error::PreparedCompletion::allocation_bytes())
            })
            .ok_or(Error::Rejected(crate::RejectionReason::KeyDerivation(
                crate::KeyDerivationRejection::DerivationGraphOverflow,
            )))?;
        let observations_bytes = resident::Initial::requested(
            parent,
            child,
            output_spec,
            &admission,
            output.id(),
            output.label(),
        )?;
        let mut required = parameters
            .allocation_bytes()?
            .checked_add(
                output
                    .template::<crate::attributes::TemplateSize>()?
                    .owned_bytes()?,
            )
            .and_then(|n| n.checked_add(fixed))
            .and_then(|n| n.checked_add(observations_bytes))
            .ok_or(Error::Rejected(crate::RejectionReason::KeyDerivation(
                crate::KeyDerivationRejection::DerivationGraphOverflow,
            )))?;
        let ((completion, permits, prepared, observations, registry, prepaid), access) =
            reservation.prepare_with_roles_prepaid(
                self,
                [
                    (Some(base), crate::session::activity::AccessMode::Read),
                    (
                        salt_key.as_ref(),
                        crate::session::activity::AccessMode::Read,
                    ),
                ],
                false,
                reference_admission.progress(),
                |overhead| loop {
                    let admitted = required.checked_add(overhead).ok_or(Error::Rejected(
                        crate::RejectionReason::KeyDerivation(
                            crate::KeyDerivationRejection::DerivationGraphOverflow,
                        ),
                    ))?;
                    self.snapshot.check_authentication_unchanged(epoch)?;
                    let (permits, mut prepaid) = reference_admission
                        .managed_with_observation_storage(1, admitted, || {
                            self.snapshot.observe_authentication_unchanged(epoch)
                        })?;
                    let parameter_storage = ParameterStorage::allocate(&parameters)?;
                    let template = crate::attributes::OwnedTemplateStorage::allocate(
                        output.template::<Template>()?,
                    )?;
                    let observations = resident::Initial::allocate(
                        parent,
                        child,
                        output_spec,
                        &admission,
                        output.id(),
                        output.label(),
                    )?;
                    let observation_bytes = observations.allocated_bytes()?;
                    let actual = parameter_storage
                        .allocated_bytes()?
                        .checked_add(template.allocated_bytes()?)
                        .and_then(|n| n.checked_add(fixed))
                        .and_then(|n| n.checked_add(observation_bytes))
                        .and_then(|bytes| bytes.checked_add(overhead))
                        .ok_or(Error::Rejected(crate::RejectionReason::KeyDerivation(
                            crate::KeyDerivationRejection::DerivationGraphOverflow,
                        )))?;
                    if actual > admitted {
                        drop((template, parameter_storage, observations));
                        drop(prepaid);
                        drop(permits);
                        required = actual.checked_sub(overhead).ok_or(Error::Rejected(
                            crate::RejectionReason::KeyDerivation(
                                crate::KeyDerivationRejection::DerivationGraphOverflow,
                            ),
                        ))?;
                        continue;
                    }
                    prepaid.release(admitted - actual);
                    prepaid.observation_budget()?;
                    let parameters = parameter_storage.bind(&parameters, &mut prepaid)?;
                    let template = template.bind(&mut prepaid)?;
                    let prepared = DeriveCall {
                        parameters,
                        template,
                        mechanism: CK_MECHANISM {
                            mechanism: 0,
                            pParameter: null_mut(),
                            ulParameterLen: 0,
                        },
                        created: CK_INVALID_HANDLE,
                        _credit: prepaid.split(frame_bytes)?,
                    };
                    let registry = crate::session::recovery::observations::Prepared::allocate(
                        &self.inner.symmetric_budget,
                        &mut prepaid,
                    )?;
                    let completion =
                        crate::error::PreparedCompletion::prepare("C_DeriveKey", &mut prepaid)?;
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
        reference_admission.check(&access)?;
        let handle = self.managed_handle(&access, base)?;
        if let Some(key) = &salt_key {
            self.managed_handle(&access, key)?;
        }
        let (coordination, access, cleanup) = observations.publish(
            self,
            access,
            prepared,
            &reservation,
            handle,
            admission.clone(),
            permits,
            epoch,
            registry,
            prepaid,
        )?;
        drop(reservation);
        // The public entry retains the charge through every typed projection,
        // including an observation error that carries the native creation.
        let (completion, cleanup) = diagnostics.insert((completion, cleanup));
        resident::run(
            self,
            &admission,
            reference_admission.progress(),
            epoch,
            coordination,
            access,
            completion,
            cleanup,
            |access, dispatch, cleanup, diagnostic| {
                reference_admission.check(access)?;
                execute_derivation(
                    self,
                    access,
                    base,
                    salt_key.as_ref(),
                    dispatch.call,
                    dispatch.creation,
                    cleanup,
                    diagnostic,
                )
            },
            |access, reference, evidence| {
                let result = finish(reference, output, evidence)?;
                base.identity.access.check(&self.snapshot)?;
                if let Some(salt) = &salt_reference {
                    let reference = salt.reference()?;
                    self.managed_handle(access, &reference)?;
                }
                self.entry(access)?;
                Ok(result)
            },
        )
    }
}

// The resident owner grants one dispatch. Its protection is retained by the
// frame, including when native completion is unknown; no waiter repeats C.
pub(super) fn execute_derivation(
    session: &Session,
    s: &crate::session::SessionAccess<'_>,
    base: &ManagedObjectRef,
    salt_key: Option<&ManagedObjectRef>,
    prepared: DeriveCall,
    mut creation: crate::managed::PreparedCreation,
    cleanup: &mut crate::error::CleanupStorage,
    diagnostic: &mut Option<crate::error::CompletionDiagnostic>,
) -> Result<crate::native::creation::CreatedObject> {
    let h = session.entry(s)?.handle;
    let handle = session.managed_handle(s, base)?;
    let salt_resource = if let Some(key) = salt_key {
        let native = session.managed_handle(s, key)?;
        Some((native, key.identity.resource()))
    } else {
        None
    };
    let call = s.native.table.C_DeriveKey.ok_or(Error::Rejected(
        crate::RejectionReason::NativeDerivation(
            crate::NativeDerivationRejection::CDeriveKeyUnavailable,
        ),
    ))?;
    let count = prepared.template.count()?;
    let scalars = prepared.parameters.scalars();
    let bytes_hash = prepared.parameters.bytes_hash();
    let mut frame = crate::native::frame::NativeFrame::session(s.clone(), prepared)?;
    // No creation is registered while local preconditions or frame allocation
    // can still fail. prepare_dispatch owns exact restitution until emission.
    let creation = creation.begin()?;
    let created = {
        let (returned, body) = frame.session_parts();
        let data = &mut *body.data;
        data.mechanism = data.parameters.mechanism();
        let mechanism_before = (
            data.mechanism.mechanism,
            data.mechanism.pParameter,
            data.mechanism.ulParameterLen,
        );

        creation.prepare_dispatch(s, || {
            session.entry(s)?;
            s.native.record("C_DeriveKey")
        })?;
        returned.arm();
        // SAFETY: all parameters/template/output storage and source and
        // destination activities are retained by the session frame. Its
        // mechanism points into stable Parameters, never stack storage.
        let rv = returned.observe(
            unsafe {
                call(
                    h,
                    &mut data.mechanism,
                    handle,
                    data.template.as_mut_ptr(),
                    count,
                    &mut data.created,
                )
            },
            &s.native,
        );
        let mutation = crate::native_return::MutationCall::Derive;
        let inspection = session.inspect_native_inputs(s, mutation.function(), rv, || {
            (
                data.mechanism.mechanism,
                data.mechanism.pParameter,
                data.mechanism.ulParameterLen,
            ) == mechanism_before
                && data.parameters.scalars() == scalars
                && data.parameters.bytes_hash() == bytes_hash
                && data.template.unchanged()
        });
        let completed = inspection.memory_returned();
        let unchanged = !inspection.violated();
        if !unchanged {
            returned.quarantine(&s.native);
        } else if completed {
            returned.terminated();
        } else {
            returned.recoverable();
            session.poison(s);
        }
        if !unchanged {
            let diagnostic =
                diagnostic
                    .take()
                    .ok_or(Error::Rejected(crate::RejectionReason::Diagnostics(
                        crate::DiagnosticsRejection::CompletionDiagnosticAlreadyConsumed,
                    )))?;
            return Err(cleanup.mark_remaining(diagnostic.boundary_failure(
                rv,
                Error::Rejected(crate::RejectionReason::KeyDerivation(
                    crate::KeyDerivationRejection::DerivationNativeInputMutation,
                )),
            )));
        }
        let native = inspection.check(!mutation.definite_object_refusal(rv));
        if native.is_err()
            && inspection.no_objects(crate::native_return::protocol::CreationContract::Function(
                mutation,
            ))
        {
            creation.refused(s, mutation, rv);
        }
        native?;
        if data.created == handle {
            managed::revoke_returned_source(s, base.identity.resource(), |cause| {
                cleanup.mark_remaining(cause)
            })?;
            return Err(cleanup.mark_remaining(Error::Rejected(
                crate::RejectionReason::NativeDerivation(
                    crate::NativeDerivationRejection::DeriveReturnedBaseHandle,
                ),
            )));
        }
        if let Some((salt_handle, resource)) = salt_resource {
            if data.created == salt_handle {
                managed::revoke_returned_source(s, resource, |cause| {
                    cleanup.mark_remaining(cause)
                })?;
                return Err(cleanup.mark_remaining(Error::Rejected(
                    crate::RejectionReason::KeyDerivation(
                        crate::KeyDerivationRejection::DeriveReturnedSaltHandle,
                    ),
                )));
            }
        }
        creation.handles_prepared(s, &[data.created], |cause| cleanup.mark_remaining(cause))?;
        data.created
    };
    drop(frame);

    Ok(crate::native::creation::CreatedObject::accepted(
        created, creation,
    ))
}
