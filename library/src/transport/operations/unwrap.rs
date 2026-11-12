// SPDX-License-Identifier: Apache-2.0
//! Unwrap keys into prepared destinations with creation and cleanup ownership.
//! Observation and publication follow the exact native result without replay.

use super::*;

impl Session {
    /// Restore a symmetric key from wrapped bytes using the requested native attributes.
    ///
    /// # AES key length
    /// On selected PKCS#11 tables 2.20, 2.30, 2.40, 3.0 and 3.1, the AES
    /// template omits CKA_VALUE_LEN as required by the AES key table's footnote 6
    /// (3.1, section 6.10.2). The mechanism determines the recovered key length;
    /// the requested AES size is neither transmitted nor implicitly observed.
    /// On tables 3.2 and later 3.x, the length request is included. For classical
    /// C_UnwrapKey, PKCS#11 3.2 section 5.18.4 requires a conforming module to
    /// return CKR_WRAPPED_KEY_LEN_RANGE on a length conflict. The authenticated
    /// route also includes the request, but that clause does not specify
    /// C_UnwrapKeyAuthenticated's length-conflict behavior.
    ///
    /// The returned algorithm retains the caller's selection, not an attestation
    /// of native key length. Select [`crate::Attribute::ValueLen`] in
    /// `spec.key.admission.public_attributes`, or read it explicitly through
    /// [`crate::Session::managed_attributes`], to obtain the module's length observation.
    /// Compare an available value in the application when a particular length is
    /// required; an unavailable observation is not evidence of the requested size.
    pub fn unwrap_symmetric_key(
        &self,
        kek: &UnwrappingKey,
        parameters: UnwrapParameters<'_>,
        ciphertext: &[u8],
        spec: SymmetricIntroductionSpec,
    ) -> Result<crate::CreatedObjects<IntroducedSymmetricKey>> {
        let mut diagnostics = None;
        Ok(self
            .unwrap_destination(
                kek,
                parameters,
                ciphertext,
                Destination::Symmetric(spec),
                &mut diagnostics,
            )?
            .map(|key| match key {
                DestinationKey::Symmetric(key) => key,
                _ => unreachable!(),
            }))
    }

    /// Restore an AES KEK with caller-selected native usages and transport views.
    ///
    /// The template follows the version-dependent AES length rules documented by
    /// [`crate::Session::unwrap_symmetric_key`]. On tables through 3.1, no length request
    /// is transmitted or implicitly observed. The KEK type alone does not attest
    /// its size, including when it is subsequently used to wrap other keys.
    /// Select [`crate::Attribute::ValueLen`] in `spec.key.admission.public_attributes`
    /// or use [`crate::Session::managed_attributes`] and compare an available observation
    /// before using the KEK when the application requires a particular length.
    /// Unlike KEK import, this operation does not compare the module's reported
    /// length with the requested size. No additional native read is imposed.
    pub fn unwrap_aes_key_encryption_key(
        &self,
        kek: &UnwrappingKey,
        parameters: UnwrapParameters<'_>,
        ciphertext: &[u8],
        spec: AesKeyEncryptionSpec,
    ) -> Result<crate::CreatedObjects<AesKeyEncryptionKey>> {
        let mut diagnostics = None;
        Ok(self
            .unwrap_destination(
                kek,
                parameters,
                ciphertext,
                Destination::AesKek(spec),
                &mut diagnostics,
            )?
            .map(|key| match key {
                DestinationKey::AesKek(key) => key,
                _ => unreachable!(),
            }))
    }

    pub(crate) fn unwrap_prepared_signing(
        &self,
        kek: &UnwrappingKey,
        parameters: UnwrapParameters<'_>,
        ciphertext: &[u8],
        destination: crate::crypto::PreparedSigningRestore<'_>,
        diagnostics: &mut crate::error::ObjectCreationDiagnostics,
    ) -> Result<crate::CreatedObjects<crate::IntroducedSigningKey>> {
        Ok(self
            .unwrap_destination(
                kek,
                parameters,
                ciphertext,
                Destination::Signing(destination),
                diagnostics,
            )?
            .map(|key| match key {
                DestinationKey::Signing(key) => key,
                _ => unreachable!(),
            }))
    }

    pub(in crate::transport) fn unwrap_prepared_rsa(
        &self,
        kek: &UnwrappingKey,
        parameters: UnwrapParameters<'_>,
        ciphertext: &[u8],
        destination: super::super::rsa::PreparedRsaRestore<'_>,
        diagnostics: &mut crate::error::ObjectCreationDiagnostics,
    ) -> Result<crate::CreatedObjects<RsaKeyEncryptionPrivate>> {
        Ok(self
            .unwrap_destination(
                kek,
                parameters,
                ciphertext,
                Destination::Rsa(destination),
                diagnostics,
            )?
            .map(|key| match key {
                DestinationKey::Rsa(key) => key,
                _ => unreachable!(),
            }))
    }

    pub(crate) fn unwrap_prepared_agreement(
        &self,
        kek: &UnwrappingKey,
        parameters: UnwrapParameters<'_>,
        ciphertext: &[u8],
        destination: crate::crypto::derivation::PreparedAgreementRestore,
        diagnostics: &mut crate::error::ObjectCreationDiagnostics,
    ) -> Result<crate::CreatedObjects<crate::IntroducedAgreementKey>> {
        Ok(self
            .unwrap_destination(
                kek,
                parameters,
                ciphertext,
                Destination::Agreement(destination),
                diagnostics,
            )?
            .map(|key| match key {
                DestinationKey::Agreement(key) => key,
                _ => unreachable!(),
            }))
    }

    pub(super) fn unwrap_destination(
        &self,
        kek: &UnwrappingKey,
        parameters: UnwrapParameters<'_>,
        ciphertext: &[u8],
        destination: Destination<'_>,
        diagnostics: &mut crate::error::ObjectCreationDiagnostics,
    ) -> Result<crate::CreatedObjects<DestinationKey>> {
        destination.validate()?;
        let profile = parameters.profile();
        let call = TransportInputs::validate_unwrap(&parameters)?;
        let class = destination.class();
        // A requested application ID does not alias the KEK's native handle.
        // Reserve the destination and retain the source resource independently.
        let reference_admission =
            self.reference_admission(crate::session::ReferenceMode::Synchronous, |state| {
                if matches!(call, MutationCall::UnwrapAuthenticated) {
                    state
                        .native
                        .authenticated_transport
                        .and_then(|functions| functions.unwrap)
                        .ok_or(Error::Rejected(
                            crate::RejectionReason::KeyTransport(crate::KeyTransportRejection::CUnwrapKeyAuthenticatedUnavailableInSelectedInterface),
                        ))?;
                } else {
                    state
                        .native
                        .table
                        .C_UnwrapKey
                        .ok_or(Error::Rejected(crate::RejectionReason::KeyTransport(crate::KeyTransportRejection::CUnwrapKeyUnavailable)))?;
                }
                Ok(())
            })?;
        // Keep one decision across estimation, construction and resource-wait retries.
        let include_length =
            destination.unwrap_includes_value_len(self.inner.module_binding.table_version);
        let reservation = Arc::new(managed::reserve_key(self, class, destination.id())?);

        use managed::restoration::InitialRestoration;
        let admission = destination.object_admission().clone();
        let contextual = false;
        let epoch = self.snapshot.authentication_stamp();
        let publication_source = destination.publication_source().unwrap_or(&[]);
        // CallData and its enclosing SessionFrame are separate stable allocations.
        let frame_bytes = std::mem::size_of::<UnwrapCall>()
            + crate::native::frame::SessionFrame::<'_, UnwrapCall>::allocation_bytes()
            - std::mem::size_of::<crate::attributes::OwnedTemplate>()
            - if matches!(&parameters, UnwrapParameters::AuthenticatedGcm { .. }) {
                std::mem::size_of::<super::super::authenticated::GcmBuffers>()
            } else {
                0
            };
        let observation_fixed = InitialRestoration::fixed_bytes()?;
        let fixed = frame_bytes
            .checked_add(observation_fixed)
            .and_then(|bytes| {
                bytes.checked_add(crate::error::PreparedCompletion::allocation_bytes())
            })
            .ok_or(Error::Rejected(crate::RejectionReason::KeyTransport(
                crate::KeyTransportRejection::UnwrappingStorageSize,
            )))?;
        let observations = destination.with_observation(|plan| {
            InitialRestoration::requested(
                class,
                &admission,
                destination.id(),
                destination.label(),
                plan,
            )
        })?;
        let mut required = destination
            .template_size(include_length)?
            .owned_bytes()?
            .checked_add(TransportStorage::unwrap_allocation_bytes(&parameters)?)
            .and_then(|v| v.checked_add(fixed))
            .and_then(|v| v.checked_add(observations))
            .and_then(|v| v.checked_add(ciphertext.len()))
            .and_then(|v| v.checked_add(publication_source.len()))
            .ok_or(Error::Rejected(crate::RejectionReason::KeyTransport(
                crate::KeyTransportRejection::UnwrappingStorageSize,
            )))?;
        let ((completion, permit, prepared, observations, publication, registry, prepaid), access) =
            reservation.prepare_with_roles_prepaid(
                self,
                [(
                    Some(kek.inner.managed()),
                    crate::session::activity::AccessMode::Read,
                )],
                contextual,
                reference_admission.progress(),
                |overhead| loop {
                    let admitted = required.checked_add(overhead).ok_or(Error::Rejected(
                        crate::RejectionReason::KeyTransport(
                            crate::KeyTransportRejection::UnwrappingStorageSize,
                        ),
                    ))?;
                    self.snapshot.check_authentication_unchanged(epoch)?;
                    let (permit, mut prepaid) = reference_admission
                        .managed_with_observation_storage(1, admitted, || {
                            self.snapshot.observe_authentication_unchanged(epoch)
                        })?;
                    let inputs = TransportStorage::for_unwrap(&parameters)?;
                    let template = crate::attributes::OwnedTemplateStorage::allocate(
                        destination.template(include_length)?,
                    )?;
                    let input =
                        crate::symmetric::memory::UnboundBuffer::allocate(ciphertext.len())?;
                    let publication = crate::crypto::integer_key::PublicDerStorage::allocate(
                        publication_source.len(),
                    )?;
                    let observations = destination.with_observation(|plan| {
                        InitialRestoration::allocate(
                            class,
                            &admission,
                            destination.id(),
                            destination.label(),
                            plan,
                        )
                    })?;
                    let observation_bytes = observations.allocated_bytes()?;
                    let actual = inputs
                        .allocated_bytes()?
                        .checked_add(template.allocated_bytes()?)
                        .and_then(|v| v.checked_add(fixed))
                        .and_then(|v| v.checked_add(input.allocated()))
                        .and_then(|v| v.checked_add(publication.allocated()))
                        .and_then(|v| v.checked_add(observation_bytes))
                        .and_then(|bytes| bytes.checked_add(overhead))
                        .ok_or(Error::Rejected(crate::RejectionReason::KeyTransport(
                            crate::KeyTransportRejection::UnwrappingStorageSize,
                        )))?;
                    if actual > admitted {
                        drop((inputs, template, input, publication, observations));
                        drop(prepaid);
                        drop(permit);
                        required = actual.checked_sub(overhead).ok_or(Error::Rejected(
                            crate::RejectionReason::KeyTransport(
                                crate::KeyTransportRejection::UnwrappingStorageSize,
                            ),
                        ))?;
                        continue;
                    }
                    prepaid.release(admitted - actual);
                    prepaid.observation_budget()?;
                    let inputs = inputs.bind(&mut prepaid)?;
                    let template = template.bind(&mut prepaid)?;
                    let mut input = input.bind(&mut prepaid)?;
                    input.as_mut().copy_from_slice(ciphertext);
                    let prepared = UnwrapCall {
                        inputs,
                        template,
                        input,
                        mechanism: mechanism(profile),
                        output: CK_INVALID_HANDLE,
                        _credit: prepaid.split(frame_bytes)?,
                    };
                    let publication = publication.bind(publication_source, &mut prepaid)?;
                    let registry = crate::session::recovery::observations::Prepared::allocate(
                        &self.inner.symmetric_budget,
                        &mut prepaid,
                    )?;
                    let completion =
                        crate::error::PreparedCompletion::prepare(call.function(), &mut prepaid)?;
                    let coordination = prepaid.split(overhead)?;
                    return Ok((
                        (
                            completion,
                            permit,
                            prepared,
                            observations,
                            publication,
                            registry,
                            prepaid,
                        ),
                        coordination,
                    ));
                },
                |access| reference_admission.check(access),
            )?;
        reference_admission.check(&access)?;

        kek.inner.native_handle(&access, self)?;
        let restoration = observations.publish(
            self,
            access,
            prepared,
            &reservation,
            class,
            admission.clone(),
            publication,
            permit,
            epoch,
            registry,
            prepaid,
        )?;
        drop(reservation);
        // Both callbacks borrow this one input selection. Only a completed
        // resident observation can consume it to construct the public result.
        let destination = std::cell::RefCell::new(Some(destination));
        restoration.finish(
            self,
            &admission,
            reference_admission.progress(),
            contextual,
            diagnostics,
            completion,
            |access, dispatch, cleanup, diagnostic| {
                reference_admission.check(access)?;
                self.entry(access)?;
                execute_unwrap(
                    self,
                    access,
                    kek,
                    &parameters,
                    ciphertext,
                    dispatch.call,
                    dispatch.creation,
                    cleanup,
                    diagnostic,
                )
            },
            |access, reference, evidence, public| {
                let destination = destination.borrow_mut().take().ok_or(Error::Rejected(
                    crate::RejectionReason::KeyTransport(
                        crate::KeyTransportRejection::RestorationAlreadyConsumed,
                    ),
                ))?;
                let key = destination.finish_observed(reference, evidence, public)?;
                kek.inner.native_handle(access, self)?;
                self.snapshot.check_authentication_unchanged(epoch)?;
                self.entry(access)?;
                Ok(key)
            },
        )
    }
}

pub(super) fn execute_unwrap(
    session: &Session,
    s: &crate::session::SessionAccess<'_>,
    kek: &UnwrappingKey,
    parameters: &UnwrapParameters<'_>,
    ciphertext: &[u8],
    prepared: UnwrapCall,
    mut creation: managed::PreparedCreation,
    cleanup: &mut crate::error::CleanupStorage,
    diagnostic: &mut Option<crate::error::CompletionDiagnostic>,
) -> Result<crate::native::creation::CreatedObject> {
    let profile = parameters.profile();
    let call = TransportInputs::validate_unwrap(parameters)?;
    let h = session.entry(s)?.handle;
    let key_handle = kek.inner.native_handle(s, session)?;
    let native_call = resolved::Unwrap::resolve(&s.native, prepared.inputs.aad())?;
    let count = prepared.template.count()?;
    let n = bounds::ck_length(prepared.input.capacity())?;
    let mut frame = crate::native::frame::NativeFrame::session(s.clone(), prepared)?;
    // No creation is registered while local preconditions or frame allocation
    // can still fail. prepare_dispatch owns exact restitution until emission.
    let creation = creation.begin()?;
    creation.prepare_dispatch(s, || {
        session.entry(s)?;
        s.native.record(call.function())
    })?;
    let output = {
        let (returned, body) = frame.session_parts();
        let data = &mut *body.data;
        // Copy by-value arguments before exposing the parameter pointer;
        // no Rust borrow of inputs spans the native call.
        data.mechanism = data.inputs.mechanism(profile);
        let pointer = data.mechanism.pParameter;
        returned.arm();
        // SAFETY: exact selected ABI, stable owned descriptors, parameter
        // structs, buffers and output, with retained KEK/destination guards.
        let rv = returned.observe(
            unsafe {
                match native_call {
                    resolved::Unwrap::Authenticated {
                        native,
                        aad,
                        aad_len,
                    } => native(
                        h,
                        &mut data.mechanism,
                        key_handle,
                        data.input.as_mut().as_mut_ptr(),
                        n,
                        data.template.as_mut_ptr(),
                        count,
                        aad,
                        aad_len,
                        &mut data.output,
                    ),
                    resolved::Unwrap::Standard(native) => native(
                        h,
                        &mut data.mechanism,
                        key_handle,
                        data.input.as_mut().as_mut_ptr(),
                        n,
                        data.template.as_mut_ptr(),
                        count,
                        &mut data.output,
                    ),
                }
            },
            &s.native,
        );
        let inspection = session.inspect_native_inputs(s, call.function(), rv, || {
            data.inputs.unchanged(&data.mechanism, pointer, parameters)
                && data.template.unchanged()
                && data.input.as_slice() == ciphertext
        });
        let completed = inspection.memory_returned();
        let valid = !inspection.violated();
        if !valid {
            returned.quarantine(&s.native);
        } else if completed {
            returned.terminated();
        } else {
            returned.recoverable();
            session.poison(s);
        }
        if !valid {
            let diagnostic =
                diagnostic
                    .take()
                    .ok_or(Error::Rejected(crate::RejectionReason::Diagnostics(
                        crate::DiagnosticsRejection::CompletionDiagnosticAlreadyConsumed,
                    )))?;
            return Err(cleanup.mark_remaining(diagnostic.boundary_failure(
                rv,
                Error::Rejected(crate::RejectionReason::KeyTransport(
                    crate::KeyTransportRejection::UnwrappingInputsChanged,
                )),
            )));
        }
        let native = inspection.check(!call.definite_object_refusal(rv));
        if native.is_err()
            && inspection.no_objects(crate::native_return::protocol::CreationContract::Function(
                call,
            ))
        {
            creation.refused(s, call, rv);
        }
        native?;
        let identity = (|| -> Result<()> {
            if data.output == key_handle {
                managed::revoke_returned_source(
                    s,
                    kek.inner.managed().identity.resource(),
                    |cause| cleanup.mark_remaining(cause),
                )?;
                return Err(cleanup.mark_remaining(Error::Rejected(
                    crate::RejectionReason::KeyTransport(
                        crate::KeyTransportRejection::UnwrapReturnedKekHandle,
                    ),
                )));
            }
            creation.handles_prepared(s, &[data.output], |cause| cleanup.mark_remaining(cause))?;
            Ok(())
        })();
        if let Err(cause) = identity {
            let completed = diagnostic
                .take()
                .expect("creation completion prepared before dispatch");
            return completed.finish(Err(cause));
        }
        data.output
    };
    drop(frame);
    Ok(crate::native::creation::CreatedObject::accepted(
        output, creation,
    ))
}
