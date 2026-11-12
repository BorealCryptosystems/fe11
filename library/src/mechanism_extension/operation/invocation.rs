// SPDX-License-Identifier: Apache-2.0
//! Dispatch a prepared extension through its operation-specific owner.
//! Secondary key roles and parameter alignment determine the native route.

use super::*;

pub(super) fn execute_published<'a, T>(
    session: &crate::Session,
    request: impl Into<super::super::graph::recipe::Request<'a>>,
    input: ExtensionInput<'_>,
    limits: crate::InputLimits,
    mut authentication: Option<crate::ContextAuthentication>,
    alignment: usize,
    sources: [Option<&crate::NativeObjectRef>; 4],
    validate_publication: bool,
    publish: impl FnOnce(ExtensionResult) -> Result<T>,
    root: &mut Invocation,
) -> Result<T> {
    let mut prepared_authentication;
    let request = request.into();
    if !alignment.is_power_of_two() {
        return Err(Error::Rejected(
            crate::RejectionReason::MechanismExtensions(
                crate::MechanismExtensionsRejection::NativeOutputAlignment,
            ),
        ));
    }
    // Generated typed recipes without embedded secondary keys use the same
    // owner as public extension requests. Compound key recipes retain their
    // secondary sources in the dedicated binding used by the native route.
    if sources.iter().all(Option::is_none) {
        match &input {
            ExtensionInput::Digest { .. } | ExtensionInput::DigestMultipart { .. }
                if alignment == 1 =>
            {
                return crate::advanced::digest::batch::execute(
                    session,
                    request,
                    input,
                    limits,
                    authentication,
                    root.digest(),
                )
                .and_then(publish)
            }
            ExtensionInput::Encrypt { .. }
            | ExtensionInput::Decrypt { .. }
            | ExtensionInput::EncryptMultipart { .. }
            | ExtensionInput::DecryptMultipart { .. }
                if alignment == 1 =>
            {
                return crate::advanced::cipher::batch::execute(
                    session,
                    request,
                    input,
                    limits,
                    authentication,
                    root.cipher(),
                )
                .and_then(publish)
            }
            ExtensionInput::Sign { .. }
            | ExtensionInput::Verify { .. }
            | ExtensionInput::SignMultipart { .. }
            | ExtensionInput::VerifyMultipart { .. }
            | ExtensionInput::VerifySignature { .. }
            | ExtensionInput::VerifySignatureMultipart { .. }
                if alignment
                    == crate::advanced::signature::output_alignment(
                        request.contract.mechanism_number(),
                    ) =>
            {
                if validate_publication {
                    return crate::advanced::signature::batch::execute_and_publish(
                        session,
                        request,
                        input,
                        limits,
                        authentication,
                        publish,
                        root.signature(),
                    );
                }
                return crate::advanced::signature::batch::execute(
                    session,
                    request,
                    input,
                    limits,
                    authentication,
                    root.signature(),
                )
                .and_then(publish);
            }
            _ => {}
        }
    }
    let (operation, key, input, signature, capacity, multipart_parts) = match input {
        ExtensionInput::DigestMultipart {
            parts,
            output_capacity,
        } => (
            ExtensionOperation::DigestMultipart,
            None,
            &[][..],
            &[][..],
            output_capacity,
            Some(parts),
        ),
        ExtensionInput::EncryptMultipart {
            key,
            parts,
            output_capacity,
        } => (
            ExtensionOperation::EncryptMultipart,
            Some(key),
            &[][..],
            &[][..],
            output_capacity,
            Some(parts),
        ),
        ExtensionInput::DecryptMultipart {
            key,
            parts,
            output_capacity,
        } => (
            ExtensionOperation::DecryptMultipart,
            Some(key),
            &[][..],
            &[][..],
            output_capacity,
            Some(parts),
        ),

        ExtensionInput::VerifySignature {
            key,
            input,
            signature,
        } => (
            ExtensionOperation::VerifySignature,
            Some(key),
            input,
            signature,
            0,
            None,
        ),
        ExtensionInput::VerifySignatureMultipart {
            key,
            parts,
            signature,
        } => (
            ExtensionOperation::VerifySignatureMultipart,
            Some(key),
            &[][..],
            signature,
            0,
            Some(parts),
        ),
        ExtensionInput::SignRecover {
            key,
            input,
            output_capacity,
        } => (
            ExtensionOperation::SignRecover,
            Some(key),
            input,
            &[][..],
            output_capacity,
            None,
        ),
        ExtensionInput::VerifyRecover {
            key,
            signature,
            output_capacity,
        } => (
            ExtensionOperation::VerifyRecover,
            Some(key),
            signature,
            &[][..],
            output_capacity,
            None,
        ),
        ExtensionInput::SignMultipart {
            key,
            parts,
            output_capacity,
        } => (
            ExtensionOperation::SignMultipart,
            Some(key),
            &[][..],
            &[][..],
            output_capacity,
            Some(parts),
        ),
        ExtensionInput::VerifyMultipart {
            key,
            parts,
            signature,
        } => (
            ExtensionOperation::VerifyMultipart,
            Some(key),
            &[][..],
            signature,
            0,
            Some(parts),
        ),
        ExtensionInput::Encrypt {
            key,
            input,
            output_capacity,
        } => (
            ExtensionOperation::Encrypt,
            Some(key),
            input,
            &[][..],
            output_capacity,
            None,
        ),
        ExtensionInput::Decrypt {
            key,
            input,
            output_capacity,
        } => (
            ExtensionOperation::Decrypt,
            Some(key),
            input,
            &[][..],
            output_capacity,
            None,
        ),
        ExtensionInput::Sign {
            key,
            input,
            output_capacity,
        } => (
            ExtensionOperation::Sign,
            Some(key),
            input,
            &[][..],
            output_capacity,
            None,
        ),
        ExtensionInput::Verify {
            key,
            input,
            signature,
        } => (
            ExtensionOperation::Verify,
            Some(key),
            input,
            signature,
            0,
            None,
        ),
        ExtensionInput::Digest {
            input,
            output_capacity,
        } => (
            ExtensionOperation::Digest,
            None,
            input,
            &[][..],
            output_capacity,
            None,
        ),
    };
    request.contract.check(&session.inner, operation)?;
    if key.is_none() && authentication.is_some() {
        return Err(Error::Rejected(
            crate::RejectionReason::MechanismExtensions(crate::MechanismExtensionsRejection::DigestExtensionHasNoContextualKeyAuthentication),
        ));
    }
    let single = [input];
    let pieces = multipart_parts.unwrap_or(&single);
    limits.validate(session.inner.crypto_options.limits, pieces)?;
    bounds::ck_length(signature.len())?;
    let input_bytes = input::checked_length(
        pieces.iter().map(|piece| piece.len()),
        multipart_parts.is_some(),
    )?;
    bounds::ck_length(capacity)?;
    let allocation = capacity.checked_add(alignment - 1).ok_or(Error::Rejected(
        crate::RejectionReason::MechanismExtensions(
            crate::MechanismExtensionsRejection::NativeAlignedOutputAccounting,
        ),
    ))?;
    let diagnostic_bytes = Diagnostics::allocation_bytes();
    let mut required = OwnedGraph::recipe_bytes(request.parameters.recipe())?
        .checked_add(size_of::<Call>() - size_of::<OwnedGraph>())
        .and_then(|n| {
            n.checked_add(crate::native::frame::SessionFrame::<'_, Call>::allocation_bytes())
        })
        .and_then(|n| n.checked_add(input_bytes.checked_add(signature.len())?.checked_mul(2)?))
        .and_then(|n| n.checked_add(allocation))
        .and_then(|n| n.checked_add(diagnostic_bytes))
        .ok_or(Error::Rejected(
            crate::RejectionReason::MechanismExtensions(
                crate::MechanismExtensionsRejection::ExtensionCallAllocationAccounting,
            ),
        ))?;
    let progress = crate::session::AdmissionProgress::default();
    let mutates = request.contract.mutates_key();
    use crate::session::activity::AccessMode;
    let primary = if mutates {
        AccessMode::Write
    } else {
        AccessMode::Read
    };
    let epoch = session.snapshot.authentication_stamp();
    let mut authentication_plan =
        crate::session::ContextLoginPlan::at_epoch(session, authentication.as_ref(), epoch)?;
    // Keep candidate snapshots and authentication storage alive until access
    // has left if the route or an operand refuses before native dispatch.
    let (prepared, revocation, mut authentication_storage, diagnostics, state) = loop {
        let (((prepared, mut revocation, diagnostics), authentication_storage), state) = session
            .prepare_with_native_roles_prepaid_at_epoch(
                [
                    (key, primary),
                    (sources[0], AccessMode::Read),
                    (sources[1], AccessMode::Read),
                    (sources[2], AccessMode::Read),
                    (sources[3], AccessMode::Read),
                ],
                authentication.is_some(),
                epoch,
                &progress,
                |overhead| {
                    authentication_plan.prepare(session, overhead, |overhead| loop {
                        session.snapshot.check_authentication_unchanged(epoch)?;
                        let shape = if mutates {
                            key.map(|key| {
                                crate::managed::RevocationShape::discover(
                                    session,
                                    key.identity.resource(),
                                    epoch,
                                )
                            })
                            .transpose()?
                        } else {
                            None
                        };
                        let revocation_bytes = shape
                            .as_ref()
                            .map(crate::managed::RevocationShape::allocation_bytes)
                            .transpose()?
                            .unwrap_or(0);
                        let admitted = required
                            .checked_add(revocation_bytes)
                            .and_then(|n| n.checked_add(overhead))
                            .ok_or(Error::Rejected(crate::RejectionReason::MechanismExtensions(crate::MechanismExtensionsRejection::ExtensionCallAllocationAccounting)))?;
                        let mut prepaid = crate::advanced::reserve_preparation_at_epoch(
                            session, admitted, &progress, epoch,
                        )?;
                        let graph = super::super::graph::GraphStorage::allocate_input(request.parameters)?;
                        let revocation = shape.map(|shape| shape.allocate()).transpose()?;
                        let revocation_actual = revocation
                            .as_ref()
                            .map(|storage| storage.allocated_bytes())
                            .transpose()?
                            .unwrap_or(0);
                        let input =
                            input::Storage::allocate(input_bytes, multipart_parts.is_some())?;
                        let signature_storage =
                            crate::native::derivation::InputBytesStorage::allocate(
                                signature.len(),
                            )?;
                        let output = crate::symmetric::memory::UnboundBuffer::allocate(allocation)?;
                        let enclosing = (size_of::<Call>() - size_of::<OwnedGraph>())
                            .checked_add(
                                crate::native::frame::SessionFrame::<'_, Call>::allocation_bytes(),
                            )
                            .ok_or(Error::Rejected(crate::RejectionReason::MechanismExtensions(crate::MechanismExtensionsRejection::ExtensionCallAllocationAccounting)))?;
                        let signature_bytes = signature_storage.allocated_bytes()?;
                        let actual = graph
                            .allocated_bytes()?
                            .checked_add(input.allocated_bytes()?)
                            .and_then(|n| n.checked_add(signature_bytes))
                            .and_then(|n| n.checked_add(output.allocated()))
                            .and_then(|n| n.checked_add(enclosing))
                            .and_then(|n| n.checked_add(diagnostic_bytes))
                            .and_then(|n| n.checked_add(revocation_actual))
                            .and_then(|n| n.checked_add(overhead))
                            .ok_or(Error::Rejected(crate::RejectionReason::MechanismExtensions(crate::MechanismExtensionsRejection::ExtensionCallAllocationAccounting)))?;
                        if actual > admitted {
                            drop(revocation);
                            drop(output);
                            drop(signature_storage);
                            drop(input);
                            drop(graph);
                            drop(prepaid);
                            required = actual
                                .checked_sub(revocation_bytes)
                                .and_then(|n| n.checked_sub(overhead))
                                .ok_or(Error::Rejected(crate::RejectionReason::MechanismExtensions(crate::MechanismExtensionsRejection::ExtensionCallAllocationAccounting)))?;
                            continue;
                        }
                        prepaid.release(admitted - actual);
                        let diagnostics =
                            Diagnostics::prepare(&mut prepaid)?;
                        let revocation = revocation
                            .map(|storage| storage.bind(&mut prepaid))
                            .transpose()?;
                        let mut output = output.bind(&mut prepaid)?;
                        let output_offset = output.as_mut().as_mut_ptr().align_offset(alignment);
                        if output_offset > alignment - 1 {
                            return Err(Error::Rejected(crate::RejectionReason::MechanismExtensions(crate::MechanismExtensionsRejection::NativeOutputAlignmentUnavailable)));
                        }
                        let prepared = Call {
                            mechanism: CK_MECHANISM {
                                mechanism: request.contract.mechanism,
                                pParameter: std::ptr::null_mut(),
                                ulParameterLen: 0,
                            },
                            parameters: graph.bind(&mut prepaid)?,
                            input: input.bind_parts(pieces, &mut prepaid)?,
                            signature: signature_storage.bind(signature, &mut prepaid)?,
                            output,
                            output_offset,
                            produced: 0,
                            length: bounds::ck_length(capacity)?,
                            _credit: prepaid.split(enclosing)?,
                        };
                        return Ok(((prepared, revocation, diagnostics), prepaid));
                    })
                },
            )?;
        let revocation = match revocation.as_mut() {
            Some(snapshot) => match snapshot.bind(&state)? {
                Some(targets) => Some(targets),
                None => {
                    // Registry growth: release the entire unpublished candidate
                    // and possession before retrying; no native call was made.
                    drop(state);
                    drop(prepared);
                    drop(authentication_storage);
                    drop(diagnostics);
                    continue;
                }
            },
            None => None,
        };
        break (
            prepared,
            revocation,
            authentication_storage,
            diagnostics,
            state,
        );
    };
    session.entry(&state)?;
    let route = Route::new(&state, operation, multipart_parts.is_some())?;
    let (init_name, function) = route.names();
    let handle = if let Some(key) = key {
        session.native_object_handle(&state, key)?
    } else {
        CK_INVALID_HANDLE
    };
    for source in sources.iter().flatten() {
        session.native_object_handle(&state, source)?;
    }
    prepared_authentication = PreparedContextLogin::from_prepared(
        session,
        &state,
        &mut authentication,
        &mut authentication_storage,
    )?;
    // The public invocation owns the credit even after these leaves are moved
    // into an error and this private helper has returned.
    let diagnostics = root.native(diagnostics);
    let diagnostic = &diagnostics.completion;
    let mut frame = NativeFrame::session(state.clone(), prepared)?;
    {
        let (returned, body) = frame.session_parts();
        let access = &body.access;
        let data = &mut *body.data;
        let (pointer, length) = data.parameters.projection();
        data.mechanism.pParameter = pointer;
        data.mechanism.ulParameterLen = length;
        let expected = (data.mechanism.mechanism, pointer, length);
        let single_input = data.input.single();
        if single_input.is_some() != route.update().is_none() {
            return Err(Error::Rejected(
                crate::RejectionReason::MechanismExtensions(
                    crate::MechanismExtensionsRejection::ExtensionInputRouteChanged,
                ),
            ));
        }
        access.native.record(init_name)?;
        // Invalidate observations before dispatch, including unwind and any
        // refused Init. A stateful native key is never rolled back locally.
        if let Some(revocation) = revocation {
            drop(revocation.arm());
        }
        let sequence = Sequence::for_frame_prepared(access, session, returned, diagnostic);
        // SAFETY: exact bound route, owned aligned graph, retained key activity.
        let rv = returned.observe(
            unsafe { route.init(session.entry.handle, data, handle) },
            &access.native,
        );
        use crate::native_return::protocol::SequencePhase;
        use crate::native_return::sequence::OutputRequest;
        sequence
            .inspect_return(rv, init_name, SequencePhase::Initialize, || {
                if !data.unchanged(expected) {
                    return Err(Error::Rejected(crate::RejectionReason::MechanismExtensions(
                        crate::MechanismExtensionsRejection::ExtensionInitializationInputMutation,
                    )));
                }
                Ok(())
            })?
            .check(mutates)
            .map_err(|e| effect(e, mutates))?;
        if let Some(mut authentication) = prepared_authentication.take() {
            let result = authentication.perform(session);
            diagnostics.authentication = Some(authentication.into_diagnostics());
            if let Err(cause) = result {
                returned.recoverable();
                return Err(cause);
            }
            if !data.unchanged(expected) {
                return Err(
                    sequence.invalid_output(crate::RejectionReason::MechanismExtensions(crate::MechanismExtensionsRejection::ExtensionInputMutationDuringAuthentication))
                );
            }
        }
        if let Some((update, name)) = route.update() {
            let mut offset = 0;
            for piece in pieces {
                data.length = bounds::ck_length(capacity - data.produced)?;
                sequence.record_next(name)?;
                // SAFETY: each checked chunk is a span of the complete copied
                // input allocation. The frame retains all chunks on uncertainty.
                let rv = returned.observe(
                    unsafe {
                        update.run(session.entry.handle, data, offset, piece.len() as CK_ULONG)
                    },
                    &access.native,
                );
                sequence.inspect_return(
                    rv, name, SequencePhase::Continue(OutputRequest::Unspecified), || {
                        if !data.unchanged(expected) {
                            return Err(Error::Rejected(crate::RejectionReason::MechanismExtensions(
                                crate::MechanismExtensionsRejection::ExtensionUpdateInputMutation,
                            )));
                        }
                        if rv == CKR_OK && matches!(update, Update::Output(_)) {
                            bounds::final_length(data.length, capacity - data.produced)?;
                        }
                        Ok(())
                    },
                )?.check(mutates)?;
                if matches!(update, Update::Output(_)) {
                    let produced = match bounds::final_length(data.length, capacity - data.produced)
                    {
                        Ok(length) => length,
                        Err(cause) => {
                            returned.quarantine(&access.native);
                            return diagnostic.finish(function, Err(cause));
                        }
                    };
                    data.produced += produced;
                }
                offset += piece.len();
            }
        }
        data.length = bounds::ck_length(capacity - data.produced)?;
        sequence.record_next(function)?;
        // SAFETY: same stable graph and frame, no replay or output size probe.
        let rv = returned.observe(
            unsafe { route.run(session.entry.handle, data, single_input) },
            &access.native,
        );
        sequence
            .inspect_return(
                rv,
                function,
                SequencePhase::Continue(OutputRequest::Buffer),
                || {
                    if !data.unchanged(expected) {
                        return Err(Error::Rejected(
                            crate::RejectionReason::MechanismExtensions(
                                crate::MechanismExtensionsRejection::ExtensionNativeInputMutation,
                            ),
                        ));
                    }
                    if rv == CKR_OK {
                        bounds::final_length(data.length, capacity - data.produced)?;
                        // Parameter output extents are part of the terminal
                        // memory boundary, before any completion receipt.
                        data.parameters.validate_output_bounds()?;
                    }
                    Ok(())
                },
            )?
            .check(mutates)?;
        if let Err(cause) = bounds::final_length(data.length, capacity - data.produced) {
            returned.quarantine(&access.native);
            return diagnostic.finish(function, Err(cause));
        }
        let length = data.produced + data.length as usize;
        data.output
            .as_mut()
            .copy_within(data.output_offset..data.output_offset + length, 0);
        data.output.set_length(length)?;
        if let Err(cause) = data.parameters.finish() {
            returned.quarantine(&access.native);
            return diagnostic.finish(function, Err(cause));
        }
    }
    let mut completed = match frame.into_inner() {
        Ok(body) => body.data.into_inner(),
        Err(cause) => return diagnostic.finish(function, Err(cause)),
    };
    let native_output_origin =
        completed.output.as_mut().as_mut_ptr() as usize + completed.output_offset;
    diagnostic.finish(
        function,
        session
            .public_result(
                &state,
                Ok(ExtensionResult {
                    bytes: completed.output,
                    native_output_origin,
                    parameters: completed.parameters,
                    provenance: request.contract.provenance(),
                }),
            )
            .and_then(publish),
    )
}
