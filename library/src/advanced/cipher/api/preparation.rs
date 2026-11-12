// SPDX-License-Identifier: Apache-2.0
//! Prepare classic cipher input, storage and keys before installing an operation.
//! Output resizing retains the existing sequence and its confirmed prefix.

use super::*;

pub(super) fn start(
    session: &Session,
    key: &SymmetricKey,
    parameters: AesCipherParameters,
    direction: Direction,
    route: MessageRoute,
    parts: &[&[u8]],
    limits: InputLimits,
    output: CipherOutputPlan,
    validation: bool,
    remaining: &mut usize,
    retirement: &mut crate::advanced::PollDiagnostics,
) -> Result<OperationTicket> {
    if !matches!(
        key.algorithm(),
        SymmetricAlgorithm::Aes128 | SymmetricAlgorithm::Aes192 | SymmetricAlgorithm::Aes256
    ) {
        return Err(Error::Rejected(crate::RejectionReason::CipherContinuation(
            crate::CipherContinuationRejection::AesOperationRequiresAnAesKey,
        )));
    }
    start_common(
        session,
        CipherKey::Profiled(key),
        CipherParameters::from(parameters),
        direction,
        route,
        parts,
        limits,
        output,
        validation,
        remaining,
        retirement,
    )
}

pub(in crate::advanced::cipher) fn start_common<'a>(
    session: &Session,
    key: CipherKey<'_>,
    parameters: impl Into<Selection<'a>>,
    direction: Direction,
    route: MessageRoute,
    parts: &[&[u8]],
    limits: InputLimits,
    output: CipherOutputPlan,
    capture_validation: bool,
    remaining: &mut usize,
    retirement: &mut crate::advanced::PollDiagnostics,
) -> Result<OperationTicket> {
    start_common_with_input(
        session,
        key,
        parameters,
        direction,
        route,
        parts,
        limits,
        output,
        capture_validation,
        remaining,
        crate::advanced::input::InputState::closed(),
        None,
        retirement,
    )
}

pub(in crate::advanced::cipher) fn start_common_with_input<'a>(
    session: &Session,
    key: CipherKey<'_>,
    parameters: impl Into<Selection<'a>>,
    direction: Direction,
    route: MessageRoute,
    parts: &[&[u8]],
    limits: InputLimits,
    output: CipherOutputPlan,
    capture_validation: bool,
    remaining: &mut usize,
    input: crate::advanced::input::InputState,
    ccm_data_length: Option<u64>,
    retirement: &mut crate::advanced::PollDiagnostics,
) -> Result<OperationTicket> {
    start_retained(
        session,
        key,
        parameters,
        direction,
        route,
        parts,
        limits,
        output,
        capture_validation,
        remaining,
        input,
        ccm_data_length,
        false,
        retirement,
    )
    .map(|(ticket, _, _)| ticket)
}

pub(in crate::advanced::cipher) fn start_retained<'a>(
    session: &Session,
    key: CipherKey<'_>,
    parameters: impl Into<Selection<'a>>,
    direction: Direction,
    route: MessageRoute,
    parts: &[&[u8]],
    limits: InputLimits,
    output: CipherOutputPlan,
    capture_validation: bool,
    remaining: &mut usize,
    input: crate::advanced::input::InputState,
    ccm_data_length: Option<u64>,
    facade: bool,
    retirement: &mut crate::advanced::PollDiagnostics,
) -> Result<(
    OperationTicket,
    Arc<crate::advanced::ledger::OperationCell>,
    Option<crate::error::PreparedFailurePair>,
)> {
    let parameters = parameters.into();
    if let Selection::Extension(source) = parameters {
        source.check_start(session, direction.decrypts(), route)?;
    }
    if matches!(parameters, Selection::Aead(_, _))
        && matches!(key, CipherKey::Native(CipherKeyReference::NoKey))
    {
        return Err(Error::Rejected(crate::RejectionReason::CipherContinuation(
            crate::CipherContinuationRejection::AeadRequiresASecretKey,
        )));
    }
    if session.entry.mode != AdvancedSessionMode::Synchronous {
        return Err(Error::Rejected(crate::RejectionReason::CipherContinuation(
            crate::CipherContinuationRejection::NativeCipherAsynchronousModeUnavailable,
        )));
    }
    match parameters {
        Selection::Plain(_) | Selection::Extension(_) => {
            limits.validate(session.inner.crypto_options.limits, parts)?;
        }
        Selection::Aead(p, _) => {
            crate::symmetric::input_size(
                session.inner.crypto_options.limits,
                limits,
                parts,
                p.aad(),
                if direction.decrypts() {
                    p.tag_bits()?.div_ceil(8) as usize
                } else {
                    0
                },
            )?;
        }
    }
    let check_functions = |state: &crate::module::State| -> Result<()> {
        let table = &state.native.table;
        if !matches!(parameters, Selection::Extension(_))
            && parameters.mechanism_number() == CKM_AES_CCM as u64
            && !matches!(
                (table.version.major, table.version.minor),
                (2, 40..) | (3, _)
            )
        {
            return Err(Error::Unsupported(
                crate::UnsupportedReason::CipherContinuation(crate::CipherContinuationUnsupported::CcmParameterLayoutUnavailableInSelectedEdition),
            ));
        }
        let available = match (direction, route) {
            (Direction::Encrypt, MessageRoute::Single) => {
                table.C_EncryptInit.is_some() && table.C_Encrypt.is_some()
            }
            (Direction::Decrypt, MessageRoute::Single) => {
                table.C_DecryptInit.is_some() && table.C_Decrypt.is_some()
            }
            (Direction::Encrypt, MessageRoute::Multipart) => {
                table.C_EncryptInit.is_some()
                    && table.C_EncryptUpdate.is_some()
                    && table.C_EncryptFinal.is_some()
            }
            (Direction::Decrypt, MessageRoute::Multipart) => {
                table.C_DecryptInit.is_some()
                    && table.C_DecryptUpdate.is_some()
                    && table.C_DecryptFinal.is_some()
            }
        };
        if !available {
            return Err(Error::Rejected(crate::RejectionReason::CipherContinuation(
                crate::CipherContinuationRejection::SelectedCipherFunctionsUnavailable,
            )));
        }
        Ok(())
    };
    let authentication = session.snapshot.authentication_stamp();
    let progress = session.advanced_preflight_at_epoch(authentication, &check_functions)?;
    let request = if input.incremental {
        if route != MessageRoute::Multipart || !parts.is_empty() {
            return Err(Error::Rejected(crate::RejectionReason::CipherContinuation(
                crate::CipherContinuationRejection::IncrementalCipherStartsWithoutQueuedInput,
            )));
        }
        snapshot::Request::incremental(direction, parameters, output, ccm_data_length)?
    } else {
        snapshot::Request::new(direction, route, parameters, parts, output)?
    };
    let validation_bytes = if capture_validation {
        validation::Capture::allocation_bytes(1)?
    } else {
        0
    };
    let diagnostic_bytes = if facade {
        crate::error::PreparedFailurePair::preparation_bytes()
    } else {
        0
    };
    let mut bytes = request
        .allocation_bytes()
        .checked_add(crate::advanced::preparation::Shell::allocation_bytes())
        .and_then(|n| n.checked_add(validation_bytes))
        .and_then(|n| n.checked_add(diagnostic_bytes))
        .ok_or(Error::Rejected(crate::RejectionReason::CipherContinuation(
            crate::CipherContinuationRejection::CipherOperationStorageSize,
        )))?;
    let mutates = matches!(parameters, Selection::Extension(source) if source.metadata().mutates_key)
        && super::super::key_preparation::reference(&key).is_some();
    loop {
        // Retiring the registry on a terminal Init refusal must not destroy
        // this entire owner until session/key possession has unwound.
        let held: Arc<crate::advanced::ledger::OperationCell>;
        let _returned: super::super::ReturnedOperands;
        let ((diagnostic, frame, cancel, validation, mut revocation), access, grant) =
            super::super::key_preparation::prepare_with(
                session,
                &key,
                mutates,
                &progress,
                authentication,
                |overhead| {
                    loop {
                        session
                            .snapshot
                            .check_authentication_unchanged(authentication)?;
                        // One admission covers every unpublished allocation. Waiting never
                        // retains a private frame that could consume its own missing credit.
                        let shape = if mutates {
                            Some(crate::managed::RevocationShape::discover(
                                session,
                                super::super::key_preparation::reference(&key)
                                    .unwrap()
                                    .identity
                                    .resource(),
                                authentication,
                            )?)
                        } else {
                            None
                        };
                        let revocation_bytes = shape
                            .as_ref()
                            .map(crate::managed::RevocationShape::allocation_bytes)
                            .transpose()?
                            .unwrap_or(0);
                        let admitted = bytes
                            .checked_add(revocation_bytes)
                            .and_then(|n| n.checked_add(overhead))
                            .ok_or(Error::Rejected(crate::RejectionReason::CipherContinuation(
                                crate::CipherContinuationRejection::CipherRevocationStorageSize,
                            )))?;
                        let mut prepaid = crate::advanced::preparation::reserve_new_at_epoch(
                            session,
                            admitted,
                            &progress,
                            authentication,
                        )?;
                        let revocation = shape.map(|shape| shape.allocate()).transpose()?;
                        let revocation_actual = revocation
                            .as_ref()
                            .map(|storage| storage.allocated_bytes())
                            .transpose()?
                            .unwrap_or(0);
                        // This allocator can bind private credits. Attribute
                        // the whole candidate before its first split, so later
                        // authentication cannot wait on this facade's own bytes.
                        if facade {
                            prepaid.observation_budget()?;
                        }
                        let storage = request.allocate(parts, &mut prepaid)?;
                        let validation = capture_validation
                            .then(|| validation::CaptureStorage::allocate(1))
                            .transpose()?;
                        let validation_actual = validation
                            .as_ref()
                            .map(validation::CaptureStorage::allocated_bytes)
                            .transpose()?
                            .unwrap_or(0);
                        let actual = storage
                            .allocated_bytes()?
                            .checked_add(validation_actual)
                            .and_then(|n| n.checked_add(diagnostic_bytes))
                            .and_then(|n| n.checked_add(revocation_actual))
                            .and_then(|n| {
                                n.checked_add(
                                    crate::advanced::preparation::Shell::allocation_bytes(),
                                )
                            })
                            .and_then(|n| n.checked_add(overhead))
                            .ok_or(Error::Rejected(crate::RejectionReason::CipherContinuation(
                                crate::CipherContinuationRejection::CipherOperationStorageSize,
                            )))?;
                        if actual > admitted {
                            drop(revocation);
                            drop(validation);
                            drop(storage);
                            drop(prepaid);
                            bytes = actual
                                .checked_sub(revocation_bytes)
                                .and_then(|n| n.checked_sub(overhead))
                                .ok_or(Error::Rejected(crate::RejectionReason::CipherContinuation(crate::CipherContinuationRejection::CipherRevocationStorageSize)))?;
                            continue;
                        }
                        prepaid.release(admitted - actual);
                        let diagnostic = if facade {
                            Some(crate::error::PreparedFailurePair::prepare(&mut prepaid)?)
                        } else {
                            None
                        };
                        let revocation = revocation
                            .map(|storage| storage.bind(&mut prepaid))
                            .transpose()?;
                        let frame = storage
                            .bind(&mut prepaid)?
                            .fill_request(parameters, parts)?;
                        let validation = validation
                            .map(|storage| storage.bind(&mut prepaid))
                            .transpose()?;
                        let cancel =
                            crate::advanced::preparation::Shell::from_prepaid(&mut prepaid)?;
                        return Ok(((diagnostic, frame, cancel, validation, revocation), prepaid));
                    }
                },
            )?;
        let mut bound_revocation;
        let mut pending_lease = None;
        let lease;
        let token;
        let cancellation;
        let mut candidate;
        let mut retained_shell;
        let mut grant = grant;
        let access = access;
        session
            .snapshot
            .check_authentication_unchanged(authentication)?;
        check_functions(&access)?;
        bound_revocation = match revocation.as_mut() {
            Some(prepared) => match prepared.bind(&access)? {
                Some(targets) => Some(targets),
                None => {
                    // Registry growth: drop possession and the unpublished frame
                    // before reserving again. No native initialization happened.
                    drop(access);
                    drop(grant);
                    continue;
                }
            },
            None => None,
        };
        retained_shell = Some(cancel);
        (token, cancellation) = crate::advanced::preparation::Shell::bind_retained(
            &mut retained_shell,
            &access.lease_admission()?,
        )?;
        lease = grant.bind(
            session,
            key,
            CK_MECHANISM_TYPE::try_from(parameters.mechanism_number()).map_err(|_| {
                Error::Rejected(crate::RejectionReason::CipherContinuation(
                    crate::CipherContinuationRejection::CipherMechanismWidth,
                ))
            })?,
            &mut bound_revocation,
            &mut pending_lease,
        )?;
        let mut body = CipherOperation::new(lease, frame, output);
        body.input = input;
        if input.incremental && parts.is_empty() {
            body.frame.inputs.clear();
        }
        candidate = Some(
            Operation::new(OperationBody::Cipher(body), token, cancellation)
                .with_validation(validation),
        );
        let (id, installed) = access.operations.install_with_retained(
            &session.entry,
            &mut candidate,
            &mut None,
            |_| {},
        )?;
        let ticket = OperationTicket {
            owner: session.inner.clone(),
            uid: session.uid,
            id,
            validation_report: None,
            state_provenance: None,
        };
        // The invocation keeps the metadata credit even if the first native
        // step retires this owner before its error reaches the public facade.
        retirement.retired_owner = Some(installed.clone());
        held = installed;
        let mut operation = held.lock().map_err(|_| Error::Poisoned)?;
        let driven = drive(&access, &session.entry, &mut operation, false, remaining);
        let OperationBody::Cipher(body) = &mut operation.body else {
            unreachable!("installed classic cipher owner")
        };
        _returned = body.take_returned_operands();
        if let Err(error) = driven {
            let (error, released) = operation.retire_terminal_error(&access, &session.entry, error);
            if !released {
                if let OperationBody::Cipher(body) = &mut operation.body {
                    body.observer = super::super::OutputObserver::Session;
                }
            }
            return Err(error);
        }
        drop(operation);
        return Ok((ticket, held, diagnostic));
    }
}

pub(super) fn resize(session: &Session, ticket: &OperationTicket, capacity: usize) -> Result<()> {
    crate::advanced::output_preparation::replace(
        session,
        ticket,
        capacity,
        crate::advanced::output_preparation::Family::Cipher,
    )
}
