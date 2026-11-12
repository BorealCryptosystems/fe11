// SPDX-License-Identifier: Apache-2.0
//! Prepare closed or incremental digest input and its operation storage.
//! The selected digest representation remains explicit through installation.

use super::*;

// Both facades install exactly the same frame, reservation and native driver.
pub(in crate::advanced) fn start(
    session: &Session,
    parts: &[&[u8]],
    limits: crate::InputLimits,
    selection: DigestSelection,
    validation_requested: bool,
    capture_validation: bool,
    remaining: &mut usize,
    retired_owner: &mut Option<std::sync::Arc<crate::advanced::ledger::OperationCell>>,
) -> Result<OperationTicket> {
    start_with_oid(
        session,
        parts,
        limits,
        selection,
        None,
        validation_requested,
        capture_validation,
        remaining,
        retired_owner,
    )
}

pub(in crate::advanced) fn start_with_oid(
    session: &Session,
    parts: &[&[u8]],
    limits: crate::InputLimits,
    selection: DigestSelection,
    oid: Option<&[u8]>,
    validation_requested: bool,
    capture_validation: bool,
    remaining: &mut usize,
    retired_owner: &mut Option<std::sync::Arc<crate::advanced::ledger::OperationCell>>,
) -> Result<OperationTicket> {
    start_with_input(
        session,
        parts,
        limits,
        selection,
        oid,
        validation_requested,
        capture_validation,
        remaining,
        super::super::input::InputState::closed(),
        None,
        retired_owner,
    )
}

pub(in crate::advanced) fn start_open(
    session: &Session,
    parts: &[&[u8]],
    limits: crate::InputLimits,
    selection: DigestSelection,
    validation_requested: bool,
    capture_validation: bool,
    remaining: &mut usize,
    retired_owner: &mut Option<std::sync::Arc<crate::advanced::ledger::OperationCell>>,
) -> Result<OperationTicket> {
    start_open_with_oid(
        session,
        parts,
        limits,
        selection,
        None,
        validation_requested,
        capture_validation,
        remaining,
        retired_owner,
    )
}

pub(in crate::advanced) fn start_open_with_oid(
    session: &Session,
    parts: &[&[u8]],
    limits: crate::InputLimits,
    selection: DigestSelection,
    oid: Option<&[u8]>,
    validation_requested: bool,
    capture_validation: bool,
    remaining: &mut usize,
    retired_owner: &mut Option<std::sync::Arc<crate::advanced::ledger::OperationCell>>,
) -> Result<OperationTicket> {
    start_with_input(
        session,
        parts,
        limits,
        selection,
        oid,
        validation_requested,
        capture_validation,
        remaining,
        super::super::input::InputState::open(),
        None,
        retired_owner,
    )
}

pub(super) fn start_with_input(
    session: &Session,
    parts: &[&[u8]],
    limits: crate::InputLimits,
    selection: DigestSelection,
    oid: Option<&[u8]>,
    validation_requested: bool,
    capture_validation: bool,
    remaining: &mut usize,
    input: super::super::input::InputState,
    extension: Option<crate::mechanism_extension::graph::recipe::Request<'_>>,
    retired_owner: &mut Option<std::sync::Arc<crate::advanced::ledger::OperationCell>>,
) -> Result<OperationTicket> {
    start_retained(
        session,
        parts,
        limits,
        selection,
        oid,
        validation_requested,
        capture_validation,
        remaining,
        input,
        extension,
        false,
        retired_owner,
    )
    .map(|(ticket, _, _)| ticket)
}

pub(super) fn start_retained(
    session: &Session,
    parts: &[&[u8]],
    limits: crate::InputLimits,
    selection: DigestSelection,
    oid: Option<&[u8]>,
    validation_requested: bool,
    capture_validation: bool,
    remaining: &mut usize,
    input: super::super::input::InputState,
    extension: Option<crate::mechanism_extension::graph::recipe::Request<'_>>,
    facade: bool,
    retired_owner: &mut Option<std::sync::Arc<crate::advanced::ledger::OperationCell>>,
) -> Result<(
    OperationTicket,
    std::sync::Arc<crate::advanced::ledger::OperationCell>,
    Option<crate::error::PreparedFailurePair>,
)> {
    // A terminal Init refusal can remove the registry entry. Keep its complete
    // installed owner until session/key possession has unwound on that return.
    let installed: std::sync::Arc<crate::advanced::ledger::OperationCell>;
    let _returned: super::super::fragment_retirement::ReturnedOperands;
    limits.validate(session.inner.crypto_options.limits, parts)?;
    match (selection, extension.as_ref()) {
        (
            DigestSelection::Extension {
                mechanism,
                capacity,
                route,
            },
            Some(request),
        ) => {
            let native = match route {
                MessageRoute::Single => crate::ExtensionOperation::Digest,
                MessageRoute::Multipart => crate::ExtensionOperation::DigestMultipart,
            };
            request.contract.check(&session.inner, native)?;
            bounds::ck_length(capacity)?;
            if request.contract.native_mechanism() != mechanism || oid.is_some() {
                return Err(Error::Rejected(crate::RejectionReason::DigestContinuation(
                    crate::DigestContinuationRejection::DigestExtensionSelection,
                )));
            }
        }
        (DigestSelection::Extension { .. }, None) | (_, Some(_)) => {
            return Err(Error::Rejected(crate::RejectionReason::DigestContinuation(
                crate::DigestContinuationRejection::DigestExtensionGraphSelection,
            )))
        }
        _ => {}
    }
    // Reserve and allocate before holding the native session guard. The same
    // frame is used by synchronous, cooperative and restored operations.
    let check_functions = |state: &crate::module::State| -> Result<()> {
        // The caller selects the algorithm. Discovery remains descriptive:
        // C_DigestInit decides native support, without a probe or fallback.
        if state.native.table.C_DigestInit.is_none()
            || match selection.route() {
                MessageRoute::Single => state.native.table.C_Digest.is_none(),
                MessageRoute::Multipart => {
                    state.native.table.C_DigestUpdate.is_none()
                        || state.native.table.C_DigestFinal.is_none()
                }
            }
        {
            return Err(Error::Rejected(crate::RejectionReason::DigestContinuation(
                crate::DigestContinuationRejection::DigestFunctionsUnavailable,
            )));
        }
        Ok(())
    };
    let progress = session.advanced_preflight(&check_functions)?;
    let capture = capture_validation || validation_requested;
    let validation_bytes = if capture {
        validation::Capture::allocation_bytes(1)?
    } else {
        0
    };
    let extension_bytes = extension
        .as_ref()
        .map(|request| {
            crate::mechanism_extension::OwnedGraph::recipe_bytes(request.parameters.recipe())
        })
        .transpose()?
        .unwrap_or(0);
    let diagnostic_bytes = if facade {
        crate::error::PreparedFailurePair::preparation_bytes()
    } else {
        0
    };
    let temporary_bytes = snapshot::Storage::temporary_bytes(parts.len())?;
    let mut total = DigestFrame::allocation_bytes_with_oid(parts, selection, oid)?
        .checked_add(validation_bytes)
        .and_then(|n| n.checked_add(extension_bytes))
        .and_then(|n| n.checked_add(crate::advanced::preparation::Shell::allocation_bytes()))
        .and_then(|n| n.checked_add(temporary_bytes))
        .and_then(|n| n.checked_add(diagnostic_bytes))
        .ok_or(Error::Rejected(crate::RejectionReason::DigestContinuation(
            crate::DigestContinuationRejection::DigestOperationStorageSize,
        )))?;
    let possession = super::super::keys::KeyReaders::<0>::prepare(session, [])?;
    let ((diagnostic, frame, cancel, validation), s, _readers) =
        possession.prepare_with(session, &progress, || loop {
            let mut prepaid =
                crate::advanced::preparation::reserve_new_with_progress(session, total, &progress)?;
            let graph = extension
                .as_ref()
                .map(|request| {
                    crate::mechanism_extension::GraphStorage::allocate_input(request.parameters)
                })
                .transpose()?;
            let graph_actual = graph
                .as_ref()
                .map(|graph| graph.allocated_bytes())
                .transpose()?
                .unwrap_or(0);
            let frame = snapshot::Storage::allocate_lengths(
                selection,
                parts.iter().map(|part| part.len()),
                oid.map(<[u8]>::len),
            )?;
            let validation = capture
                .then(|| validation::CaptureStorage::allocate(1))
                .transpose()?;
            let validation_actual = validation
                .as_ref()
                .map(validation::CaptureStorage::allocated_bytes)
                .transpose()?
                .unwrap_or(0);
            let actual = frame
                .allocated_bytes()?
                .checked_add(validation_actual)
                .and_then(|n| n.checked_add(diagnostic_bytes))
                .and_then(|n| n.checked_add(graph_actual))
                .and_then(|n| {
                    n.checked_add(crate::advanced::preparation::Shell::allocation_bytes())
                })
                .ok_or(Error::Rejected(crate::RejectionReason::DigestContinuation(
                    crate::DigestContinuationRejection::DigestOperationStorageSize,
                )))?;
            if actual > total {
                drop(graph);
                drop(validation);
                drop(frame);
                drop(prepaid);
                total = actual;
                continue;
            }
            prepaid.release(total - actual);
            let diagnostic = if facade {
                prepaid.observation_budget()?;
                Some(crate::error::PreparedFailurePair::prepare(&mut prepaid)?)
            } else {
                None
            };
            let mut frame = frame.bind(&mut prepaid)?;
            if let Some(graph) = graph {
                let request = extension.as_ref().expect("prepared extension graph");
                let mut parameters =
                    extension::Parameters::new(request.contract.clone(), graph.bind(&mut prepaid)?);
                parameters.attach(&mut frame.mechanism);
                frame.extension = Some(parameters);
            }
            let validation = validation
                .map(|storage| storage.bind(&mut prepaid))
                .transpose()?;
            let cancel = crate::advanced::preparation::Shell::from_prepaid(&mut prepaid)?;
            for (destination, source) in frame.parts.iter_mut().zip(parts) {
                destination.as_mut().copy_from_slice(source);
            }
            if let (Some(destination), Some(source)) = (frame.oid.as_mut(), oid) {
                destination.fill_before_dispatch(source)?;
            }
            return Ok((diagnostic, frame, cancel, validation));
        })?;
    check_functions(&s)?;
    let (lease, cancel) = cancel.bind(&s.lease_admission()?)?;
    let (id, owner) = s.operations.install(
        &session.entry,
        Operation::new(
            OperationBody::Digest(DigestOperation {
                observer: crate::advanced::digest::Observer::Ticket,
                frame,
                step: Step::Init,
                input,
                activity: NativeActivity::Inactive,
                validation_requested,
            }),
            lease,
            cancel,
        )
        .with_validation(validation),
    )?;
    let ticket = OperationTicket {
        owner: session.inner.clone(),
        uid: session.uid,
        id,
        validation_report: None,
        state_provenance: None,
    };
    installed = owner;
    *retired_owner = Some(installed.clone());
    let mut operation = installed.lock().map_err(|_| Error::Poisoned)?;
    let driven = drive(&s, &session.entry, &mut operation, false, remaining);
    let OperationBody::Digest(body) = &mut operation.body else {
        unreachable!("installed digest owner")
    };
    _returned = body.take_returned_operands();
    if let Err(error) = driven {
        let (error, released) = operation.retire_terminal_error(&s, &session.entry, error);
        if !released {
            if let OperationBody::Digest(body) = &mut operation.body {
                body.observer = Observer::Session;
            }
        }
        return Err(error);
    }
    drop(operation);
    Ok((ticket, installed, diagnostic))
}
