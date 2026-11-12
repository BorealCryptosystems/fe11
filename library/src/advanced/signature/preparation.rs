// SPDX-License-Identifier: Apache-2.0
//! Prepare the complete signature frame before session/key possession.
use super::{InputState, Kind, NativeActivity, SignatureOperation, SignatureOutputPlan, Stage};
use crate::advanced::{drive, preparation::Shell, Operation, OperationBody, OperationTicket};
use crate::mechanism_extension::graph::{recipe, GraphStorage, OwnedGraph};
use crate::native::derivation::InputBytesStorage;
use crate::session::activity::AccessMode;
use crate::symmetric::memory::UnboundBuffer;
use crate::{
    bounds, AdvancedSessionMode, Error, InputLimits, MessageRoute, NativeObjectRef, Result, Session,
};
use fe11_sys::{CK_MECHANISM, CK_ULONG};
use std::mem::size_of;

pub(super) fn metadata_bytes() -> usize {
    size_of::<SignatureOperation>() - size_of::<OwnedGraph>()
        + size_of::<CK_MECHANISM>()
        + size_of::<CK_ULONG>()
        + crate::error::CompletionStorage::allocation_bytes()
}

/// Keep scalar allocations and their charge together across role-admission
/// retries. An enclosing candidate may be discarded before it is destructured.
/// Field order also protects errors after that candidate becomes local state.
struct PreparedScalars {
    mechanism: Box<CK_MECHANISM>,
    length: Box<CK_ULONG>,
    completion_diagnostic: crate::error::CompletionStorage,
    _credit: crate::symmetric::memory::Credit,
}

/// Complete-input calls start closed; an explicit Init starts open, including
/// a deferred monobloc call. VerifySignature needs its signature during Init.
pub(super) fn start(
    session: &Session,
    key: &NativeObjectRef,
    request: recipe::Request<'_>,
    kind: Kind,
    route: MessageRoute,
    initial: Option<&[u8]>,
    signature: Option<&[u8]>,
    limits: InputLimits,
    plan: SignatureOutputPlan,
    maximum_output: usize,
    capture_validation: bool,
    remaining: &mut usize,
    retirement: &mut crate::advanced::PollDiagnostics,
) -> Result<OperationTicket> {
    start_retained(
        session,
        key,
        request,
        kind,
        route,
        initial,
        signature,
        limits,
        plan,
        maximum_output,
        capture_validation,
        super::batch::DiagnosticPlan::None,
        remaining,
        retirement,
    )
    .map(|(ticket, _owner, _diagnostics)| ticket)
}

/// The complete-input facade keeps this exact ledger owner until it either
/// publishes a result or returns its continuation to the session. Parking must
/// not reacquire resource admission after that same admission has timed out.
pub(super) fn start_retained(
    session: &Session,
    key: &NativeObjectRef,
    request: recipe::Request<'_>,
    kind: Kind,
    route: MessageRoute,
    initial: Option<&[u8]>,
    signature: Option<&[u8]>,
    limits: InputLimits,
    plan: SignatureOutputPlan,
    maximum_output: usize,
    capture_validation: bool,
    diagnostic_plan: super::batch::DiagnosticPlan,
    remaining: &mut usize,
    retirement: &mut crate::advanced::PollDiagnostics,
) -> Result<(
    OperationTicket,
    std::sync::Arc<crate::advanced::ledger::OperationCell>,
    Option<super::batch::Diagnostics>,
)> {
    if session.entry.mode != AdvancedSessionMode::Synchronous {
        return Err(Error::Rejected(
            crate::RejectionReason::AsynchronousExecution(
                crate::AsynchronousExecutionRejection::SignatureAsynchronousModeUnavailable,
            ),
        ));
    }
    if route == MessageRoute::Multipart && initial.is_some()
        || kind == Kind::VerifySignature && signature.is_none()
        || kind == Kind::Sign && signature.is_some()
    {
        return Err(Error::Rejected(
            crate::RejectionReason::SignatureContinuation(
                crate::SignatureContinuationRejection::SignatureInitialOperands,
            ),
        ));
    }
    request
        .contract
        .check(&session.inner, kind.operation(route))?;
    // InputLimits describe message input. Signature bytes have their own ABI
    // extent and retained memory credit; they are not additional message parts.
    if let Some(initial) = initial {
        limits.validate(session.inner.crypto_options.limits, &[initial])?;
    } else {
        limits.validate(session.inner.crypto_options.limits, &[])?;
    }
    if let Some(signature) = signature {
        bounds::ck_length(signature.len())?;
    }
    let capacity = match plan {
        SignatureOutputPlan::Buffer { capacity } => capacity,
        SignatureOutputPlan::LengthOnly => 0,
    };
    if capacity > maximum_output || kind != Kind::Sign && capacity != 0 {
        return Err(Error::Rejected(
            crate::RejectionReason::SignatureContinuation(
                crate::SignatureContinuationRejection::SignatureOutputCapacity,
            ),
        ));
    }
    bounds::ck_length(capacity)?;
    let output_bytes = super::output_storage_bytes(request.contract.mechanism_number(), capacity)?;
    let check_functions = |state: &crate::module::State| kind.check_functions(route, state);
    let authentication = session.snapshot.authentication_stamp();
    let progress = session.init_preflight_at_epoch(authentication, &check_functions)?;
    let bytes = initial
        .map_or(0, <[u8]>::len)
        .checked_add(signature.map_or(0, <[u8]>::len))
        .and_then(|n| n.checked_mul(2))
        .ok_or(Error::Rejected(
            crate::RejectionReason::SignatureContinuation(
                crate::SignatureContinuationRejection::SignatureInputAccounting,
            ),
        ))?;
    let validation_bytes = if capture_validation {
        crate::advanced::validation::Capture::allocation_bytes(1)?
    } else {
        0
    };
    let mut required = OwnedGraph::recipe_bytes(request.parameters.recipe())?
        .checked_add(bytes)
        .and_then(|n| n.checked_add(validation_bytes))
        .and_then(|n| n.checked_add(output_bytes))
        .and_then(|n| n.checked_add(metadata_bytes()))
        .and_then(|n| n.checked_add(Shell::allocation_bytes()))
        .and_then(|n| n.checked_add(diagnostic_plan.preparation_bytes()))
        .ok_or(Error::Rejected(
            crate::RejectionReason::SignatureContinuation(
                crate::SignatureContinuationRejection::SignatureOperationAccounting,
            ),
        ))?;
    let mutates = request.contract.mutates_key();
    let role = if mutates {
        AccessMode::Write
    } else {
        AccessMode::Read
    };
    loop {
        // Both anchors outlive session/key access on every error return.
        // Successful construction transfers the complete installed owner.
        let installed: std::sync::Arc<crate::advanced::ledger::OperationCell>;
        let _returned: super::ReturnedOperands;
        let bound_revocation;
        let body;
        let mut retained_shell;
        let mut candidate;
        let mut replacement;
        let _unused_identity;
        let (
            (
                mut parameters,
                fragment,
                signature,
                mut output,
                mut scalars,
                shell,
                validation,
                mut revocation,
                competing_preparation,
                diagnostics,
            ),
            access,
        ) = session.prepare_init_with_native_roles_prepaid_at_epoch(
            [(Some(key), role)],
            kind.category(),
            authentication,
            &progress,
            |overhead| loop {
                session
                    .snapshot
                    .check_authentication_unchanged(authentication)?;
                let competing = session
                    .entry
                    .advanced_operation
                    .load(std::sync::atomic::Ordering::Acquire)
                    != 0;
                let competing_bytes = if competing {
                    super::competing_init::preparation_bytes()
                } else {
                    0
                };
                // Admit the frame and revocation storage together. No private
                // partial reservation can wait for bytes that it already holds.
                let revocation_shape = mutates
                    .then(|| {
                        crate::managed::RevocationShape::discover(
                            session,
                            key.identity.resource(),
                            authentication,
                        )
                    })
                    .transpose()?;
                let revocation_bytes = revocation_shape
                    .as_ref()
                    .map(crate::managed::RevocationShape::allocation_bytes)
                    .transpose()?
                    .unwrap_or(0);
                let admitted = required
                    .checked_add(revocation_bytes)
                    .and_then(|n| n.checked_add(competing_bytes))
                    .and_then(|n| n.checked_add(overhead))
                    .ok_or(Error::Rejected(crate::RejectionReason::SignatureContinuation(crate::SignatureContinuationRejection::SignatureRevocationAccounting)))?;
                let Some(mut prepaid) = crate::advanced::reserve_preparation_while(
                    session,
                    admitted,
                    &progress,
                    || {
                        session
                            .snapshot
                            .observe_authentication_unchanged(authentication)?;
                        Ok((session
                            .entry
                            .advanced_operation
                            .load(std::sync::atomic::Ordering::Acquire)
                            != 0)
                            == competing)
                    },
                )?
                else {
                    continue;
                };
                let revocation = revocation_shape.map(|shape| shape.allocate()).transpose()?;
                let revocation_actual = revocation
                    .as_ref()
                    .map(|storage| storage.allocated_bytes())
                    .transpose()?
                    .unwrap_or(0);
                let graph = GraphStorage::allocate_input(request.parameters)?;
                let fragment = initial
                    .map(|bytes| InputBytesStorage::allocate(bytes.len()))
                    .transpose()?;
                let supplied_signature = signature
                    .map(|bytes| InputBytesStorage::allocate(bytes.len()))
                    .transpose()?;
                let validation = capture_validation
                    .then(|| crate::advanced::validation::CaptureStorage::allocate(1))
                    .transpose()?;
                let validation_actual = validation
                    .as_ref()
                    .map(crate::advanced::validation::CaptureStorage::allocated_bytes)
                    .transpose()?
                    .unwrap_or(0);
                let output = UnboundBuffer::allocate(output_bytes)?;
                let fragment_bytes = fragment
                    .as_ref()
                    .map(InputBytesStorage::allocated_bytes)
                    .transpose()?
                    .unwrap_or(0);
                let signature_bytes = supplied_signature
                    .as_ref()
                    .map(InputBytesStorage::allocated_bytes)
                    .transpose()?
                    .unwrap_or(0);
                let actual = graph
                    .allocated_bytes()?
                    .checked_add(fragment_bytes)
                    .and_then(|n| n.checked_add(revocation_actual))
                    .and_then(|n| n.checked_add(validation_actual))
                    .and_then(|n| n.checked_add(signature_bytes))
                    .and_then(|n| n.checked_add(output.allocated()))
                    .and_then(|n| n.checked_add(metadata_bytes()))
                    .and_then(|n| n.checked_add(Shell::allocation_bytes()))
                    .and_then(|n| n.checked_add(overhead))
                    .and_then(|n| n.checked_add(competing_bytes))
                    .and_then(|n| n.checked_add(diagnostic_plan.preparation_bytes()))
                    .ok_or(Error::Rejected(crate::RejectionReason::SignatureContinuation(crate::SignatureContinuationRejection::SignatureOperationAccounting)))?;
                if actual > admitted {
                    drop(revocation);
                    drop(validation);
                    drop(output);
                    drop(supplied_signature);
                    drop(fragment);
                    drop(graph);
                    drop(prepaid);
                    required = actual
                        .checked_sub(revocation_bytes)
                        .and_then(|n| n.checked_sub(overhead))
                        .and_then(|n| n.checked_sub(competing_bytes))
                        .ok_or(Error::Rejected(crate::RejectionReason::SignatureContinuation(crate::SignatureContinuationRejection::SignatureRevocationAccounting)))?;
                    continue;
                }
                prepaid.release(admitted - actual);
                if !matches!(diagnostic_plan, super::batch::DiagnosticPlan::None) {
                    // Attribute the whole facade candidate before splitting.
                    // Later Update/login reservations include every still-live
                    // descendant, including the root's diagnostic leaves.
                    prepaid.observation_budget()?;
                }
                let revocation = revocation
                    .map(|storage| storage.bind(&mut prepaid))
                    .transpose()?;
                let validation = validation
                    .map(|storage| storage.bind(&mut prepaid))
                    .transpose()?;
                let graph = graph.bind(&mut prepaid)?;
                let fragment = fragment
                    .zip(initial)
                    .map(|(storage, bytes)| storage.bind(bytes, &mut prepaid))
                    .transpose()?;
                let signature = supplied_signature
                    .zip(signature)
                    .map(|(storage, bytes)| storage.bind(bytes, &mut prepaid))
                    .transpose()?;
                let mut output = output.bind(&mut prepaid)?;
                output.set_length(0)?;
                let credit = prepaid.split(metadata_bytes())?;
                let competing_preparation = competing
                    .then(|| super::competing_init::prepare(&mut prepaid))
                    .transpose()?;
                let shell = Shell::from_prepaid(&mut prepaid)?;
                let diagnostics = diagnostic_plan.prepare(&mut prepaid)?;
                let scalars = PreparedScalars {
                    mechanism: Box::new(CK_MECHANISM {
                        mechanism: request.contract.native_mechanism(),
                        pParameter: std::ptr::null_mut(),
                        ulParameterLen: 0,
                    }),
                    length: Box::new(bounds::ck_length(capacity)?),
                    completion_diagnostic: crate::error::CompletionStorage::allocate()?,
                    _credit: credit,
                };
                return Ok((
                    (
                        graph,
                        fragment,
                        signature,
                        output,
                        scalars,
                        shell,
                        validation,
                        revocation,
                        competing_preparation,
                        diagnostics,
                    ),
                    prepaid,
                ));
            },
        )?;
        session
            .snapshot
            .check_authentication_unchanged(authentication)?;
        if session
            .entry
            .advanced_operation
            .load(std::sync::atomic::Ordering::Acquire)
            != 0
            && competing_preparation.is_none()
        {
            // The sizing observation raced with installation. Drop possession
            // before this complete unpublished candidate; then plan the frame
            // outside guards. No native Init has run for this attempt.
            drop(access);
            continue;
        }
        check_functions(&access)?;
        session.native_object_handle(&access, key)?;
        bound_revocation = match revocation.as_mut() {
            Some(prepared) => match prepared.bind(&access)? {
                Some(targets) => Some(targets),
                None => {
                    // No native call or installation happened. Release possession
                    // and all unpublished frame storage before preparing again.
                    drop(access);
                    continue;
                }
            },
            None => None,
        };
        let (pointer, length) = parameters.projection();
        scalars.mechanism.pParameter = pointer;
        scalars.mechanism.ulParameterLen = length;
        let output_offset = super::output_offset(request.contract.mechanism_number(), &mut output)?;
        // This binding precedes access: shell/ledger refusal must not destroy
        // native parameters, private inputs or revocation snapshots first.
        body = SignatureOperation {
            key: key.identity.clone(),
            authentication,
            _roles: super::roles::Roles::Original(access.retain_role_lease()),
            own_revocation: false,
            revocation: bound_revocation,
            contract: request.contract.clone(),
            kind,
            route,
            mechanism: scalars.mechanism,
            parameters: Some(parameters),
            fragment,
            signature,
            output: Some(output),
            output_offset,
            returned: super::ReturnedOperands::default(),
            length: scalars.length,
            plan,
            maximum_output,
            input: if initial.is_some() {
                InputState::closed()
            } else {
                InputState::open()
            },
            stage: Stage::Init,
            observer: super::Observer::Ticket,
            activity: NativeActivity::Inactive,
            completion_diagnostic: Some(scalars.completion_diagnostic),
            _credit: scalars._credit,
        };
        retained_shell = Some(shell);
        if session
            .entry
            .advanced_operation
            .load(std::sync::atomic::Ordering::Acquire)
            != 0
        {
            let prepared =
                competing_preparation.expect("competing frame prepared before possession");
            // The public facade owns this root across all private adapters.
            // Frame B can remain native-resident independently of its error.
            retirement.competing_signature = Some(prepared.diagnostic_credit);
            let (control, identity) = retained_shell
                .take()
                .expect("prepared signature shell")
                .into_replacement_parts();
            _unused_identity = identity;
            replacement = crate::advanced::operation::SignatureReplacement {
                control,
                validation,
                provenance: None,
            };
            let result = super::competing_init::attempt(
                session,
                access,
                body,
                prepared.frame_credit,
                prepared.diagnostic,
                &mut replacement,
                retirement,
                remaining,
            );
            return result.map(|(ticket, owner)| (ticket, owner, diagnostics));
        }
        drop(competing_preparation);
        let (token, cancel) =
            Shell::bind_retained(&mut retained_shell, &access.lease_admission()?)?;
        candidate = Some(
            Operation::new(OperationBody::Signature(body), token, cancel)
                .with_validation(validation),
        );
        let (id, owner) = access.operations.install_with_retained(
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
        // Terminal retirement must not release the prepaid metadata before the
        // caller has projected the initial native result.
        retirement.retired_owner = Some(owner.clone());
        installed = owner;
        let mut operation = installed.lock().map_err(|_| Error::Poisoned)?;
        let driven = drive(&access, &session.entry, &mut operation, false, remaining);
        let OperationBody::Signature(body) = &mut operation.body else {
            unreachable!("installed classic signature owner")
        };
        _returned = body.take_returned_operands();
        if let Err(error) = driven {
            let (error, released) = operation.retire_terminal_error(&access, &session.entry, error);
            if !released {
                if let OperationBody::Signature(body) = &mut operation.body {
                    body.observer = super::Observer::Session;
                }
            }
            return Err(error);
        }
        drop(operation);
        return Ok((ticket, installed, diagnostics));
    }
}
