// SPDX-License-Identifier: Apache-2.0
//! Aggregate admission for an initialized generic message parent.
use super::{binding::Binding, preparation::OwnerStorage, NativeMessageOperation};
use crate::advanced::{key_roles::Roles, preparation::Shell, validation};
use crate::mechanism_extension::{graph::recipe, parameter_keys::ParameterKeys};
use crate::session::{activity::AccessMode, SessionAccess};
use crate::{AdvancedSessionMode, Error, MessageRoute, NativeObjectRef, Result, Session};

/// Access is first so dropping an unpublished start releases possession before
/// destroying candidate buffers/credits. Installation consumes the other fields
/// while this access remains held and rechecks the operation registry there.
pub(super) struct PreparedStart<'s> {
    pub(super) access: SessionAccess<'s>,
    pub(super) body: NativeMessageOperation,
    pub(super) shell: Shell,
    pub(super) validation: Option<validation::Capture>,
    pub(super) diagnostics: Option<super::batch::Diagnostics>,
}

fn accounting() -> Error {
    Error::Rejected(crate::RejectionReason::NativeMessages(
        crate::NativeMessagesRejection::GenericMessageStartAccounting,
    ))
}

/// `future_parameter_writes` declares a possible effect of later ABI parameters,
/// not a cryptographic admission policy. Acquire that writer before Init; the
/// driver arms revocation only when an actually submitted declaration modifies
/// the key. No future input bytes or parameter graphs are required here.
pub(super) fn prepare<'s, 'a>(
    session: &'s Session,
    key: &NativeObjectRef,
    request: recipe::Request<'a>,
    keys: ParameterKeys<'a>,
    route: MessageRoute,
    verify: bool,
    future_parameter_writes: bool,
    capture_validation: bool,
    facade: bool,
) -> Result<PreparedStart<'s>> {
    if session.entry.mode != AdvancedSessionMode::Synchronous {
        return Err(Error::Rejected(crate::RejectionReason::NativeMessages(
            crate::NativeMessagesRejection::MessageAsynchronousModeUnavailable,
        )));
    }
    let operation = crate::mechanism_extension::message::operation_kind(
        !verify,
        route == MessageRoute::Multipart,
    );
    request.contract.check(&session.inner, operation)?;
    keys.validate(request.parameters.recipe())?;
    let sources = keys.references()?;
    let check_functions =
        |state: &crate::module::State| super::driver::functions(state, verify, route).map(|_| ());
    let authentication = session.snapshot.authentication_stamp();
    let progress = session.advanced_preflight_at_epoch(authentication, &check_functions)?;
    let writer = request.contract.mutates_key() || future_parameter_writes;
    let primary_mode = if writer {
        AccessMode::Write
    } else {
        AccessMode::Read
    };
    // Zero completed messages still need capacity for the explicit parent Final.
    let observation_bytes = if capture_validation {
        validation::Capture::allocation_bytes(1)?
    } else {
        0
    };
    let diagnostic_bytes = if facade {
        super::batch::Diagnostics::preparation_bytes(verify)
    } else {
        0
    };
    let mut required = OwnerStorage::required_bytes(request)?
        .checked_add(Shell::allocation_bytes())
        .and_then(|bytes| bytes.checked_add(observation_bytes))
        .and_then(|bytes| bytes.checked_add(diagnostic_bytes))
        .ok_or_else(accounting)?;
    loop {
        let ((prepared, shell, validation, diagnostics, mut revocation), access) = session
            .prepare_with_native_roles_prepaid_at_epoch(
                [
                    (Some(key), primary_mode),
                    (sources[0], AccessMode::Read),
                    (sources[1], AccessMode::Read),
                    (sources[2], AccessMode::Read),
                    (sources[3], AccessMode::Read),
                ],
                false,
                authentication,
                &progress,
                |overhead| loop {
                    session
                        .snapshot
                        .check_authentication_unchanged(authentication)?;
                    let shape = writer
                        .then(|| {
                            crate::managed::RevocationShape::discover(
                                session,
                                key.identity.resource(),
                                authentication,
                            )
                        })
                        .transpose()?;
                    let revocation_bytes = shape
                        .as_ref()
                        .map(crate::managed::RevocationShape::allocation_bytes)
                        .transpose()?
                        .unwrap_or(0);
                    let admitted = required
                        .checked_add(overhead)
                        .and_then(|bytes| bytes.checked_add(revocation_bytes))
                        .ok_or_else(accounting)?;
                    let mut prepaid = crate::advanced::reserve_preparation_at_epoch(
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
                    let observation = capture_validation
                        .then(|| validation::CaptureStorage::allocate(1))
                        .transpose()?;
                    let observation_actual = observation
                        .as_ref()
                        .map(validation::CaptureStorage::allocated_bytes)
                        .transpose()?
                        .unwrap_or(0);
                    let storage = OwnerStorage::allocate(request, keys)?;
                    let actual = storage
                        .allocated_bytes()?
                        .checked_add(Shell::allocation_bytes())
                        .and_then(|bytes| bytes.checked_add(observation_actual))
                        .and_then(|bytes| bytes.checked_add(diagnostic_bytes))
                        .and_then(|bytes| bytes.checked_add(revocation_actual))
                        .and_then(|bytes| bytes.checked_add(overhead))
                        .ok_or_else(accounting)?;
                    if actual > admitted {
                        // No possession or C yet. Replan the entire candidate;
                        // never wait for more credit while keeping this one.
                        drop(storage);
                        drop(observation);
                        drop(revocation);
                        drop(prepaid);
                        required = actual
                            .checked_sub(revocation_bytes)
                            .and_then(|bytes| bytes.checked_sub(overhead))
                            .ok_or_else(accounting)?;
                        continue;
                    }
                    prepaid.release(admitted - actual);
                    let diagnostics = if facade {
                        prepaid.observation_budget()?;
                        Some(super::batch::Diagnostics::prepare(verify, &mut prepaid)?)
                    } else {
                        None
                    };
                    let revocation = revocation
                        .map(|storage| storage.bind(&mut prepaid))
                        .transpose()?;
                    let observation = observation
                        .map(|storage| storage.bind(&mut prepaid))
                        .transpose()?;
                    let prepared = storage.bind(&mut prepaid)?;
                    let shell = Shell::from_prepaid(&mut prepaid)?;
                    return Ok((
                        (prepared, shell, observation, diagnostics, revocation),
                        prepaid,
                    ));
                },
            )?;
        session
            .snapshot
            .check_authentication_unchanged(authentication)?;
        check_functions(&access)?;
        session.native_object_handle(&access, key)?;
        for source in sources.iter().flatten() {
            session.native_object_handle(&access, source)?;
        }
        // Results precede access so a later binding refusal cannot release
        // the successful revocation snapshot while possession is still held.
        let bound_revocation;
        let mut primary;
        let binding;
        let access = access;
        bound_revocation = match revocation.as_mut() {
            Some(snapshot) => match snapshot.bind(&access)? {
                Some(targets) => Some(targets),
                None => {
                    // Object registry grew after sizing: release possession
                    // and every unpublished candidate before a new admission.
                    drop(access);
                    drop(prepared);
                    drop(shell);
                    drop(validation);
                    continue;
                }
            },
            None => None,
        };
        primary = Some(crate::advanced::signature::binding::Binding {
            key: key.identity.clone(),
            authentication,
            roles: Roles::Original(access.retain_role_lease()),
            contract: request.contract.clone(),
            own_revocation: false,
            revocation: bound_revocation,
        });
        binding = Binding::from_start(&mut primary, writer, sources)?;
        if let Err(error) = prepared.check_binding(&binding, route, verify) {
            drop(access);
            return Err(error);
        }
        let body = prepared.finish(binding, route, verify);
        return Ok(PreparedStart {
            access,
            body,
            shell,
            validation,
            diagnostics,
        });
    }
}

/// Shared installation for caller-fed and complete-input facades. Retaining the
/// Arc lets a facade park its ticket even after a context error blocks new access.
pub(super) fn start_retained(
    session: &Session,
    key: &NativeObjectRef,
    request: recipe::Request<'_>,
    keys: ParameterKeys<'_>,
    route: MessageRoute,
    verify: bool,
    future_parameter_writes: bool,
    capture_validation: bool,
    facade: bool,
    authentication: Option<&crate::ContextAuthentication>,
    retirement: &mut crate::advanced::PollDiagnostics,
) -> Result<(
    crate::OperationTicket,
    std::sync::Arc<crate::advanced::ledger::OperationCell>,
    Option<super::batch::Diagnostics>,
)> {
    use crate::advanced::{drive, Operation, OperationBody, OperationTicket};
    // The invocation retains terminal metadata through public projection;
    // body/role destruction still follows session and operation possession.
    let mut candidate;
    let mut shell;
    let prepared = prepare(
        session,
        key,
        request,
        keys,
        route,
        verify,
        future_parameter_writes,
        capture_validation,
        facade,
    )?;
    if let Some(authentication) = authentication {
        // Known function absence must fail before installation or native Init.
        authentication.check_available(&prepared.access)?;
    }
    // Destructure access last: on any refusal it leaves before the remaining
    // body/validation inputs and the earlier retained shell/operation slots.
    let PreparedStart {
        body,
        shell: initial_shell,
        validation,
        diagnostics,
        access,
    } = prepared;
    shell = Some(initial_shell);
    let admission = access.lease_admission()?;
    let (lease, cancellation) = Shell::bind_retained(&mut shell, &admission)?;
    candidate = Some(
        Operation::new(OperationBody::NativeMessages(body), lease, cancellation)
            .with_validation(validation),
    );
    let (id, held) = access.operations.install_with_retained(
        &session.entry,
        &mut candidate,
        &mut None,
        |_| {},
    )?;
    retirement.retired_owner = Some(held.clone());
    let ticket = OperationTicket {
        owner: session.inner.clone(),
        uid: session.uid,
        id,
        validation_report: None,
        state_provenance: None,
    };
    let mut operation = held.lock().map_err(|_| Error::Poisoned)?;
    // Init only. Authentication and each input transition remain explicit.
    if let Err(error) = drive(&access, &session.entry, &mut operation, false, &mut 1) {
        let (error, released) = operation.retire_terminal_error(&access, &session.entry, error);
        if !released {
            if let OperationBody::NativeMessages(body) = &mut operation.body {
                body.observer = super::Observer::Session;
            }
        }
        return Err(error);
    }
    drop(operation);
    Ok((ticket, held, diagnostics))
}
