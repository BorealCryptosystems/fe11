// SPDX-License-Identifier: Apache-2.0
//! Build AEAD message storage and bind the requested key roles.
//! Shared initialization parameters and individual messages retain separate ownership.

use super::*;

// Additional output ownership requested by a synchronous compatibility facade.
// Allocate before Init; never wait for its buffer after nonce consumption.
pub(super) fn start_shared_messages(
    session: &Session,
    key: MessageKey<'_>,
    requests: Requests<'_>,
    route: MessageRoute,
    limits: crate::InputLimits,
    init: MessageInitLayout,
    pacing: OperationPacing,
    capture: bool,
    accounting: InputAccounting,
    retained: Option<(usize, usize)>,
    diagnostics: &mut Option<ticket::Diagnostics>,
) -> Result<(
    OperationTicket,
    Option<(Buffer, Credit)>,
    Arc<crate::advanced::ledger::OperationCell>,
)> {
    // Keep the whole installed owner outside possession, including an Init
    // refusal that removes its registry entry before any input was consumed.
    // On success this anchor is transferred to the caller unchanged.
    let held: Arc<crate::advanced::ledger::OperationCell>;
    if diagnostics.is_some() {
        return Err(Error::Rejected(crate::RejectionReason::AeadMessages(
            crate::AeadMessagesRejection::AeadInvocationDiagnosticsAlreadyInstalled,
        )));
    }
    // Returned operands have a separate lifetime from the still-live owner.
    // Both release owners are declared before every possession guard.
    let _released: input::ReleasedInput;
    accounting.validate(&requests, limits, session.inner.crypto_options.limits)?;
    requests.validate_init(init)?;
    let progress = session.advanced_preflight(|state| {
        check_message_key(state, key, requests.kind(), requests.decrypt(), route)
    })?;
    let maximum = requests.len().checked_add(1).ok_or(Error::Rejected(
        crate::RejectionReason::AeadMessages(crate::AeadMessagesRejection::ValidationReportLength),
    ))?;
    let shape = snapshot::Shape::for_requests(&requests, route, init)?;
    let retained_bytes = match retained {
        Some((bytes, metadata)) => storage_sum(&[bytes, metadata])?,
        None => 0,
    };
    let publication = retained.is_some().then_some(if requests.decrypt() {
        "C_MessageDecryptFinal"
    } else {
        "C_MessageEncryptFinal"
    });
    let diagnostic_bytes = ticket::Diagnostics::preparation_bytes(publication.is_some());
    let known = storage_sum(&[
        diagnostic_bytes,
        shape.allocation_bytes(),
        crate::advanced::preparation::Shell::allocation_bytes(),
        retained_bytes,
        if capture {
            crate::advanced::validation::Capture::allocation_bytes(maximum)?
        } else {
            0
        },
    ])?;
    let key_readers = super::super::keys::KeyReaders::prepare(
        session,
        [Some(match key {
            MessageKey::Aes(key) => &key.managed,
            MessageKey::Native(key) => key,
        })],
    )?;
    let mut total = known;
    let ((prepared_diagnostics, prepared, cancel, retained, validation), s, mut prepared_readers) =
        key_readers.prepare_with(session, &progress, || loop {
            let mut prepaid =
                crate::advanced::preparation::reserve_new_with_progress(session, total, &progress)?;
            let metadata = shape.allocate_metadata()?;
            let metadata_actual = metadata.allocated_bytes()?;
            // Keep every known sibling in the bound before binding metadata.
            // Excess vector capacity must not consume the credits reserved for
            // the continuation account, diagnostics, shell or retained output.
            let metadata_total = known
                .checked_sub(shape.metadata_bytes()?)
                .and_then(|n| n.checked_add(metadata_actual))
                .ok_or(Error::Rejected(crate::RejectionReason::AeadMessages(
                    crate::AeadMessagesRejection::AeadStorageOverflow,
                )))?;
            if metadata_total > total {
                drop(metadata);
                drop(prepaid);
                total = metadata_total;
                continue;
            }
            prepaid.observation_budget()?;
            let mut metadata = metadata.bind(&mut prepaid)?;
            shape.describe_request(&mut metadata, &requests)?;
            let storage = shape.allocate(metadata)?;
            let validation = capture
                .then(|| crate::advanced::validation::CaptureStorage::allocate(maximum))
                .transpose()?;
            let retained_storage = retained
                .map(|(bytes, _)| crate::symmetric::memory::UnboundBuffer::allocate(bytes))
                .transpose()?;
            let actual = storage_sum(&[
                diagnostic_bytes,
                metadata_actual,
                storage.allocated_bytes()?,
                crate::advanced::preparation::Shell::allocation_bytes(),
                validation
                    .as_ref()
                    .map(crate::advanced::validation::CaptureStorage::allocated_bytes)
                    .transpose()?
                    .unwrap_or(0),
                retained_storage
                    .as_ref()
                    .map_or(0, crate::symmetric::memory::UnboundBuffer::allocated),
                retained.map_or(0, |(_, metadata)| metadata),
            ])?;
            if actual > total {
                drop(retained_storage);
                drop(validation);
                drop(storage);
                drop(prepaid);
                total = actual;
                continue;
            }
            prepaid.release(total - actual);
            let prepared_diagnostics = ticket::Diagnostics::prepare(&mut prepaid, publication)?;
            let prepared = storage.bind(&mut prepaid)?.fill_request(&requests)?;
            let validation = validation
                .map(|storage| storage.bind(&mut prepaid))
                .transpose()?;
            let retained = match (retained_storage, retained) {
                (Some(storage), Some((_, metadata))) => {
                    Some((storage.bind(&mut prepaid)?, prepaid.split(metadata)?))
                }
                (None, None) => None,
                _ => {
                    return Err(Error::Rejected(crate::RejectionReason::AeadMessages(
                        crate::AeadMessagesRejection::AeadStorageShapeChanged,
                    )))
                }
            };
            let cancel = crate::advanced::preparation::Shell::from_prepaid(&mut prepaid)?;
            return Ok((prepared_diagnostics, prepared, cancel, retained, validation));
        })?;
    *diagnostics = Some(prepared_diagnostics);
    let key = message_key(
        session,
        &s,
        key,
        requests.kind(),
        requests.decrypt(),
        route,
        &mut prepared_readers,
    )?;
    let body = prepared.bind(key);
    let (lease, cancel) = cancel.bind(&s.lease_admission()?)?;
    let (id, operation) = s.operations.install(
        &session.entry,
        Operation::new(OperationBody::AeadMessages(body), lease, cancel)
            .with_validation(validation),
    )?;
    let mut ticket = OperationTicket {
        owner: session.inner.clone(),
        uid: session.uid,
        id,
        validation_report: None,
        state_provenance: None,
    };
    held = operation;
    // A first-drive failure can retire the ledger before this starter returns.
    // Its invocation root keeps the body's diagnostic credit through projection.
    diagnostics
        .as_mut()
        .expect("AEAD diagnostics installed")
        .retired_owner = Some(held.clone());
    let mut operation = held.lock().map_err(|_| Error::Poisoned)?;
    let driven = drive(
        &s,
        &session.entry,
        &mut operation,
        false,
        &mut pacing.budget(),
    );
    let OperationBody::AeadMessages(body) = &mut operation.body else {
        unreachable!("installed AEAD message owner")
    };
    _released = body.take_released_input();
    if let Err(error) = driven {
        let (error, retired) = operation.retire_terminal_error(&s, &session.entry, error);
        if retired {
            return Err(error);
        }
        // Preserve the original diagnostic while keeping the retained native
        // owner reachable. No second admission or native request is attempted.
        return match ticket::park_locked(session, &mut ticket, &mut operation) {
            Ok(()) => Err(error),
            Err(cleanup) => Err(diagnostics
                .as_mut()
                .expect("AEAD diagnostics installed")
                .parking
                .finish(error, cleanup)),
        };
    }
    drop(operation);
    Ok((ticket, retained, held))
}

impl AeadMessageOperation {
    pub(super) fn validate_binding(&self) -> Result<()> {
        validate_binding_storage(self.kind, &self.mechanism, &self.init, &self.frames)
    }

    pub(super) fn prepare_message(&mut self, i: usize) -> Result<()> {
        prepare_message_storage(self.kind, &self.mechanism, &mut self.init, &self.frames, i)
    }
}
