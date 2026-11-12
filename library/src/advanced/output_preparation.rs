// SPDX-License-Identifier: Apache-2.0
//! Replacement storage for an explicitly paused output, without native replay.
use super::{
    preparation, progress, CipherBufferRequest, OperationBody, OperationTicket,
    RecoveryBufferRequest,
};
use crate::{
    symmetric::memory::{Buffer, PreparedBuffer},
    Error, Result, Session,
};
use std::sync::Arc;

pub(super) enum Family {
    Digest,
    Cipher,
    Aead,
    Recovery,
    Signature,
}

// These are copied observations, not access to the source prefix or native
// descriptors. Both remain in their registered owner throughout the wait.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Need {
    Digest {
        required: usize,
        previous: usize,
        total: usize,
    },
    Signature {
        request: super::SignatureBufferRequest,
        total: usize,
    },
    Cipher {
        request: CipherBufferRequest,
        total: usize,
    },
    Recovery {
        request: RecoveryBufferRequest,
        total: usize,
    },
}
impl Need {
    fn bytes(self) -> usize {
        match self {
            Self::Digest { total, .. }
            | Self::Cipher { total, .. }
            | Self::Recovery { total, .. }
            | Self::Signature { total, .. } => total,
        }
    }
}

fn need(body: &OperationBody, family: &Family, capacity: usize) -> Result<Need> {
    match (body, family) {
        (OperationBody::Digest(body), Family::Digest) => {
            let (required, previous) = body.digest_output_preparation(capacity)?;
            Ok(Need::Digest {
                required,
                previous,
                total: capacity,
            })
        }
        (OperationBody::NativeMessages(body), Family::Signature) => Ok(Need::Signature {
            request: body.output_preparation(capacity)?,
            total: body.output_storage_bytes(capacity)?,
        }),
        (OperationBody::Messages(body), Family::Signature) => Ok(Need::Signature {
            request: body.output_preparation(capacity)?,
            total: capacity,
        }),
        (OperationBody::Signature(body), Family::Signature) => Ok(Need::Signature {
            request: body.output_preparation(capacity)?,
            total: body.output_storage_bytes(capacity)?,
        }),
        (OperationBody::AeadMessages(body), Family::Aead) => {
            let (request, total) = body.output_preparation(capacity)?;
            Ok(Need::Cipher { request, total })
        }
        (OperationBody::Cipher(body), Family::Cipher) => {
            let (request, total) = body.output_preparation(capacity)?;
            Ok(Need::Cipher { request, total })
        }
        (OperationBody::Recover(body), Family::Recovery) => {
            let request = body.output_preparation(capacity)?;
            Ok(Need::Recovery {
                request,
                total: capacity,
            })
        }
        (_, Family::Digest) => Err(Error::Rejected(crate::RejectionReason::OperationOwnership(
            crate::OperationOwnershipRejection::DigestTicketRequired,
        ))),
        (_, Family::Cipher) => Err(Error::Rejected(crate::RejectionReason::OperationOwnership(
            crate::OperationOwnershipRejection::CipherTicketRequired,
        ))),
        (_, Family::Aead) => Err(Error::Rejected(crate::RejectionReason::OperationOwnership(
            crate::OperationOwnershipRejection::AeadMessageTicketRequired,
        ))),
        (_, Family::Recovery) => Err(Error::Rejected(crate::RejectionReason::OperationOwnership(
            crate::OperationOwnershipRejection::RecoveryTicketRequired,
        ))),
        (_, Family::Signature) => Err(Error::Rejected(crate::RejectionReason::OperationOwnership(
            crate::OperationOwnershipRejection::SignatureTicketRequired,
        ))),
    }
}

pub(super) fn replace(
    session: &Session,
    ticket: &OperationTicket,
    capacity: usize,
    family: Family,
) -> Result<()> {
    if !Arc::ptr_eq(&ticket.owner, &session.inner) || ticket.uid != session.uid || ticket.id == 0 {
        return Err(Error::Rejected(match family {
            Family::Digest => crate::RejectionReason::OperationOwnership(
                crate::OperationOwnershipRejection::ForeignOrConsumedDigestTicket,
            ),
            Family::Cipher => crate::RejectionReason::OperationOwnership(
                crate::OperationOwnershipRejection::ForeignOrConsumedCipherTicket,
            ),
            Family::Aead => crate::RejectionReason::OperationOwnership(
                crate::OperationOwnershipRejection::ForeignOrConsumedAeadMessageTicket,
            ),
            Family::Recovery => crate::RejectionReason::OperationOwnership(
                crate::OperationOwnershipRejection::ForeignOrConsumedRecoveryTicket,
            ),
            Family::Signature => crate::RejectionReason::OperationOwnership(
                crate::OperationOwnershipRejection::ForeignOrConsumedSignatureTicket,
            ),
        }));
    }
    let admission = crate::admission_wait::current();
    // Public output-capacity methods tail-return this result without retaining
    // an error in another owner. Keep its credit here through every helper,
    // source-guard release and displaced-output destruction before that return.
    let mut diagnostics = None;
    let mut candidate: Option<(Need, Buffer)> = None;
    let mut waiter: Option<progress::Waiter<'_>> = None;
    loop {
        let access = session.advanced_access()?;
        let held = access.operations.get(ticket.uid)?;
        let mut operation = held.lock().map_err(|_| Error::Poisoned)?;
        if operation.id != ticket.id {
            return Err(Error::Rejected(match family {
                Family::Digest => crate::RejectionReason::OperationOwnership(
                    crate::OperationOwnershipRejection::StaleDigestTicket,
                ),
                Family::Cipher => crate::RejectionReason::OperationOwnership(
                    crate::OperationOwnershipRejection::StaleCipherTicket,
                ),
                Family::Aead => crate::RejectionReason::OperationOwnership(
                    crate::OperationOwnershipRejection::StaleAeadMessageTicket,
                ),
                Family::Recovery => crate::RejectionReason::OperationOwnership(
                    crate::OperationOwnershipRejection::StaleRecoveryTicket,
                ),
                Family::Signature => crate::RejectionReason::OperationOwnership(
                    crate::OperationOwnershipRejection::StaleSignatureTicket,
                ),
            }));
        }
        operation.check_continuation_control(&session.entry)?;
        super::rejoin::check_keys(&operation.body, &session.entry)?;
        let current = need(&operation.body, &family, capacity)?;
        if diagnostics.is_none() {
            drop(operation);
            drop(held);
            drop(access);
            diagnostics = Some(progress::FailureDiagnostics::prepare(session, ticket.id)?);
            continue;
        }
        if let Some(waiting) = waiter.as_mut() {
            let unchanged = !waiting.changed()
                && candidate
                    .as_ref()
                    .is_some_and(|(expected, _)| *expected == current);
            waiting.succeed()?;
            if !unchanged {
                drop(operation);
                drop(held);
                drop(access);
                drop(candidate.take());
                drop(waiter.take());
                continue;
            }
            access
                .operations
                .claim_progress(&session.entry, operation.id)?;
            let (_, output) = candidate.take().expect("matching output preparation");
            let old = match &mut operation.body {
                OperationBody::Digest(body) => body.attach_digest_output(capacity, output)?,
                OperationBody::Cipher(body) => body.attach_output(capacity, output)?,
                OperationBody::AeadMessages(body) => body.attach_output(capacity, output)?,
                OperationBody::Recover(body) => body.attach_output(capacity, output)?,
                OperationBody::Signature(body) => body.attach_output(capacity, output)?,
                OperationBody::Messages(body) => body.attach_output(capacity, output)?,
                OperationBody::NativeMessages(body) => body.attach_output(capacity, output)?,
                _ => unreachable!("validated output owner"),
            };
            // Publish the new owner under possession, but erase/free the old
            // storage and notify its budget only after all guards are released.
            drop(operation);
            drop(held);
            drop(access);
            drop(old);
            return Ok(());
        }

        waiter = Some(progress::Waiter::new(
            session,
            operation.id,
            progress::Effect::PreserveOwner,
        )?);
        drop(operation);
        drop(held);
        drop(access);
        let waiting = waiter.as_mut().expect("registered output waiter");
        let diagnostics = diagnostics.as_mut().expect("output diagnostics prepared");
        let prepared = Buffer::new_controlled_retaining(
            diagnostics.budget(),
            current.bytes(),
            crate::session::lifecycle_diagnostics::Store::allocation_bytes(),
            &admission,
            || {
                preparation::context(session)?;
                Ok(waiting.changed().then_some(()))
            },
        );
        match prepared {
            Ok(PreparedBuffer::Ready(output)) => candidate = Some((current, output)),
            Ok(PreparedBuffer::Redirect(())) => {
                waiting.succeed()?;
            }
            Err(error) => return Err(waiting.fail_prepared(error, diagnostics)),
        }
    }
}
