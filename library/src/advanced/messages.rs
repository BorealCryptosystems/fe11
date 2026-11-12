// SPDX-License-Identifier: Apache-2.0
//! PKCS#11 message signature operations retained by the operation ledger.
use super::{
    asynchronous, continuation, drive, preparation, record, restoration_keys, spend, validation,
    AdvancedSession, AdvancedSessionMode, NativeActivity, Operation, OperationBody,
    OperationProgress, OperationTicket, StateKeyReference, StateRestoreKeys,
};

use crate::module::{SessionEntry, State};
use crate::native::message_signature as dispatch;
use crate::symmetric::memory::{Budget, Buffer, Credit};

use crate::{bounds, Error, Result, Session};
use fe11_sys::{
    CKF_MESSAGE_SIGN, CKF_MESSAGE_VERIFY, CKR_OK, CKR_PENDING, CKR_SIGNATURE_INVALID,
    CKR_SIGNATURE_LEN_RANGE, CK_ASYNC_DATA, CK_FLAGS, CK_MECHANISM, CK_MECHANISM_TYPE,
    CK_RSA_PKCS_PSS_PARAMS, CK_ULONG,
};

use std::sync::atomic::Ordering;
use std::sync::Arc;
mod input;
mod output;
mod released;
pub(super) use released::ReleasedInputs;
pub(in crate::advanced) mod pss;
pub(super) mod snapshot;
mod stream_api;
mod stream_capture;
use super::keys::{pss_profile, KeyLease};
use crate::advanced::record::Family;
use crate::{SymmetricKey, Verification};
use pss::PssFrame;

/// Explicit message route. Refusal never selects the other route.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum MessageRoute {
    /// One complete native data call: C_*Message for message APIs, or the
    /// traditional C_Digest/C_Sign/C_Verify function for their corresponding APIs.
    Single,
    /// Message APIs use Begin/Next; traditional APIs use Update/Final.
    /// Each supplied part keeps its boundary; native support is established by the call.
    Multipart,
}
/// Borrowed input copied into bounded owned storage before any native call.
pub struct SignatureMessage<'a> {
    /// Ordered pieces of one message. An empty list represents an empty message.
    pub parts: &'a [&'a [u8]],
}
/// HMAC spelling retained for callers; the message representation is shared.
pub type MacMessage<'a> = SignatureMessage<'a>;
/// Completed signatures in input order; bytes and vector credit remain owned.
/// No signature is published before the whole native process finishes.
pub struct MessageSignatures {
    bytes: Vec<Buffer>,
    // Same stable row order as bytes; stored and admitted with result metadata.
    rejections: Vec<Option<crate::NativeMessageRejection>>,
    _metadata: Credit,
}
impl MessageSignatures {
    /// Number of submitted messages, including refused rows.
    pub fn len(&self) -> usize {
        self.bytes.len()
    }
    /// Whether this result contains no messages.
    pub fn is_empty(&self) -> bool {
        self.bytes.is_empty()
    }
    /// Borrow one signature; caller copies are outside the library byte budget.
    pub fn get(&self, index: usize) -> Option<&[u8]> {
        if self.rejections.get(index)?.is_some() {
            return None;
        }
        self.bytes.get(index).map(Buffer::as_slice)
    }
    /// Exact operational refusal for a row. No bytes are exposed for that row.
    pub fn rejection(&self, index: usize) -> Option<crate::NativeMessageRejection> {
        self.rejections.get(index).copied().flatten()
    }
}

/// Typed verification results when at least one message was operationally refused.
/// There is no aggregate Valid/Invalid verdict for this partially evaluated set.
/// The errors were already returned at their call boundaries; this owner preserves
/// their row association after explicit parent Final without retaining key leases.
pub struct MessageVerificationDetails {
    results: MessageSignatures,
    invalid_seen: bool,
}
impl MessageVerificationDetails {
    /// Number of submitted messages, including operational refusals.
    pub fn len(&self) -> usize {
        self.results.len()
    }
    /// Whether no message was submitted.
    pub fn is_empty(&self) -> bool {
        self.results.is_empty()
    }
    /// Operational refusal for this row; None is not an individual validity assertion.
    pub fn rejection(&self, index: usize) -> Option<crate::NativeMessageRejection> {
        self.results.rejection(index)
    }
    /// Whether any completed native verification explicitly reported an invalid signature.
    pub fn has_invalid_signature(&self) -> bool {
        self.invalid_seen
    }
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum MessageStep {
    Init,
    /// Initialized process awaiting an explicit message or parent Final.
    Ready,
    /// Begin completed; absence of a fragment cannot finish this message.
    Receive(usize),
    Single(usize),
    Begin(usize),
    Next(usize, usize),
    StreamUpdate(usize),
    StreamLast(usize),
    Output(output::Pending),
    Finish,
    Done,
    Failed,
}
// Only the initial data call can report insufficient output capacity.
// PKCS#11 3.2 §5.21.1 requires that result before returning CKR_PENDING;
// an observation cannot supply a fabricated size from the old length cell.
#[derive(Clone, Copy, PartialEq, Eq)]
enum CompletionSource {
    Call,
    Observation,
}

enum MessageOutcome {
    Nominal,
    Invalid,
    ClosingInvalid(crate::error::CleanupDiagnostic),
    ClosingFailure(crate::error::CleanupDiagnostic),
}
impl MessageOutcome {
    fn valid(&self) -> bool {
        matches!(self, Self::Nominal)
    }
    fn closing(&self) -> bool {
        matches!(self, Self::ClosingInvalid(_) | Self::ClosingFailure(_))
    }
}
pub(super) struct MacOperation {
    input: super::input::InputState,
    released: ReleasedInputs,
    // Only the current caller-fed fragment. Buffered facades retain their
    // original input tables; the two representations never share a dispatch.
    stream_fragment: Option<Buffer>,
    key: KeyLease,
    kind: CK_MECHANISM_TYPE,
    route: MessageRoute,
    verify: bool,
    outcome: MessageOutcome,
    size: usize,
    step: MessageStep,
    activity: NativeActivity,
    mechanism: Box<CK_MECHANISM>,
    pss: Option<PssFrame>,
    inputs: Vec<Vec<Buffer>>,
    layouts: Vec<super::continuation::InputLayout>,
    signatures: Option<MessageSignatures>,
    lengths: Vec<Box<CK_ULONG>>,
    completion: Box<CK_ASYNC_DATA>,
    name: [u8; 32],
    cleanup_diagnostic: Option<crate::error::CleanupDiagnostic>,
    completion_diagnostic: Option<crate::error::CompletionStorage>,
    _metadata: Credit,
}
// SAFETY: native pointers refer only to allocations owned by this installed
// operation. Its mutex and session possession serialize access. Pending buffers
// are neither accessed nor released until completion or successful native close.
unsafe impl Send for MacOperation {}

fn validate_messages(
    messages: &[MacMessage<'_>],
    expected: Option<&[&[u8]]>,
    limits: crate::InputLimits,
    ceiling: crate::CryptoLimits,
) -> Result<()> {
    limits.validate(ceiling, &[])?;
    if messages.is_empty() || messages.len() > limits.maximum_parts {
        return Err(Error::Rejected(crate::RejectionReason::SignatureMessages(
            crate::SignatureMessagesRejection::MessageCount,
        )));
    }
    if expected.is_some_and(|e| e.len() != messages.len()) {
        return Err(Error::Rejected(crate::RejectionReason::SignatureMessages(
            crate::SignatureMessagesRejection::MessageSignatureCount,
        )));
    }
    let mut parts = 0usize;
    let mut bytes = 0usize;
    for message in messages {
        limits.validate(ceiling, message.parts)?;
        parts = parts
            .checked_add(message.parts.len().max(1))
            .ok_or(Error::Rejected(crate::RejectionReason::SignatureMessages(
                crate::SignatureMessagesRejection::MessagePartOverflow,
            )))?;
        for part in message.parts {
            bytes = bytes.checked_add(part.len()).ok_or(Error::Rejected(
                crate::RejectionReason::SignatureMessages(
                    crate::SignatureMessagesRejection::MessageByteOverflow,
                ),
            ))?;
        }
    }
    if let Some(expected) = expected {
        for signature in expected {
            bounds::ck_length(signature.len())?;
            bytes = bytes.checked_add(signature.len()).ok_or(Error::Rejected(
                crate::RejectionReason::SignatureMessages(
                    crate::SignatureMessagesRejection::MessageByteOverflow,
                ),
            ))?;
        }
    }
    if parts > limits.maximum_parts || bytes > limits.maximum_total_bytes {
        return Err(Error::Rejected(crate::RejectionReason::SignatureMessages(
            crate::SignatureMessagesRejection::MessageInputCeiling,
        )));
    }
    Ok(())
}

impl OperationTicket {
    /// Read established native message progress without another native call.
    /// Buffered calls have closed input from their start; queued data is not
    /// counted as consumed, and a pending call is counted as issued only once.
    pub fn message_signature_progress(
        &self,
    ) -> Result<(crate::StreamInputStatus, crate::StreamProgress)> {
        if self.id == 0 {
            return Err(Error::Rejected(crate::RejectionReason::SignatureMessages(
                crate::SignatureMessagesRejection::ConsumedMessageTicket,
            )));
        }
        let state = self.owner.read()?;
        let held = state.operations.get(self.uid)?;
        let operation = held.lock().map_err(|_| Error::Poisoned)?;
        if operation.id != self.id {
            return Err(Error::Rejected(crate::RejectionReason::SignatureMessages(
                crate::SignatureMessagesRejection::StaleMessageTicket,
            )));
        }
        match &operation.body {
            OperationBody::Messages(body) => Ok((body.input.status, body.input.progress)),
            OperationBody::NativeMessages(body) => Ok(body.input_progress()),
            _ => Err(Error::Rejected(crate::RejectionReason::SignatureMessages(
                crate::SignatureMessagesRejection::MessageSignatureTicketRequired,
            ))),
        }
    }
}

// Exact known ownership graph, computed without credit or a native key.
#[derive(Clone, Copy, PartialEq, Eq)]
struct MacStorage {
    metadata: usize,
    results: usize,
    total: usize,
}
impl MacStorage {
    fn for_messages(
        size: usize,
        messages: &[MacMessage<'_>],
        expected: Option<&[&[u8]]>,
        route: MessageRoute,
        pss: bool,
    ) -> Result<Self> {
        if expected.is_some_and(|values| values.len() != messages.len()) {
            return Err(Error::Rejected(crate::RejectionReason::SignatureMessages(
                crate::SignatureMessagesRejection::MessageSignatureCount,
            )));
        }
        let parts = messages
            .iter()
            .try_fold(0usize, |n, m| {
                n.checked_add(if route == MessageRoute::Single {
                    1
                } else {
                    m.parts.len().max(1)
                })
            })
            .ok_or(Error::Rejected(crate::RejectionReason::SignatureMessages(
                crate::SignatureMessagesRejection::MessagePartOverflow,
            )))?;
        let mut total = 0usize;
        for (index, message) in messages.iter().enumerate() {
            let input = message
                .parts
                .iter()
                .try_fold(0usize, |n, part| n.checked_add(part.len()))
                .ok_or(Error::Rejected(crate::RejectionReason::SignatureMessages(
                    crate::SignatureMessagesRejection::MessageByteOverflow,
                )))?;
            if route == MessageRoute::Single {
                bounds::ck_length(input)?;
            } else {
                for part in message.parts {
                    bounds::ck_length(part.len())?;
                }
            }
            let output = expected.map_or(size, |values| values[index].len());
            bounds::ck_length(output)?;
            let layout = continuation::InputLayout::allocation_bytes(message.parts.len())?;
            total = total
                .checked_add(input)
                .and_then(|n| n.checked_add(output))
                .and_then(|n| n.checked_add(layout))
                .ok_or(Error::Rejected(crate::RejectionReason::SignatureMessages(
                    crate::SignatureMessagesRejection::MessageByteOverflow,
                )))?;
        }
        Self::with_buffer_bytes(messages.len(), parts, pss, total)
    }
    fn with_buffer_bytes(rows: usize, parts: usize, pss: bool, buffers: usize) -> Result<Self> {
        let fixed = std::mem::size_of::<MacOperation>()
            + crate::error::CleanupDiagnostic::allocation_bytes()
            + crate::error::CompletionStorage::allocation_bytes()
            + std::mem::size_of::<CK_MECHANISM>()
            + std::mem::size_of::<CK_ASYNC_DATA>()
            + if pss {
                std::mem::size_of::<CK_RSA_PKCS_PSS_PARAMS>()
            } else {
                0
            };
        let metadata = parts
            .checked_mul(std::mem::size_of::<Buffer>())
            .and_then(|n| {
                rows.checked_mul(
                    std::mem::size_of::<Vec<Buffer>>()
                        + std::mem::size_of::<super::continuation::InputLayout>()
                        + std::mem::size_of::<Box<CK_ULONG>>()
                        + std::mem::size_of::<CK_ULONG>(),
                )
                .and_then(|m| n.checked_add(m))
            })
            .and_then(|n| n.checked_add(fixed))
            .ok_or(Error::Rejected(crate::RejectionReason::SignatureMessages(
                crate::SignatureMessagesRejection::MessageMetadataOverflow,
            )))?;
        let results = rows
            .checked_mul(
                std::mem::size_of::<Buffer>()
                    + std::mem::size_of::<Option<crate::NativeMessageRejection>>(),
            )
            .ok_or(Error::Rejected(crate::RejectionReason::SignatureMessages(
                crate::SignatureMessagesRejection::MessageResultMetadata,
            )))?;
        let total = metadata
            .checked_add(results)
            .and_then(|n| n.checked_add(buffers))
            .ok_or(Error::Rejected(crate::RejectionReason::SignatureMessages(
                crate::SignatureMessagesRejection::MessageByteOverflow,
            )))?;
        Ok(Self {
            metadata,
            results,
            total,
        })
    }
}

/// Unbound message storage: preparation cannot consume a key or dispatch C.
pub(super) struct PreparedMac {
    input: super::input::InputState,
    // A completed invalid Verify remains invalid across a native-state copy.
    invalid_seen: bool,
    stream_fragment: Option<Buffer>,
    step: MessageStep,
    activity: NativeActivity,
    kind: CK_MECHANISM_TYPE,
    route: MessageRoute,
    verify: bool,
    size: usize,
    mechanism: Box<CK_MECHANISM>,
    pss: Option<PssFrame>,
    inputs: Vec<Vec<Buffer>>,
    layouts: Vec<continuation::InputLayout>,
    signatures: Option<MessageSignatures>,
    lengths: Vec<Box<CK_ULONG>>,
    completion: Box<CK_ASYNC_DATA>,
    name: [u8; 32],
    cleanup_diagnostic: Option<crate::error::CleanupDiagnostic>,
    completion_diagnostic: Option<crate::error::CompletionStorage>,
    _metadata: Credit,
}
impl PreparedMac {
    pub(super) fn bind(self, key: KeyLease) -> MacOperation {
        let Self {
            input,
            invalid_seen,
            stream_fragment,
            step,
            activity,
            kind,
            route,
            verify,
            size,
            mechanism,
            pss,
            inputs,
            layouts,
            signatures,
            lengths,
            completion,
            name,
            cleanup_diagnostic,
            completion_diagnostic,
            _metadata,
        } = self;
        MacOperation {
            input,
            released: ReleasedInputs::default(),
            stream_fragment,
            key,
            outcome: if invalid_seen {
                MessageOutcome::Invalid
            } else {
                MessageOutcome::Nominal
            },
            step,
            activity,
            kind,
            route,
            verify,
            size,
            mechanism,
            pss,
            inputs,
            layouts,
            signatures,
            lengths,
            completion,
            name,
            cleanup_diagnostic,
            completion_diagnostic,
            _metadata,
        }
    }
}

impl crate::symmetric::memory::RetainedStorage for MessageSignatures {
    fn retain_credits(&self, retained: &mut crate::symmetric::memory::RetainedBytes) -> Result<()> {
        self.bytes.retain_credits(retained)?;
        self._metadata.retain_credits(retained)?;
        Ok(())
    }
}

mod api;
mod operation;
mod progression;
mod resolved_call;
