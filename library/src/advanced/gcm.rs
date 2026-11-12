// SPDX-License-Identifier: Apache-2.0
//! Owned GCM/CCM/stream-AEAD message processing; publish only after the selected native request succeeds.
use super::aead_parameters::{CipherKind, NativeParameters, Selection};
use super::keys::KeyLease;
#[path = "ccm.rs"]
mod ccm;
#[path = "stream_aead.rs"]
mod stream_aead;
use super::{
    asynchronous, drive, poll, reconstruction, record, restoration_keys, spend, AdvancedSession,
    AdvancedSessionMode, MessageRoute, NativeActivity, Operation, OperationBody, OperationPacing,
    OperationProgress, OperationTicket, StateRestoreKeys, ValidationCaptureMode,
};

use crate::module::{SessionEntry, State};
use crate::symmetric::memory::{Budget, Buffer, Credit};
use crate::{bounds, Error, Result, Session};
use fe11_sys::{
    CKF_END_OF_MESSAGE, CKF_MESSAGE_DECRYPT, CKF_MESSAGE_ENCRYPT, CKR_AEAD_DECRYPT_FAILED,
    CKR_ENCRYPTED_DATA_INVALID, CKR_ENCRYPTED_DATA_LEN_RANGE, CKR_OK, CKR_PENDING, CK_ASYNC_DATA,
    CK_FLAGS, CK_MECHANISM, CK_RV, CK_ULONG,
};

use std::sync::atomic::Ordering;
use std::sync::Arc;
mod call;
pub(super) mod checkpoint;
mod extension;
mod initialization;
mod resolved_call;
pub use extension::{DeclaredGcmMessage, DeclaredGcmMessages, GcmMessageExtension};
mod input;
mod output;
mod progression;
mod queued_input;
pub(super) mod result;
pub(super) use input::ReleasedInput;
use result::Disposition;
pub use result::MessageAeadRejection;
pub(super) mod snapshot;
mod stream_api;
mod submission;
mod ticket;
use crate::advanced::record::Family;

use crate::{AeadNonce, MessageInitLayout, SymmetricAlgorithm, SymmetricKey};
pub use ccm::{
    CcmCiphertexts, CcmDecryptMessage, CcmEncryptMessage, CcmMessageCiphertext, CcmPlaintexts,
    CcmRejection,
};
pub use stream_aead::{
    StreamAeadCiphertext, StreamAeadCiphertexts, StreamAeadDecryptMessage,
    StreamAeadEncryptMessage, StreamAeadPlaintexts, StreamAeadRejection,
};
pub use stream_api::{
    MessageAeadInit, MessageAeadInput, MessageAeadMechanism, MessageAeadParameters,
};
pub(crate) use ticket::Diagnostics as AeadMessageDiagnostics;

/// One AES-GCM plaintext message with explicit nonce origin and AAD.
pub struct GcmEncryptMessage<'a> {
    /// Native random generation or caller-owned uniqueness policy.
    pub nonce: AeadNonce,
    /// Authenticated context, charged to caller-selected input limits.
    pub aad: &'a [u8],
    /// Ordered plaintext parts; an empty list means an empty message.
    pub parts: &'a [&'a [u8]],
}
/// One AES-GCM ciphertext message with the selected separate tag.
pub struct GcmDecryptMessage<'a> {
    /// Exact IV and tag-bit selection used for encryption. Message decryption
    /// ignores generator/fixed-bit fields and passes their ABI values unchanged.
    pub nonce: AeadNonce,
    /// Exact authenticated context.
    pub aad: &'a [u8],
    /// Ciphertext parts only; the tag is not appended to these bytes.
    pub parts: &'a [&'a [u8]],
    /// Exactly ceil(tag_bits / 8) tag bytes.
    pub tag: &'a [u8],
}
/// Borrowed complete message ciphertext and its public parameters.
pub struct GcmCiphertext<'a> {
    /// Ciphertext without the tag.
    pub ciphertext: &'a [u8],
    /// Nonce actually used by the completed native operation.
    pub nonce: &'a [u8],
    /// Authentication tag returned by the completed native operation.
    pub tag: &'a [u8],
    /// Exact native authentication-tag length, in bits.
    pub tag_bits: u64,
}
struct Output {
    disposition: Disposition,
    bytes: Buffer,
    nonce: Buffer,
    tag: Buffer,
    tag_bits: u64,
}
struct Outputs {
    entries: Vec<Output>,
    init: MessageInitLayout,
    _credit: Credit,
}
/// Owned ciphertext batch; nonce and tag remain associated with each message.
pub struct GcmCiphertexts(Outputs);

#[doc = include_str!("../../docs/api/advanced/gcm/GcmPlaintexts.md")]
pub struct GcmPlaintexts(Outputs);

/// Exact native rejection and terminal cleanup observations, without plaintext.
/// An inactive cleanup is not a successful decryption or a conformance claim.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct GcmRejection {
    /// Native message function that refused the ciphertext.
    pub function: &'static str,
    /// Exact rejection: AEAD_DECRYPT_FAILED, ENCRYPTED_DATA_INVALID or LEN_RANGE.
    pub code: u64,
    /// Exact MessageDecryptFinal result: OK or OPERATION_NOT_INITIALIZED.
    /// The latter confirms no process remains after the rejection; other
    /// cleanup failures remain errors requiring explicit session cleanup.
    pub cleanup_code: u64,
}
#[derive(Clone)]
struct Request<'a> {
    nonce: Selection,
    aad: &'a [u8],
    parts: &'a [&'a [u8]],
    tag: Option<&'a [u8]>,
}

/// Credits follow the owners that release the corresponding allocations.
/// Byte buffers and logical fragment boundaries split from the remaining pool.
struct AeadStoragePlan {
    owner: usize,
    results: usize,
    shared_init: usize,
    total: usize,
}

/// One row's scalar dimensions, shared by borrowed records and normal requests.
struct RowDimensions {
    parts: usize,
    fragments: usize,
    data: usize,
    aad: usize,
    nonce: usize,
    tag: usize,
    expected_tag: usize,
    retained: usize,
    generated: usize,
}

enum Requests<'a> {
    StreamEncrypt {
        kind: CipherKind,
        messages: &'a [StreamAeadEncryptMessage<'a>],
    },
    StreamDecrypt {
        kind: CipherKind,
        messages: &'a [StreamAeadDecryptMessage<'a>],
    },
    Encrypt(&'a [GcmEncryptMessage<'a>]),
    Decrypt(&'a [GcmDecryptMessage<'a>]),
    CcmEncrypt(&'a [CcmEncryptMessage<'a>]),
    CcmDecrypt(&'a [CcmDecryptMessage<'a>]),
    Prepared {
        kind: CipherKind,
        decrypt: bool,
        entries: &'a [Request<'a>],
    },
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum AeadStep {
    Output(output::Pending),
    Init,
    Ready,
    Receive(usize),
    StreamUpdate(usize),
    StreamLast(usize),
    Single(usize),
    Begin(usize),
    Next(usize, usize),
    Finish,
    Done,
    Failed,
}
#[derive(Clone, Copy, PartialEq, Eq)]
enum CompletionSource {
    Call,
    Observation,
}

struct Frame {
    params: Box<NativeParameters>,
    aad: Buffer,
    inputs: Vec<Buffer>,
    retirement: Option<queued_input::Pool>,
    layout: super::continuation::InputLayout,
    length: Box<CK_ULONG>,
    expected: usize,
    used: usize,
    // Exact accepted text for new messages; absent for imported older records.
    // The parent still accounts for new deltas when prior row history is absent.
    accepted_input: Option<u128>,
    origin: Selection,
    observed_nonce: GeneratedNonce,
    expected_tag: Option<Buffer>,
}
// Allocate before dispatch so observing native output cannot fail for budget.
enum GeneratedNonce {
    NotGenerated,
    Awaiting(Buffer),
    Observed(Buffer),
}

// The shared targets outlive every message, including native pointers retained
// from Init. Per-message output copies never replace these allocations.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum InitReference {
    Seed,
    Message(usize),
}

// The seed describes only Init. It is retained independently of submitted
// messages, so a process with shared parameters can start and end without data.
struct InitializationSeed {
    origin: Selection,
    declared_length: usize,
    expected_tag: Option<Buffer>,
}

enum InitBinding {
    WithoutParameters,
    Declared(extension::DeclaredInit),
    Shared {
        params: Box<NativeParameters>,
        nonce: Buffer,
        tag: Buffer,
        prepared_message: InitReference,
        seed: Option<InitializationSeed>,
        _metadata: Credit,
    },
}

enum AeadOutcome {
    Nominal,
    Closing {
        diagnostic: crate::error::CleanupDiagnostic,
        rejection: Option<GcmRejection>,
    },
    Rejected(GcmRejection),
}

// Every constructor installs outputs for all frames. Only result() removes
// them, after Done; dispatch and completion never run after publication.
// Caller-fed input remains installed for the owner lifetime: only its fragment
// moves on an established return. Submission preflight checks that fragment
// before any native call; retained asynchronous operands keep the same storage.
// Cleanup consumes its diagnostic once and moves directly to Finish/Closing;
// every cleanup outcome is terminal, including failed local validation.
pub(super) struct AeadMessageOperation {
    key: KeyLease,
    observer: ticket::Observer,
    input: Option<input::Input>,
    retired_fragment: Option<Buffer>,
    retired_output: Option<Buffer>,
    retired_queued: queued_input::Retired,
    kind: CipherKind,
    route: MessageRoute,
    decrypt: bool,
    outcome: AeadOutcome,
    step: AeadStep,
    activity: NativeActivity,
    mechanism: Box<CK_MECHANISM>,
    init: InitBinding,
    frames: Vec<Frame>,
    outputs: Option<Outputs>,
    restart_at: usize,
    completion: Box<CK_ASYNC_DATA>,
    name: [u8; 32],
    cleanup_diagnostic: Option<crate::error::CleanupDiagnostic>,
    return_diagnostic: Option<crate::error::CompletionStorage>,
    _metadata: Credit,
}
// An unpublished native graph with no key permit and no authority to dispatch.
// Binding transfers only owned stable storage after final key possession.
pub(super) struct PreparedAead {
    input: Option<input::Input>,
    kind: CipherKind,
    route: MessageRoute,
    decrypt: bool,
    outcome: AeadOutcome,
    step: AeadStep,
    activity: NativeActivity,
    mechanism: Box<CK_MECHANISM>,
    init: InitBinding,
    frames: Vec<Frame>,
    outputs: Option<Outputs>,
    restart_at: usize,
    completion: Box<CK_ASYNC_DATA>,
    name: [u8; 32],
    cleanup_diagnostic: Option<crate::error::CleanupDiagnostic>,
    return_diagnostic: Option<crate::error::CompletionStorage>,
    _metadata: Credit,
}

// SAFETY: pointed-to parameters, IV/tag, bytes and lengths live in stable owned
// allocations installed before native Init. Session possession and the operation
// mutex serialize access; pending storage remains untouched until completion.
unsafe impl Send for AeadMessageOperation {}
#[derive(Clone, Copy)]
pub(super) enum MessageKey<'a> {
    Aes(&'a SymmetricKey),
    Native(&'a crate::NativeObjectRef),
}

#[derive(Clone, Copy)]
enum InputAccounting {
    Batch,
    // Existing convenience APIs charge plaintext/ciphertext and AAD. Their
    // separate nonce/tag are still fully charged to the physical memory graph.
    LegacySingle,
}

mod api;
mod cleanup;
mod completion;
mod operation;
mod preparation;
mod rejoin;
mod storage;
mod validation;
use completion::complete_single_message;
use completion::observe_generated_nonce;
use preparation::start_shared_messages;
use storage::prepare_message_storage;
use storage::storage_sum;
use storage::validate_binding_storage;
pub(super) use validation::check_message_key;
use validation::message_key;
