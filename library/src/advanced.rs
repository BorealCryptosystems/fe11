// SPDX-License-Identifier: Apache-2.0
//! Owned advanced operations. The module registry, not a caller stack, retains
//! every native allocation across a pending return or an abandoned ticket.
//!
//! Current sessions make synchronous PKCS#11 calls. Cooperative pacing yields
//! between those calls so the application can drive a retained local operation;
//! it creates no worker, timer or native asynchronous transaction. The native
//! PKCS#11 3.2 native asynchronous mode is unsupported and opening it is rejected before C.
//! An unexpected PENDING from a synchronous module remains a retention and
//! quarantine condition, never evidence that asynchronous mode was enabled.
//!
//! GetSessionValidationFlags is a current, explicitly selected observation. Its
//! function-table placement does not make it part of native asynchronous mode.
//! Neither an observed flag nor an absent observation certifies a cryptographic
//! result or a deployment. Typed local reasons describe library preconditions;
//! native PKCS#11 status codes remain distinct in the enclosing error.

use crate::{module::Inner, Error, Result, Session, TokenContext};

use fe11_sys::{CKR_PENDING, CK_RV};
use std::sync::{atomic::Ordering, Arc};
pub(crate) mod cipher;
pub(crate) mod digest;
mod fragment_queue;
mod fragment_retirement;
mod input;
pub use input::{StreamInputStatus, StreamProgress};
mod recover;
pub(crate) mod signature;
pub use cipher::CipherStreamChunk;
pub use cipher::{
    AesBufferRequest, AesOutputPlan, CipherBufferRequest, CipherKeyReference, CipherOutputPlan,
};
pub use recover::{RecoverMechanism, RecoverOutputPlan, RecoveryBufferRequest, RecoveryOutput};
pub use signature::{SignatureBufferRequest, SignatureOutputPlan};

use digest::{drive_digest, function, DigestOperation, DigestSelection, Step};
mod messages;
mod native_messages;
pub(crate) use native_messages::execute as execute_native_message;
pub(crate) use native_messages::Invocation as NativeMessageInvocation;
pub use native_messages::{NativeMessageRejection, NativeMessageResults};
mod operation;
mod ownership;
pub use messages::{
    MacMessage, MessageRoute, MessageSignatures, MessageVerificationDetails, SignatureMessage,
};
use operation::{drive, NativeActivity, Operation, OperationBody};
mod admission;
mod key_roles;
mod key_storage;
mod keys;
mod lease;
mod ledger;
pub(crate) use ledger::{init_reader_borrow, InitReaderBorrow};
pub(crate) use ledger::{FinalizedOperations, Ledger};
mod output_preparation;
mod poll;
pub(crate) use poll::PollDiagnostics;
mod preparation;
mod record_preparation;
pub(crate) use preparation::{
    context as preparation_context, reserve_new_at_epoch as reserve_preparation_at_epoch,
    reserve_new_while as reserve_preparation_while,
    reserve_new_while_in as reserve_preparation_while_in,
    reserve_new_with_progress as reserve_preparation_with_progress,
};
pub(crate) mod progress;
pub(crate) use admission::{
    aes_kek_synchronous, agreement_pair_synchronous, classical_pair_synchronous,
    derivation_base_synchronous, find_kem_synchronous, generate_kem_synchronous,
    introduced_symmetric_synchronous, pqc_pair_synchronous, rsa_transport_synchronous,
    symmetric_synchronous, transport_signing_synchronous, verification_synchronous,
};
use lease::TokenLease;
mod aead_parameters;
mod asynchronous;
mod authentication;
mod cancellation;
mod capture_layout;
mod capture_parts;
mod capture_preparation;
mod detachment;
mod dual;
mod gcm;
pub(crate) use gcm::AeadMessageDiagnostics;
mod rejoin;
mod state_io;
mod validation;
pub use detachment::{DetachedOperation, DetachmentProgress};
pub use rejoin::{RejoinFailure, RejoinKeys, RejoinProgress, RejoinTicket};
mod continuation;
mod record;
mod recovery;
mod terminal;
pub use dual::DualRecoveryRecord;
pub use recovery::{CcmRecoveryRecord, GcmRecoveryRecord, StreamAeadRecoveryRecord};
mod record_import;
pub use record_import::{CallerAssertedAuthenticatedRecord, ParsedRecord, RecordLimits};
mod reconstruction;
mod restoration;
mod restoration_keys;
mod restoration_transfer;
mod saved_state;
pub use restoration::{StateRestoreFailure, StateRestoreProgress, StateRestoreTicket};
pub use restoration_keys::{
    StateKeyEncoding, StateKeyReference, StateRestoreKey, StateRestoreKeys,
};
pub use saved_state::{SavedOperationState, StateCaptureProgress, StateProvenance};
mod detached_persistence;
pub use detached_persistence::{DetachedExportFailure, DetachedOperationRecord};
mod persistence;
pub use cancellation::{CancellationFlags, CancellationProgress};
pub use dual::{
    DigestPlaintext, DualAuthenticatedPlaintext, DualCipher, DualCiphertext, DualMac, DualResult,
    UnauthenticatedPlaintext,
};
pub use gcm::{
    CcmCiphertexts, CcmDecryptMessage, CcmEncryptMessage, CcmMessageCiphertext, CcmPlaintexts,
    CcmRejection, DeclaredGcmMessage, DeclaredGcmMessages, GcmCiphertext, GcmCiphertexts,
    GcmDecryptMessage, GcmEncryptMessage, GcmMessageExtension, GcmPlaintexts, GcmRejection,
    MessageAeadInit, MessageAeadInput, MessageAeadMechanism, MessageAeadParameters,
    MessageAeadRejection, StreamAeadCiphertext, StreamAeadCiphertexts, StreamAeadDecryptMessage,
    StreamAeadEncryptMessage, StreamAeadPlaintexts, StreamAeadRejection,
};
pub use persistence::{NativeStateRecord, StateExportFailure};
pub use validation::{ValidationCaptureMode, ValidationObservation, ValidationReport};

/// Immutable native execution mode, selected when opening a session.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum AdvancedSessionMode {
    /// Native calls complete synchronously; unexpected PENDING withdraws the module.
    Synchronous,
    /// Reserved for the deferred native PKCS#11 3.2 asynchronous protocol.
    /// Opening this mode is refused before native dispatch. Cooperative pacing
    /// of synchronous calls is available independently.
    Asynchronous,
}
/// An advanced session owns its ordinary session; asynchronous sessions cannot
/// escape through the synchronous session API.
pub struct AdvancedSession {
    pub(crate) session: Session,
    pacing: OperationPacing,
    validation_capture: ValidationCaptureMode,
}
/// Explicit scheduling of the local operation plan, independent of native
/// synchronous/asynchronous mode. No thread, timer or retry is introduced.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum OperationPacing {
    /// Run successive synchronous steps until completion or native Pending.
    Eager,
    /// At most one native dispatch per start/poll, including AsyncComplete.
    /// This leaves real synchronous operations available between their steps.
    Cooperative,
}
impl OperationPacing {
    fn budget(self) -> usize {
        if self == Self::Cooperative {
            1
        } else {
            usize::MAX
        }
    }
}
fn spend(remaining: &mut usize) -> bool {
    if *remaining == 0 {
        false
    } else {
        *remaining -= 1;
        true
    }
}
fn unfinished(pending: bool) -> OperationProgress {
    if pending {
        OperationProgress::Pending
    } else {
        OperationProgress::Ready
    }
}
/// Single-use observation capability. Dropping it does not cancel native work.
/// Use the owning session's explicit close or cancellation for abandoned work.
pub struct OperationTicket {
    owner: Arc<Inner>,
    uid: u64,
    id: u64,
    validation_report: Option<ValidationReport>,
    state_provenance: Option<StateProvenance>,
}
impl OperationTicket {
    /// Observe the established progress of an incremental digest without a
    /// native call. Other operation families do not synthesize digest counters.
    pub fn digest_progress(&self) -> Result<(StreamInputStatus, StreamProgress)> {
        if self.id == 0 {
            return Err(Error::Rejected(crate::RejectionReason::OperationOwnership(
                crate::OperationOwnershipRejection::ConsumedOperationTicket,
            )));
        }
        let state = self.owner.read()?;
        let slot = state.operations.get(self.uid)?;
        let operation = slot.lock().map_err(|_| Error::Poisoned)?;
        if operation.id != self.id {
            return Err(Error::Rejected(crate::RejectionReason::OperationOwnership(
                crate::OperationOwnershipRejection::StaleOperationTicket,
            )));
        }
        match &operation.body {
            OperationBody::Digest(body) => Ok((body.input.status, body.input.progress)),
            _ => Err(Error::Rejected(crate::RejectionReason::OperationOwnership(
                crate::OperationOwnershipRejection::DigestTicketRequired,
            ))),
        }
    }

    /// Recover already published generation outputs without polling native code
    /// or reading attributes. A failed or pending observation does not consume
    /// these references. The ticket retains any outstanding native buffers until
    /// explicit completion, cancellation or session closure.
    pub fn created_objects(&self) -> Result<Option<crate::CreatedObjectSet>> {
        if self.id == 0 {
            return Err(Error::Rejected(crate::RejectionReason::OperationOwnership(
                crate::OperationOwnershipRejection::ConsumedOperationTicket,
            )));
        }
        let state = self.owner.read()?;
        let slot = state.operations.get(self.uid)?;
        let operation = slot.lock().map_err(|_| Error::Poisoned)?;
        if operation.id != self.id {
            return Err(Error::Rejected(crate::RejectionReason::OperationOwnership(
                crate::OperationOwnershipRejection::StaleOperationTicket,
            )));
        }
        match &operation.body {
            OperationBody::Admission(body) => body.created_objects(&self.owner),
            _ => Ok(None),
        }
    }
}
/// Outcome of explicit advanced-session cleanup. Pending retains every resource
/// until a subsequent explicit observation establishes native completion.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum AdvancedCloseStatus {
    /// Native session closure has completed.
    Complete,
    /// Native closure remains in progress; no resource release is inferred.
    Pending,
}
pub(crate) fn close_status(
    result: Result<()>,
    mode: AdvancedSessionMode,
) -> Result<AdvancedCloseStatus> {
    match result {
        Ok(()) => Ok(AdvancedCloseStatus::Complete),
        Err(Error::Native {
            function: "C_CloseSession",
            code,
            ..
        }) if code == CKR_PENDING as u64 && mode == AdvancedSessionMode::Asynchronous => {
            Ok(AdvancedCloseStatus::Pending)
        }
        Err(error) => Err(error),
    }
}
/// Descriptive views of generated objects. Native references remain available
/// separately when construction of one of these views fails.
pub enum GeneratedObjects {
    /// Completed native observations for SymmetricKey.
    SymmetricKey(crate::SymmetricKey),
    /// Completed native observations for IntroducedSymmetricKey.
    IntroducedSymmetricKey(crate::IntroducedSymmetricKey),
    /// Completed native observations for AesKeyEncryptionKey.
    AesKeyEncryptionKey(crate::AesKeyEncryptionKey),
    /// Completed native observations for ClassicalKeyPair.
    ClassicalKeyPair(crate::ClassicalKeyPair),
    /// Completed native observations for KemKeyPair.
    KemKeyPair(crate::KemKeyPair),
    /// Completed native observations for PqcKeyPair.
    PqcKeyPair(crate::PqcKeyPair),
    /// Completed native observations for AgreementKeyPair.
    AgreementKeyPair(crate::AgreementKeyPair),
    /// Completed native observations for MontgomeryKeyPair.
    MontgomeryKeyPair(crate::MontgomeryKeyPair),
    /// Completed native observations for TransportAgreementKeyPair.
    TransportAgreementKeyPair(crate::TransportAgreementKeyPair),
    /// Completed native observations for TransportSigningKeyPair.
    TransportSigningKeyPair(crate::TransportSigningKeyPair),
    /// Completed native observations for RsaKeyEncryptionPair.
    RsaKeyEncryptionPair(crate::RsaKeyEncryptionPair),
    /// Completed native observations for AgreementKey.
    AgreementKey(crate::AgreementKey),
    /// Completed native observations for MontgomeryKey.
    MontgomeryKey(crate::MontgomeryKey),
    /// Completed native observations for HkdfKey.
    HkdfKey(crate::HkdfKey),
    /// Completed native observations for IntroducedAgreementKey.
    IntroducedAgreementKey(crate::IntroducedAgreementKey),
}
impl GeneratedObjects {
    pub(crate) fn from_progress(value: OperationProgress) -> Result<Self> {
        match value {
            OperationProgress::SymmetricKey(value) => Ok(Self::SymmetricKey(value)),
            OperationProgress::IntroducedSymmetricKey(value) => {
                Ok(Self::IntroducedSymmetricKey(value))
            }
            OperationProgress::AesKeyEncryptionKey(value) => Ok(Self::AesKeyEncryptionKey(value)),
            OperationProgress::ClassicalKeyPair(value) => Ok(Self::ClassicalKeyPair(value)),
            OperationProgress::KemKeyPair(value) => Ok(Self::KemKeyPair(value)),
            OperationProgress::PqcKeyPair(value) => Ok(Self::PqcKeyPair(value)),
            OperationProgress::AgreementKeyPair(value) => Ok(Self::AgreementKeyPair(value)),
            OperationProgress::MontgomeryKeyPair(value) => Ok(Self::MontgomeryKeyPair(value)),
            OperationProgress::TransportAgreementKeyPair(value) => {
                Ok(Self::TransportAgreementKeyPair(value))
            }
            OperationProgress::TransportSigningKeyPair(value) => {
                Ok(Self::TransportSigningKeyPair(value))
            }
            OperationProgress::RsaKeyEncryptionPair(value) => Ok(Self::RsaKeyEncryptionPair(value)),
            OperationProgress::AgreementKey(value) => Ok(Self::AgreementKey(value)),
            OperationProgress::MontgomeryKey(value) => Ok(Self::MontgomeryKey(value)),
            OperationProgress::HkdfKey(value) => Ok(Self::HkdfKey(value)),
            OperationProgress::IntroducedAgreementKey(value) => {
                Ok(Self::IntroducedAgreementKey(value))
            }
            _ => Err(Error::Rejected(crate::RejectionReason::OperationOwnership(
                crate::OperationOwnershipRejection::GenerationDescriptiveResultKind,
            ))),
        }
    }
    pub(crate) fn into_progress(self) -> OperationProgress {
        match self {
            Self::SymmetricKey(value) => OperationProgress::SymmetricKey(value),
            Self::IntroducedSymmetricKey(value) => OperationProgress::IntroducedSymmetricKey(value),
            Self::AesKeyEncryptionKey(value) => OperationProgress::AesKeyEncryptionKey(value),
            Self::ClassicalKeyPair(value) => OperationProgress::ClassicalKeyPair(value),
            Self::KemKeyPair(value) => OperationProgress::KemKeyPair(value),
            Self::PqcKeyPair(value) => OperationProgress::PqcKeyPair(value),
            Self::AgreementKeyPair(value) => OperationProgress::AgreementKeyPair(value),
            Self::MontgomeryKeyPair(value) => OperationProgress::MontgomeryKeyPair(value),
            Self::TransportAgreementKeyPair(value) => {
                OperationProgress::TransportAgreementKeyPair(value)
            }
            Self::TransportSigningKeyPair(value) => {
                OperationProgress::TransportSigningKeyPair(value)
            }
            Self::RsaKeyEncryptionPair(value) => OperationProgress::RsaKeyEncryptionPair(value),
            Self::AgreementKey(value) => OperationProgress::AgreementKey(value),
            Self::MontgomeryKey(value) => OperationProgress::MontgomeryKey(value),
            Self::HkdfKey(value) => OperationProgress::HkdfKey(value),
            Self::IntroducedAgreementKey(value) => OperationProgress::IntroducedAgreementKey(value),
        }
    }
}
/// Result of an explicit progress observation. Pending never exposes native output.
pub enum OperationProgress {
    /// Completed creation with native owners and an independent descriptive result.
    CreatedObjects(crate::CreatedObjects<GeneratedObjects>),
    /// Complete standalone block-cipher ciphertext, with no implicit authentication.
    CipherEncrypted(crate::Ciphertext),
    /// Complete classic AEAD ciphertext, with appended tag and exact nonce.
    ClassicAeadEncrypted(crate::ClassicAeadCiphertext),
    /// Plaintext published only after native terminal verification succeeds.
    ClassicAeadDecrypted(crate::AeadPlaintext),
    /// Complete standalone block-cipher plaintext from a non-authenticating mode.
    CipherDecrypted(crate::UnauthenticatedCipherPlaintext),
    /// A native block-cipher size query or insufficient buffer requires a caller choice.
    /// No output bytes are published; the ticket and native operation remain live.
    CipherBufferRequired(CipherBufferRequest),
    /// Native recovery call retained its operation and requests caller storage.
    RecoveryBufferRequired(RecoveryBufferRequest),
    /// The exact signature call is retained until replacement storage is supplied.
    SignatureBufferRequired(SignatureBufferRequest),
    /// Successful native signature and explicitly declared auxiliary outputs.
    NativeSignature(crate::ExtensionResult),
    /// Native digest and declared auxiliary parameter outputs.
    ExtensionDigest(crate::ExtensionResult),
    /// Native extension ciphertext and declared auxiliary parameter outputs.
    ExtensionEncrypted(crate::ExtensionResult),
    /// Raw native extension plaintext; no local authenticity claim is added.
    ExtensionDecrypted(crate::ExtensionResult),
    /// Successful native verification and explicitly declared auxiliary outputs.
    NativeVerification(crate::ExtensionResult),
    /// Complete signature from C_SignRecover.
    RecoveredSignature(RecoveryOutput),
    /// Message published only after successful C_VerifyRecover.
    RecoveredMessage(RecoveryOutput),
    /// A selected or newly generated key admitted in this session.
    /// Observations and refusal rules are those explicitly selected by the
    /// caller; this result does not imply a mandatory protection policy.
    SymmetricKey(crate::SymmetricKey),
    /// A generated or selected symmetric key with its explicit introduction report.
    IntroducedSymmetricKey(crate::IntroducedSymmetricKey),
    /// A dedicated AES wrapping/unwrapping key with its admission observations.
    AesKeyEncryptionKey(crate::AesKeyEncryptionKey),
    /// One existing classical public key, bound to the supplied canonical SPKI.
    VerificationKey(crate::VerificationKey),
    /// Selected or generated classical pair with completed caller-selected observations.
    /// Its observations do not establish possession or public/private correspondence.
    ClassicalKeyPair(crate::ClassicalKeyPair),
    /// Native ML-KEM generation with two admitted references and canonical public material.
    /// Generation does not establish a signature or encapsulation possession proof.
    KemKeyPair(crate::KemKeyPair),
    /// Generated PQC pair and the exact optional possession-proof observation.
    PqcKeyPair(crate::PqcKeyPair),
    /// Generated Weierstrass agreement pair with selected native history evidence.
    AgreementKeyPair(crate::AgreementKeyPair),
    /// Generated Montgomery pair retaining its exact native domain and public bytes.
    MontgomeryKeyPair(crate::MontgomeryKeyPair),
    /// Generated agreement pair with explicit transport view and origin/history report.
    TransportAgreementKeyPair(crate::TransportAgreementKeyPair),
    /// Generated signing pair with explicit export view, history and witness report.
    TransportSigningKeyPair(crate::TransportSigningKeyPair),
    /// Native RSA transport pair with linked public components and admission reports.
    RsaKeyEncryptionPair(crate::RsaKeyEncryptionPair),
    /// Selected existing Weierstrass derivation base with caller-selected evidence.
    AgreementKey(crate::AgreementKey),
    /// Selected existing Montgomery base with its exact native domain.
    MontgomeryKey(crate::MontgomeryKey),
    /// Selected or generated HKDF base with its exact native type and length.
    HkdfKey(crate::HkdfKey),
    /// Selected introduced agreement key, with explicit wrapping/operation view.
    IntroducedAgreementKey(crate::IntroducedAgreementKey),
    /// The local plan yielded between completed native calls. No native call
    /// is pending; an explicit poll may submit its next step.
    Ready,
    /// The current native step still owns its buffers.
    Pending,
    /// Completed native dual operation, with explicit plaintext authenticity.
    Dual(DualResult),
    /// Complete AES-GCM message ciphertexts and their separate nonces/tags.
    GcmCiphertexts(GcmCiphertexts),
    /// Caller-declared GCM-compatible results; provenance remains explicit.
    DeclaredGcmMessages(DeclaredGcmMessages),
    /// Complete ChaCha/Salsa-Poly1305 ciphertext batch with separate tags.
    StreamAeadCiphertexts(StreamAeadCiphertexts),
    /// Stream-AEAD results after process Final; inspect each entry's rejection.
    /// Only successful messages expose plaintext.
    StreamAeadPlaintexts(StreamAeadPlaintexts),
    /// Exact native stream-AEAD rejection and cleanup codes, without plaintext.
    StreamAeadInvalidCiphertext(StreamAeadRejection),
    /// GCM results after process Final; inspect rejection() and tag_bits().
    /// Refused messages never expose plaintext.
    GcmPlaintexts(GcmPlaintexts),
    /// Complete CCM message batch with separate MACs and associated nonces.
    CcmCiphertexts(CcmCiphertexts),
    /// CCM results after process Final; inspect each entry's rejection.
    /// Only successful messages expose plaintext.
    CcmPlaintexts(CcmPlaintexts),
    /// CCM authentication refusal, preserving native message and cleanup codes.
    CcmInvalidCiphertext(CcmRejection),
    /// Native authenticated decryption rejected the ciphertext, AAD or tag.
    /// No plaintext from any message in the batch is published.
    InvalidCiphertext(GcmRejection),
    /// Completed message signatures, published only after MessageSignFinal.
    MessageSignatures(MessageSignatures),
    /// Completed native message verification. Invalid is distinct from a
    /// provider error and is never a successful authentication assertion.
    MessageVerification(crate::Verification),
    /// Explicitly finished typed verification with operationally refused rows.
    /// Preserves their native errors; does not invent an aggregate validity verdict.
    MessageVerificationDetails(MessageVerificationDetails),
    /// Generic message signatures or verification verdicts, with all declared
    /// parameter outputs, published only after explicit parent Final.
    NativeMessages(NativeMessageResults),
    /// Completed native digest with the algorithm explicitly selected at submission.
    Digest(crate::PreparedDigest),
    /// Completed native fixed-length digest, independent of signing profiles.
    NativeDigest(crate::NativeDigest),
    /// Native digest and its explicitly requested validation observation.
    NativeDigestWithValidation {
        /// Completed result with its exact native algorithm.
        digest: crate::NativeDigest,
        /// Native flags, not a certification assertion.
        validation: SessionValidation,
    },
    /// Typed digest and its explicitly requested native validation observation.
    DigestWithValidation {
        /// Completed digest and its exact algorithm.
        digest: crate::PreparedDigest,
        /// Native last-operation flags, not a certification assertion.
        validation: SessionValidation,
    },
    /// Completed SHA-256. The bytes are copied only after native completion.
    Sha256([u8; 32]),
    /// Digest and its explicitly requested native validation observation.
    Sha256WithValidation {
        /// Completed digest.
        digest: [u8; 32],
        /// Exact flags or absence of the selected interface's function.
        validation: SessionValidation,
    },
}
/// Native last-operation indicator; this is not a FIPS certification assertion.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SessionValidation {
    /// The explicitly selected interface provides no validation function.
    Unavailable,
    /// Exact native flags. Zero is a reported value, not absence of an indicator.
    Reported(u64),
}

impl Session {
    /// Consume a synchronous session without changing its UID or admitted keys.
    /// No asynchronous session is exposed or converted back by this API.
    pub fn into_advanced(self) -> Result<AdvancedSession> {
        {
            let _access = self.access()?;
            if self.entry.mode != AdvancedSessionMode::Synchronous {
                return Err(Error::Rejected(crate::RejectionReason::OperationOwnership(
                    crate::OperationOwnershipRejection::AsynchronousLegacyConversion,
                )));
            }
        }
        Ok(AdvancedSession {
            session: self,
            pacing: OperationPacing::Eager,
            validation_capture: ValidationCaptureMode::Disabled,
        })
    }
}
impl TokenContext {
    /// Open in the requested mode without negotiation or fallback after refusal.
    /// Login/logout use a separately held synchronous administrative session.
    pub fn open_advanced_session(
        &self,
        read_write: bool,
        mode: AdvancedSessionMode,
    ) -> Result<AdvancedSession> {
        if mode == AdvancedSessionMode::Asynchronous {
            return Err(Error::Rejected(crate::RejectionReason::OperationOwnership(
                crate::OperationOwnershipRejection::NativeAsynchronousExecutionUnavailable,
            )));
        }
        Ok(AdvancedSession {
            session: self.open_session_mode(read_write, mode)?,
            pacing: OperationPacing::Eager,
            validation_capture: ValidationCaptureMode::Disabled,
        })
    }
    /// Open an advanced owner with the same owned Notify contract as Session.
    /// This does not enable the deferred native asynchronous execution mode.
    pub fn open_advanced_session_with_notify(
        &self,
        read_write: bool,
        mode: AdvancedSessionMode,
        notify: crate::NotifyHandler,
    ) -> Result<AdvancedSession> {
        if mode == AdvancedSessionMode::Asynchronous {
            return Err(Error::Rejected(crate::RejectionReason::OperationOwnership(
                crate::OperationOwnershipRejection::NativeAsynchronousExecutionUnavailable,
            )));
        }
        Ok(AdvancedSession {
            session: self.open_session_mode_with_notify(read_write, mode, Some(notify))?,
            pacing: OperationPacing::Eager,
            validation_capture: ValidationCaptureMode::Disabled,
        })
    }
}
impl AdvancedSession {
    /// Configure local session possession without changing a native operation.
    pub fn set_admission(&mut self, admission: crate::SessionAdmission) {
        self.session.set_admission(admission);
    }

    /// Current session override, or the calling thread's inherited admission.
    pub fn admission(&self) -> crate::SessionAdmission {
        self.session.admission()
    }

    /// Remove the override and use the calling scope, or Immediate outside a scope.
    pub fn inherit_admission(&mut self) {
        self.session.inherit_admission();
    }

    /// Observe local Notify diagnostics without a native call.
    pub fn notify_diagnostics(&self) -> Option<crate::NotifyDiagnostics> {
        self.session.notify_diagnostics()
    }
    /// Select local pacing only while this session has no tracked operation.
    /// This cannot change the session's native execution mode.
    pub fn set_pacing(&mut self, pacing: OperationPacing) -> Result<()> {
        {
            let _access = self.session.advanced_access()?;
            if self
                .session
                .entry
                .advanced_operation
                .load(Ordering::Acquire)
                != 0
            {
                return Err(Error::Busy(crate::BusyReason::OperationOwnership(
                    crate::OperationOwnershipBusy::AdvancedOperation,
                )));
            }
        }
        self.pacing = pacing;
        Ok(())
    }
    /// Native execution mode, fixed for the lifetime of this session.
    pub fn mode(&self) -> AdvancedSessionMode {
        self.session.entry.mode
    }
    /// Start a bounded native multipart SHA-256 operation. All input bytes are
    /// owned before Init; no hash substitution or implicit polling is performed.
    /// Retrieve completion exactly once with poll, even for synchronous sessions.
    pub fn digest_sha256(
        &self,
        parts: &[&[u8]],
        limits: crate::InputLimits,
    ) -> Result<OperationTicket> {
        let mut retired_owner = None;
        self.start_digest(
            parts,
            limits,
            DigestSelection::LegacySha256,
            false,
            &mut retired_owner,
        )
    }
    /// Capture CKS_LAST_VALIDATION_OK after this digest, under the same session
    /// ownership and before publication. No capability probe or fallback occurs.
    /// A native refusal remains an error; an absent function is Unavailable.
    pub fn digest_sha256_with_validation(
        &self,
        parts: &[&[u8]],
        limits: crate::InputLimits,
    ) -> Result<OperationTicket> {
        let mut retired_owner = None;
        self.start_digest(
            parts,
            limits,
            DigestSelection::LegacySha256,
            true,
            &mut retired_owner,
        )
    }
    /// Start native multipart hashing with an explicit typed algorithm.
    /// The module decides support at C_DigestInit. Inputs remain owned until
    /// completion or cleanup; there is no software substitution or implicit poll.
    /// Poll returns OperationProgress::Digest exactly once on success.
    pub fn digest(
        &self,
        algorithm: crate::HashAlgorithm,
        parts: &[&[u8]],
        limits: crate::InputLimits,
    ) -> Result<OperationTicket> {
        let mut retired_owner = None;
        self.start_digest(
            parts,
            limits,
            DigestSelection::Typed(algorithm),
            false,
            &mut retired_owner,
        )
    }

    /// Hash as in digest and capture the native last-operation validation flags
    /// under the same session ownership before publishing DigestWithValidation.
    /// Missing validation support remains Unavailable; a native error is preserved.
    pub fn digest_with_validation(
        &self,
        algorithm: crate::HashAlgorithm,
        parts: &[&[u8]],
        limits: crate::InputLimits,
    ) -> Result<OperationTicket> {
        let mut retired_owner = None;
        self.start_digest(
            parts,
            limits,
            DigestSelection::Typed(algorithm),
            true,
            &mut retired_owner,
        )
    }
    fn start_digest(
        &self,
        parts: &[&[u8]],
        limits: crate::InputLimits,
        selection: DigestSelection,
        validation_requested: bool,
        retired_owner: &mut Option<std::sync::Arc<crate::advanced::ledger::OperationCell>>,
    ) -> Result<OperationTicket> {
        let capture = self.validation_capture == ValidationCaptureMode::Capture;
        digest::start(
            &self.session,
            parts,
            limits,
            selection,
            validation_requested,
            capture,
            &mut self.pacing.budget(),
            retired_owner,
        )
    }
    /// Observe one completion, then submit only subsequent planned steps. At
    /// most one C_AsyncComplete is issued; an operation is never retried.
    pub fn poll(&self, ticket: &mut OperationTicket) -> Result<OperationProgress> {
        let mut diagnostics = PollDiagnostics::default();
        self.poll_admitted(
            ticket,
            crate::session::CleanupAdmission::Ordinary,
            &mut diagnostics,
        )
    }
    pub(crate) fn poll_admitted(
        &self,
        ticket: &mut OperationTicket,
        admission: crate::session::CleanupAdmission,
        diagnostics: &mut PollDiagnostics,
    ) -> Result<OperationProgress> {
        poll::poll_operation_with_diagnostics(
            &self.session,
            ticket,
            admission,
            self.pacing,
            diagnostics,
        )
    }
    /// Explicitly close this session. A native pending close is preserved;
    /// call again explicitly to observe its completion, never to repeat Close.
    /// Complete confirms session closure, not rollback of persistent creation.
    /// Closing during owned generation may leave unpublished persistent objects;
    /// the caller must reconcile, re-admit or explicitly destroy them.
    pub fn close(&self) -> Result<AdvancedCloseStatus> {
        let mut diagnostics = None;
        close_status(
            crate::session::close_entry(
                &self.session.inner,
                &self.session.entry,
                crate::session::CleanupAdmission::Ordinary,
                &mut diagnostics,
            ),
            self.mode(),
        )
    }
}
impl Drop for AdvancedSession {
    fn drop(&mut self) {
        // Only deferred local effects are eligible. A pending/native owner is
        // retained and follows the existing deferred-close path below.
        if self.session.entry.advanced_progress.cleanup_hint() {
            let _ = self.session.maintain_local();
        }
        if self.session.drop_behavior() == crate::SessionDropBehavior::Close
            && self
                .session
                .entry
                .advanced_operation
                .load(Ordering::Acquire)
                != 0
        {
            self.session
                .entry
                .deferred_close
                .store(true, Ordering::Release);
        }
    }
}

impl AdvancedSession {
    /// Select the same destructor policy as an ordinary Session. Existing local
    /// maintenance may still finish, but KeepOpen schedules no native close on
    /// Drop. Explicit close and cleanup of active operations remain required.
    pub fn set_drop_behavior(&mut self, behavior: crate::SessionDropBehavior) {
        self.session.set_drop_behavior(behavior);
    }

    /// Return the cleanup choice, including one inherited from into_advanced.
    pub fn drop_behavior(&self) -> crate::SessionDropBehavior {
        self.session.drop_behavior()
    }
}

pub(crate) struct CloseState {
    pub ticket: u64,
    pub name: [u8; 15],
    pub phase: ClosePhase,
    pub scope: crate::session::close_scope::CloseScope,
}

/// Native execution and local publication are separate. Retaining a close owner
/// is never, by itself, permission to call C_AsyncComplete on its old handle.
#[derive(Clone, Copy)]
pub(crate) enum ClosePhase {
    Prepared,
    Issued,
    Pending,
    Returned {
        code: CK_RV,
        async_completion: bool,
        publication: ClosePublication,
    },
}

impl ClosePhase {
    pub(crate) fn execution_unproven(self) -> bool {
        match self {
            Self::Prepared | Self::Issued | Self::Pending => true,
            Self::Returned {
                code,
                async_completion,
                ..
            } => {
                if async_completion {
                    !crate::native_return::async_memory_returned(code as u64)
                } else {
                    !crate::native_return::call_memory_returned(code)
                }
            }
        }
    }
}

/// Progress already committed locally after a native return. A failed step can
/// be resumed explicitly without replaying C or advancing authentication twice.
#[derive(Clone, Copy, PartialEq, Eq)]
pub(crate) enum ClosePublication {
    Observed,
    Quarantined,
    Releasing,
    Failure {
        progress: CloseFailureProgress,
        retention: CloseFailureRetention,
    },
    CreatorForgotten,
    AuthenticationExpired,
    FramesRetired,
    Complete,
}

/// A refusal's publications can fail independently after the native return.
/// Keep their progress in the exact close owner, never in a second receipt.
#[derive(Clone, Copy, PartialEq, Eq)]
pub(crate) enum CloseFailureProgress {
    Accounting,
    Classifying,
    Scope,
    AuthenticationDone,
    Complete,
}

/// Publishing a refusal does not prove that quarantined loans can be released.
#[derive(Clone, Copy, PartialEq, Eq)]
pub(crate) enum CloseFailureRetention {
    Ordinary,
    Quarantined,
}

impl CloseState {
    pub(crate) fn record_return(&mut self, code: CK_RV, async_completion: bool) {
        self.phase = if code == CKR_PENDING {
            ClosePhase::Pending
        } else {
            ClosePhase::Returned {
                code,
                async_completion,
                publication: ClosePublication::Observed,
            }
        };
    }
}

impl Drop for CloseState {
    fn drop(&mut self) {
        // close_entry moves this owner outside all guards. CloseReservation
        // explicitly returns permits, reservations, resident loans and finally
        // the unknown/SlotClose barriers, including partial preparation exits.
        drop(self.scope.release());
    }
}
