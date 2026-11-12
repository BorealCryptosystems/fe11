// SPDX-License-Identifier: Apache-2.0
//! Native dual operations, retained plaintext and explicit residual processing.
use super::keys::KeyLease;
use super::{
    asynchronous, continuation, drive, preparation, reconstruction, record, restoration_keys,
    spend, validation, AdvancedSession, AdvancedSessionMode, CallerAssertedAuthenticatedRecord,
    MessageRoute, Operation, OperationBody, OperationProgress, OperationTicket, RecordLimits,
    StateProvenance, StateRestoreKeys, ValidationCaptureMode, ValidationReport,
};

use crate::module::{SessionEntry, State};
use crate::symmetric::memory::{Budget, Buffer, Credit};
use crate::{bounds, Error, Result, Session};
use fe11_sys::{
    CKF_DECRYPT, CKF_DIGEST, CKF_ENCRYPT, CKF_SIGN, CKF_VERIFY, CKR_OK, CKR_PENDING,
    CKR_SIGNATURE_INVALID, CKR_SIGNATURE_LEN_RANGE, CK_ASYNC_DATA, CK_FLAGS, CK_MECHANISM,
    CK_ULONG,
};

use std::sync::atomic::Ordering;
use std::sync::Arc;
pub(super) mod snapshot;
use crate::advanced::record::Family;
use crate::{SymmetricAlgorithm, SymmetricKey};
pub(in crate::advanced) mod authentication;
pub(in crate::advanced) use crate::symmetric::cipher;
pub use crate::symmetric::cipher::DualCipher;
mod recovery;
use authentication::{Authentication, HmacAlgorithm};
pub(super) use cipher::output_bounds;
use cipher::CipherFrame;
pub use recovery::DualRecoveryRecord;

/// Complete native ciphertext, including a tag or padding only when selected.
pub struct DualCiphertext(Buffer);
impl DualCiphertext {
    /// Borrow ciphertext; copies are outside the library budget.
    pub fn as_bytes(&self) -> &[u8] {
        self.0.as_slice()
    }
}
/// Plaintext published after the selected nonzero GCM tag or HMAC verification.
pub struct DualAuthenticatedPlaintext(Buffer);
impl DualAuthenticatedPlaintext {
    /// Borrow authenticated plaintext.
    pub fn as_bytes(&self) -> &[u8] {
        self.0.as_slice()
    }
}
#[doc = include_str!("../../docs/api/advanced/dual/UnauthenticatedPlaintext.md")]
pub struct UnauthenticatedPlaintext(Buffer);
impl UnauthenticatedPlaintext {
    /// Borrow bytes without an authenticity assertion.
    pub fn as_bytes(&self) -> &[u8] {
        self.0.as_slice()
    }
}
/// Distinguishes nonzero-tag GCM from unauthenticated digest output.
pub enum DigestPlaintext {
    /// Native GCM tag verified successfully.
    Authenticated(DualAuthenticatedPlaintext),
    /// Cipher processing succeeded without an authentication tag.
    Unauthenticated(UnauthenticatedPlaintext),
}
/// Completed native HMAC with its hash algorithm, independent of key length.
/// This value alone makes no statement about a transport protocol.
pub struct DualMac {
    algorithm: crate::HashAlgorithm,
    bytes: Buffer,
}
impl DualMac {
    /// Hash used by the native HMAC; this does not infer a key byte count.
    pub fn algorithm(&self) -> crate::HashAlgorithm {
        self.algorithm
    }
    /// Borrow the exact full-length native MAC; caller copies are unbudgeted.
    pub fn as_bytes(&self) -> &[u8] {
        self.bytes.as_slice()
    }
}
/// Terminal result; no intermediate plaintext or successful prefix is exposed.
pub enum DualResult {
    /// Encryption and the explicitly selected digest of the full plaintext.
    DigestEncryptedWithAlgorithm {
        /// Complete native ciphertext.
        ciphertext: DualCiphertext,
        /// Digest with its selected algorithm; this is not authentication.
        digest: crate::PreparedDigest,
    },
    /// Decryption and the selected digest, including final residual plaintext.
    DigestDecryptedWithAlgorithm {
        /// Complete plaintext with the actual cipher authentication distinction.
        plaintext: DigestPlaintext,
        /// Typed digest; it adds no authenticity guarantee.
        digest: crate::PreparedDigest,
    },
    /// Encryption plus the full native MAC under the explicitly supplied MAC key.
    MacEncryptedWithAlgorithm {
        /// Complete native ciphertext.
        ciphertext: DualCiphertext,
        /// Exact algorithm and MAC, without a protocol claim.
        mac: DualMac,
    },
    /// Native encryption and SHA256 of the full plaintext.
    DigestEncrypted {
        /// Ciphertext including native tag or padding.
        ciphertext: DualCiphertext,
        /// SHA256 of all plaintext bytes; not an authentication assertion.
        digest: [u8; 32],
    },
    /// Native decryption and SHA256 including final residual plaintext.
    DigestDecrypted {
        /// Complete plaintext with its explicit authenticity distinction.
        plaintext: DigestPlaintext,
        /// SHA256 including plaintext emitted during DecryptFinal.
        digest: [u8; 32],
    },
    /// Native encryption and HMAC-SHA256 of the plaintext. This is a primitive pair,
    /// not a specified transport protocol or an encrypt-then-MAC construction.
    MacEncrypted {
        /// Complete ciphertext including its native tag or padding.
        ciphertext: DualCiphertext,
        /// HMAC-SHA256 of the full plaintext with the separate MAC key.
        mac: [u8; 32],
    },
    /// Native decryption and HMAC verification both succeeded.
    MacDecrypted(DualAuthenticatedPlaintext),
    /// Native MAC verification failed. No plaintext is attached.
    Invalid,
}
#[derive(Clone, Copy, PartialEq, Eq)]
enum Mode {
    DigestEncrypt,
    DecryptDigest,
    SignEncrypt,
    DecryptVerify,
}
impl Mode {
    fn decrypt(self) -> bool {
        matches!(self, Self::DecryptDigest | Self::DecryptVerify)
    }
    fn mac(self) -> bool {
        matches!(self, Self::SignEncrypt | Self::DecryptVerify)
    }
    fn update(self) -> &'static str {
        match self {
            Self::DigestEncrypt => "C_DigestEncryptUpdate",
            Self::DecryptDigest => "C_DecryptDigestUpdate",
            Self::SignEncrypt => "C_SignEncryptUpdate",
            Self::DecryptVerify => "C_DecryptVerifyUpdate",
        }
    }
}
#[derive(Clone, Copy, PartialEq, Eq)]
enum DualStep {
    AuthInit,
    CipherInit,
    Update(usize),
    CipherFinal,
    Residual,
    AuthFinal,
    Done,
    Failed,
}
pub(super) struct DualOperation {
    cipher_key: KeyLease,
    mode: Mode,
    authentication: authentication::AuthenticationOwner,
    step: DualStep,
    pending: bool,
    valid: bool,
    cipher: CipherFrame,
    auth_mechanism: Box<CK_MECHANISM>,
    inputs: Vec<Buffer>,
    layout: super::continuation::InputLayout,
    output: Option<Buffer>,
    auth: Buffer,
    length: Box<CK_ULONG>,
    auth_length: Box<CK_ULONG>,
    used: usize,
    input_length: usize,
    residual_start: usize,
    residual_length: usize,
    completion: Box<CK_ASYNC_DATA>,
    name: [u8; 32],
    active_flags: CK_FLAGS,
    completion_diagnostic: Option<crate::error::CompletionStorage>,
    _credit: Credit,
}
// SAFETY: every native pointer is into a stable allocation owned by this frame,
// installed in the ledger before Init. Session and frame mutex serialize access;
// pending calls retain allocations and leases without reading native outputs.
unsafe impl Send for DualOperation {}

fn check_dual_functions(state: &crate::module::State, mode: Mode) -> Result<()> {
    // Hash/MAC choices are explicit. Native initialization, not
    // an incomplete discovery list, determines whether it is supported.
    let t = &state.native.table;
    let cipher_available = if mode.decrypt() {
        t.C_DecryptInit.is_some() && t.C_DecryptFinal.is_some()
    } else {
        t.C_EncryptInit.is_some() && t.C_EncryptFinal.is_some()
    };
    let auth_available = match mode {
        Mode::DigestEncrypt => t.C_DigestInit.is_some() && t.C_DigestFinal.is_some(),
        Mode::DecryptDigest => {
            // DecryptFinal may return residual plaintext to digest separately.
            t.C_DigestInit.is_some() && t.C_DigestUpdate.is_some() && t.C_DigestFinal.is_some()
        }
        Mode::SignEncrypt => t.C_SignInit.is_some() && t.C_SignFinal.is_some(),
        Mode::DecryptVerify => {
            t.C_VerifyInit.is_some() && t.C_VerifyUpdate.is_some() && t.C_VerifyFinal.is_some()
        }
    };
    let update_available = match mode {
        Mode::DigestEncrypt => t.C_DigestEncryptUpdate.is_some(),
        Mode::DecryptDigest => t.C_DecryptDigestUpdate.is_some(),
        Mode::SignEncrypt => t.C_SignEncryptUpdate.is_some(),
        Mode::DecryptVerify => t.C_DecryptVerifyUpdate.is_some(),
    };
    if !cipher_available || !auth_available || !update_available {
        return Err(Error::Rejected(crate::RejectionReason::CombinedOperations(
            crate::CombinedOperationsRejection::DualNativeFunctionsUnavailable,
        )));
    }
    Ok(())
}

// Admission computes the complete known graph, then construction only splits
// its credit. Neither phase needs native key handles or coordination guards.
struct DualStorage {
    metadata: usize,
    total: usize,
}
impl DualStorage {
    fn for_request(
        mode: Mode,
        authentication: Authentication,
        parameters: &DualCipher<'_>,
        parts: &[&[u8]],
        input: usize,
        expected: Option<&[u8]>,
    ) -> Result<Self> {
        Self::for_dimensions(
            mode,
            authentication,
            parts.len(),
            input,
            expected,
            CipherFrame::native_parameter_bytes(parameters),
            CipherFrame::allocation_bytes(parameters)?,
        )
    }
    fn for_dimensions(
        mode: Mode,
        authentication: Authentication,
        fragments: usize,
        input: usize,
        expected: Option<&[u8]>,
        native_bytes: usize,
        cipher_bytes: usize,
    ) -> Result<Self> {
        if mode.mac() != authentication.mac().is_some()
            || (mode == Mode::DecryptVerify) != expected.is_some()
        {
            return Err(Error::Rejected(crate::RejectionReason::CombinedOperations(
                crate::CombinedOperationsRejection::DualAuthenticationOwner,
            )));
        }
        if expected.is_some_and(|v| v.len() != authentication.length()) {
            return Err(Error::Rejected(crate::RejectionReason::CombinedOperations(
                crate::CombinedOperationsRejection::DualFullMacLength,
            )));
        }
        let metadata = fragments
            .max(1)
            .checked_mul(std::mem::size_of::<Buffer>())
            .and_then(|n| {
                n.checked_add(
                    std::mem::size_of::<DualOperation>()
                        + crate::error::CompletionStorage::allocation_bytes()
                        + 2 * std::mem::size_of::<CK_MECHANISM>()
                        + native_bytes
                        + std::mem::size_of::<CK_ASYNC_DATA>()
                        + 2 * std::mem::size_of::<CK_ULONG>(),
                )
            })
            .ok_or(Error::Rejected(crate::RejectionReason::CombinedOperations(
                crate::CombinedOperationsRejection::DualMetadataOverflow,
            )))?;
        let capacity = input.checked_add(32).ok_or(Error::Rejected(
            crate::RejectionReason::CombinedOperations(
                crate::CombinedOperationsRejection::DualOutputOverflow,
            ),
        ))?;
        bounds::ck_length(capacity)?;
        bounds::ck_length(authentication.length())?;
        let layout = continuation::InputLayout::allocation_bytes(fragments)?;
        let total = metadata
            .checked_add(cipher_bytes)
            .and_then(|n| n.checked_add(input))
            .and_then(|n| n.checked_add(layout))
            .and_then(|n| n.checked_add(capacity))
            .and_then(|n| n.checked_add(authentication.length()))
            .ok_or(Error::Rejected(crate::RejectionReason::CombinedOperations(
                crate::CombinedOperationsRejection::DualOperationStorageSize,
            )))?;
        Ok(Self { metadata, total })
    }
}

pub(super) struct PreparedDual {
    mode: Mode,
    authentication: Authentication,
    step: DualStep,
    pending: bool,
    valid: bool,
    cipher: CipherFrame,
    auth_mechanism: Box<CK_MECHANISM>,
    inputs: Vec<Buffer>,
    layout: super::continuation::InputLayout,
    output: Option<Buffer>,
    auth: Buffer,
    length: Box<CK_ULONG>,
    auth_length: Box<CK_ULONG>,
    used: usize,
    input_length: usize,
    residual_start: usize,
    residual_length: usize,
    completion: Box<CK_ASYNC_DATA>,
    name: [u8; 32],
    active_flags: CK_FLAGS,
    completion_diagnostic: Option<crate::error::CompletionStorage>,
    _credit: Credit,
}
impl PreparedDual {
    pub(super) fn bind(
        self,
        cipher_key: KeyLease,
        mac_key: Option<KeyLease>,
    ) -> Result<DualOperation> {
        self.check_binding(mac_key.as_ref())?;
        Ok(self.bind_checked(cipher_key, mac_key))
    }
    pub(super) fn check_binding(&self, mac_key: Option<&KeyLease>) -> Result<()> {
        authentication::AuthenticationOwner::check_binding(self.mode, self.authentication, mac_key)
    }
    /// Transfer immediately after check_binding, keeping all stable allocations.
    pub(super) fn bind_checked(
        self,
        cipher_key: KeyLease,
        mac_key: Option<KeyLease>,
    ) -> DualOperation {
        let Self {
            mode,
            authentication,
            step,
            pending,
            valid,
            cipher,
            auth_mechanism,
            inputs,
            layout,
            output,
            auth,
            length,
            auth_length,
            used,
            input_length,
            residual_start,
            residual_length,
            completion,
            name,
            active_flags,
            completion_diagnostic,
            _credit,
        } = self;
        let authentication =
            authentication::AuthenticationOwner::bind_checked(authentication, mac_key);
        DualOperation {
            cipher_key,
            mode,
            authentication,
            step,
            pending,
            valid,
            cipher,
            auth_mechanism,
            inputs,
            layout,
            output,
            auth,
            length,
            auth_length,
            used,
            input_length,
            residual_start,
            residual_length,
            completion,
            name,
            active_flags,
            completion_diagnostic,
            _credit,
        }
    }
}

impl PreparedDual {
    fn finish_record(
        mut body: Self,
        d: record::Descriptor,
        m: &record::Message<'_>,
        pending: bool,
    ) -> Result<Self> {
        body.pending = pending;
        body.step = match d.phase.name() {
            "C_DigestInit" | "C_SignInit" | "C_VerifyInit" => DualStep::AuthInit,
            "C_EncryptInit" | "C_DecryptInit" => DualStep::CipherInit,
            "C_DigestEncryptUpdate"
            | "C_DecryptDigestUpdate"
            | "C_SignEncryptUpdate"
            | "C_DecryptVerifyUpdate" => DualStep::Update(m.next_fragment),
            "C_EncryptFinal" | "C_DecryptFinal" => DualStep::CipherFinal,
            "C_DigestUpdate" | "C_VerifyUpdate" => DualStep::Residual,
            "C_DigestFinal" | "C_SignFinal" | "C_VerifyFinal" => DualStep::AuthFinal,
            _ => {
                return Err(Error::Rejected(crate::RejectionReason::CombinedOperations(
                    crate::CombinedOperationsRejection::ReconstructionDualPhase,
                )))
            }
        };
        reconstruction::output(
            body.output.as_mut().unwrap(),
            m.result,
            matches!(body.step, DualStep::Residual | DualStep::AuthFinal),
        )?;
        body.used = m.produced;
        body.residual_start = m.residual_start;
        body.residual_length = m.residual_length;
        body.active_flags = d.active_flags.try_into().map_err(|_| {
            Error::Rejected(crate::RejectionReason::CombinedOperations(
                crate::CombinedOperationsRejection::ReconstructionActiveFlagsWidth,
            ))
        })?;
        Ok(body)
    }
}

mod api;
mod operation;
mod return_size;

mod resolved_call;
