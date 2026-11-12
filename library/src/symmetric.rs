// SPDX-License-Identifier: Apache-2.0
//! Explicit native AEAD/MAC profiles, protected keys and bounded owned buffers.
use crate::{bounds, Error, ManagedObjectRef, Result};
use fe11_sys::*;

/// Select the ABI actually sent to the module. Message AAD is a separate
/// pointer/CK_ULONG pair; the classic parameter structure has a narrower bound.
#[derive(Clone, Copy, PartialEq, Eq)]
pub(crate) enum AeadParameterLayout {
    Classic,
    Message,
}

mod ccm;
pub(crate) use ccm::{validate_ccm_fields, validate_ccm_message};
pub use ccm::{CcmCiphertext, CcmNonce, CcmParameters};
pub(crate) mod block;
mod classic_aead;
pub(crate) mod gcm_legacy;
pub(crate) mod poly1305;
pub use classic_aead::{ClassicAeadCiphertext, ClassicAeadParameters};
pub(crate) mod stream;
pub use poly1305::{
    StreamAeadAlgorithm, StreamAeadEncrypted, StreamAeadNonce, StreamAeadParameters,
};
pub(crate) mod structured;
pub use stream::StreamCipherParameters;
pub(crate) mod token_iv;
pub use structured::RcCipherParameters;
pub use token_iv::{TokenIv, TokenIvCipher};
pub(crate) mod cipher;
mod classic;
pub use block::CipherParameters;
pub(crate) mod keys;
pub(crate) mod memory;
mod operations;
pub use classic::{
    AesCipherParameters, AesCiphertext, Ciphertext, UnauthenticatedAesPlaintext,
    UnauthenticatedCipherPlaintext,
};

use memory::Buffer;
pub use memory::SymmetricLimits;

/// Immutable encoding of the native ChaCha20-Poly1305 nonce length field.
/// Both choices use the same 12-byte IETF nonce and 16-byte authentication tag.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ChaChaNonceLengthEncoding {
    /// PKCS #11 3.2: ulNonceLen is 96 bits.
    Bits,
    /// Explicit interoperability convention: ulNonceLen is 12 bytes.
    /// This encoding is not claimed to conform to PKCS #11 3.2.
    BytesCompatibility,
}
impl ChaChaNonceLengthEncoding {
    pub(crate) fn native_length(self) -> CK_ULONG {
        match self {
            Self::Bits => 96,
            Self::BytesCompatibility => 12,
        }
    }
}
// Bound both supported interpretations of the native scalar; only the first
// 12 bytes are logical IETF ChaCha nonce data.
pub(crate) fn native_nonce_storage(nonce: &[u8; 12]) -> [u8; 96] {
    let mut storage = [0; 96];
    storage[..12].copy_from_slice(nonce);
    storage
}

/// Symmetric algorithms with an explicit key-size request. Native support is
/// decided by the module; HMAC key size is independent of the full MAC width.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SymmetricAlgorithm {
    /// AES-128; GCM parameters are selected by the caller.
    Aes128,
    /// AES-192; GCM parameters are selected by the caller.
    Aes192,
    /// AES-256; GCM parameters are selected by the caller.
    Aes256,
    /// IETF ChaCha20-Poly1305, 256-bit key and 96-bit nonce.
    ChaCha20,
    /// SHA-256 HMAC with a full 32-byte MAC.
    HmacSha256 {
        /// Caller-requested key length in bytes, independent of MAC width.
        /// Native support and any deployment policy remain separate decisions.
        key_length: usize,
    },
    /// SHA-384 HMAC with a full 48-byte MAC.
    HmacSha384 {
        /// Caller-requested key length in bytes, independent of MAC width.
        /// Native support and any deployment policy remain separate decisions.
        key_length: usize,
    },
    /// SHA-512 HMAC with a full 64-byte MAC.
    HmacSha512 {
        /// Caller-requested key length in bytes, independent of MAC width.
        /// Native support and any deployment policy remain separate decisions.
        key_length: usize,
    },
}
impl SymmetricAlgorithm {
    /// Native generation mechanism selected by this algorithm/key-type request.
    /// This is request metadata, not an observed CKA_KEY_GEN_MECHANISM value.
    pub fn generation_mechanism(self, kind: Option<HmacKeyType>) -> Result<u64> {
        self.generation(kind).map(|mechanism| mechanism as u64)
    }
    /// Requested key length in bytes, not an observation of native CKA_VALUE_LEN.
    /// HMAC has no library-selected length; AES/ChaCha variants name fixed sizes.
    pub fn key_length(self) -> usize {
        match self {
            Self::Aes128 => 16,
            Self::Aes192 => 24,
            Self::Aes256 | Self::ChaCha20 => 32,
            Self::HmacSha256 { key_length }
            | Self::HmacSha384 { key_length }
            | Self::HmacSha512 { key_length } => key_length,
        }
    }
    /// Full MAC width for a hash-based MAC, independent of the selected key size.
    /// General-length MAC parameters remain available through the native API.
    pub fn mac_length(self) -> Option<usize> {
        match self {
            Self::HmacSha256 { .. } => Some(32),
            Self::HmacSha384 { .. } => Some(48),
            Self::HmacSha512 { .. } => Some(64),
            _ => None,
        }
    }
    pub(crate) fn mac(self) -> bool {
        self.mac_length().is_some()
    }
    /// Native mechanism number for the algorithm's primary operation.
    /// This is a selector, not a capability or permission claim.
    pub fn mechanism_number(self) -> u64 {
        self.mechanism() as u64
    }
    pub(crate) fn mechanism(self) -> CK_MECHANISM_TYPE {
        match self {
            Self::Aes128 | Self::Aes192 | Self::Aes256 => CKM_AES_GCM,
            Self::ChaCha20 => CKM_CHACHA20_POLY1305,
            Self::HmacSha256 { .. } => CKM_SHA256_HMAC,
            Self::HmacSha384 { .. } => CKM_SHA384_HMAC,
            Self::HmacSha512 { .. } => CKM_SHA512_HMAC,
        }
    }
    pub(crate) fn key_type(self, kind: Option<HmacKeyType>) -> Result<CK_KEY_TYPE> {
        if self.mac() {
            match kind {
                Some(HmacKeyType::Generic) => Ok(CKK_GENERIC_SECRET),
                Some(HmacKeyType::Dedicated) => Ok(match self {
                    Self::HmacSha256 { .. } => CKK_SHA256_HMAC,
                    Self::HmacSha384 { .. } => CKK_SHA384_HMAC,
                    _ => CKK_SHA512_HMAC,
                }),
                None => Err(Error::Rejected(
                    crate::RejectionReason::SymmetricParameters(
                        crate::SymmetricParametersRejection::HmacKeyTypeRequired,
                    ),
                )),
            }
        } else if kind.is_some() {
            Err(Error::Rejected(
                crate::RejectionReason::SymmetricParameters(
                    crate::SymmetricParametersRejection::HmacKeyTypeOnAead,
                ),
            ))
        } else {
            Ok(if self == Self::ChaCha20 {
                CKK_CHACHA20
            } else {
                CKK_AES
            })
        }
    }
    pub(crate) fn generation(self, kind: Option<HmacKeyType>) -> Result<CK_MECHANISM_TYPE> {
        self.key_type(kind)?;
        Ok(match self {
            Self::Aes128 | Self::Aes192 | Self::Aes256 => CKM_AES_KEY_GEN,
            Self::ChaCha20 => CKM_CHACHA20_KEY_GEN,
            // key_type above rejects a missing HMAC key kind. The remaining
            // variants are HMAC and both self/kind are unchanged Copy values.
            _ => match kind.expect("validated HMAC key type") {
                HmacKeyType::Generic => CKM_GENERIC_SECRET_KEY_GEN,
                HmacKeyType::Dedicated => match self {
                    Self::HmacSha256 { .. } => CKM_SHA256_KEY_GEN,
                    Self::HmacSha384 { .. } => CKM_SHA384_KEY_GEN,
                    _ => CKM_SHA512_KEY_GEN,
                },
            },
        })
    }
}
/// Explicit native HMAC key representation. No refusal changes this choice.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum HmacKeyType {
    /// CKK_GENERIC_SECRET and CKM_GENERIC_SECRET_KEY_GEN.
    Generic,
    /// Dedicated hash-specific key type and generation mechanism.
    Dedicated,
}
/// Native generation requests and explicit observations for generation or lookup.
pub struct SymmetricKeySpec {
    /// Explicit native usage attributes, independent of the observation selection.
    pub usages: crate::KeyUsageRequest,
    /// Native CKA_PRIVATE request, independent of class and observations.
    pub visibility: crate::ObjectVisibility,
    /// Explicit observations for the resulting object.
    pub admission: crate::ObjectAdmission,
    /// Native SENSITIVE/EXTRACTABLE request, separate from observations.
    pub protection_request: crate::CurrentKeyProtection,
    /// Explicit native provenance and protection attribute reads.
    pub history: crate::HistoryObservationPlan,
    /// Explicit observation of the native allowed-mechanism attribute.
    pub mechanisms: crate::MechanismObservationPlan,
    /// Requested algorithm and key size, not an observed native length.
    /// Generation transmits the size request; import checks the supplied material.
    /// AES Unwrap omits CKA_VALUE_LEN on selected tables through 3.1; see
    /// [`crate::Session::unwrap_symmetric_key`] and [`crate::Session::unwrap_aes_key_encryption_key`].
    /// Public CKA_VALUE_LEN observations are selected separately in
    /// admission.public_attributes; selecting a read does not compare its value.
    pub algorithm: SymmetricAlgorithm,
    /// Required for HMAC; must be None for AEAD.
    pub hmac_key_type: Option<HmacKeyType>,
    /// Native CKA_ID bytes; destination observations are selected independently.
    pub id: Vec<u8>,
    /// UTF-8 native label; no library-defined presentation policy.
    pub label: String,
    /// Token object if true, session object otherwise.
    pub persistent: bool,
}
impl SymmetricKeySpec {
    pub(crate) fn validate(&self) -> Result<()> {
        crate::bounds::metadata_lengths(&self.id, self.label.as_bytes())?;
        self.algorithm.key_type(self.hmac_key_type)?;
        Ok(())
    }
}

/// Knowledge of this API invocation, not a substituted native attribute value.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum GenerationInvocation {
    /// This call successfully invoked C_GenerateKey with this mechanism.
    GeneratedByThisCall {
        /// Mechanism actually supplied to C_GenerateKey.
        mechanism: u64,
    },
    /// This call does not attest a successful C_GenerateKey invocation.
    /// A derivation/KEM wrapper may separately describe its actual introduction.
    NotGeneratedByThisCall,
}

/// Native generation observation and knowledge of this invocation.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct GenerationMechanismReport {
    pub(crate) selection: crate::HistoryObservationPlan,
    pub(crate) invocation: GenerationInvocation,
    pub(crate) observation: crate::Observation<u64>,
}
impl GenerationMechanismReport {
    /// Exact caller selection retained without a new native read.
    pub fn selection(&self) -> &crate::HistoryObservationPlan {
        &self.selection
    }
    /// Actual generation invocation knowledge, separate from native readback.
    pub fn invocation(&self) -> GenerationInvocation {
        self.invocation
    }
    /// Exact interpreted readback or its missing/unusable state.
    pub fn observation(&self) -> crate::Observation<u64> {
        self.observation
    }
}

/// Observed public protection history, not proof of physical enforcement.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SymmetricProtection {
    /// Complete owned observation snapshot, including the caller's read plan.
    pub observations: crate::BaseProtection,
    /// Exact selected history/protection evaluation; no physical attestation.

    /// Native CKA_LOCAL.
    pub local: crate::Observation<bool>,
    /// Native CKA_ALWAYS_SENSITIVE.
    pub always_sensitive: crate::Observation<bool>,
    /// Native CKA_NEVER_EXTRACTABLE.
    pub never_extractable: crate::Observation<bool>,
    /// Generation mechanism observation and explicitly selected evaluation.
    pub generation: GenerationMechanismReport,
}
/// Opaque native secret-key reference, bound to session, generation and admission.
pub struct SymmetricKey {
    pub(crate) managed: ManagedObjectRef,
    pub(crate) algorithm: SymmetricAlgorithm,
    pub(crate) protection: SymmetricProtection,
    pub(crate) allowed: crate::MechanismObservationReport,
}
impl SymmetricKey {
    /// Caller-selected algorithm and requested key length retained at admission.
    /// This performs no read and does not attest native CKA_VALUE_LEN; consult
    /// managed().object_observations() for explicitly selected observations.
    pub fn algorithm(&self) -> SymmetricAlgorithm {
        self.algorithm
    }
    /// Observed provenance, without claiming an import/unwrap/derive method.
    pub fn protection(&self) -> &SymmetricProtection {
        &self.protection
    }
    /// Admission-time mechanism evidence and the explicitly chosen evaluation.
    pub fn mechanism_report(&self) -> &crate::MechanismObservationReport {
        &self.allowed
    }
    /// Borrow the administrative reference; no native handle or secret value.
    pub fn managed(&self) -> &ManagedObjectRef {
        &self.managed
    }
    pub(crate) fn view(&self) -> SymmetricKeyView<'_> {
        SymmetricKeyView {
            managed: &self.managed,
            algorithm: self.algorithm,
        }
    }
}
// Internal operation view carries no invented provenance and cannot be built by callers.
#[derive(Clone, Copy)]
pub(crate) struct SymmetricKeyView<'a> {
    pub(crate) managed: &'a ManagedObjectRef,
    pub(crate) algorithm: SymmetricAlgorithm,
}
/// Explicit AEAD IV and native parameter selection. The caller owns key-lifetime policy.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum AeadNonce {
    /// Explicit 96-bit IV and 128-bit tag, without native IV generation.
    Provided([u8; 12]),
    /// Explicit native random 96-bit IV and 128-bit tag, without fixed bits.
    BackendRandom,
    /// Complete AES-GCM parameter selection, without an implicit application policy.
    Gcm {
        /// Supplied IV or initial storage whose fixed bits the native generator retains.
        iv: std::sync::Arc<[u8]>,
        /// Exact CK_GENERATOR_FUNCTION value. Zero requests no generation.
        generator: u64,
        /// Exact ulIvFixedBits for message operations.
        fixed_bits: u64,
        /// Exact ulTagBits, between zero and 128 inclusive.
        tag_bits: u64,
    },
}
impl AeadNonce {
    pub(crate) fn iv(&self) -> &[u8] {
        match self {
            Self::Provided(iv) => iv,
            Self::BackendRandom => &[0; 12],
            Self::Gcm { iv, .. } => iv,
        }
    }
    pub(crate) fn generator(&self) -> Result<CK_GENERATOR_FUNCTION> {
        match self {
            Self::Provided(_) => Ok(CKG_NO_GENERATE),
            Self::BackendRandom => Ok(CKG_GENERATE_RANDOM),
            Self::Gcm { generator, .. } => {
                CK_GENERATOR_FUNCTION::try_from(*generator).map_err(|_| {
                    Error::Rejected(crate::RejectionReason::SymmetricParameters(
                        crate::SymmetricParametersRejection::GcmGeneratorAbiWidth,
                    ))
                })
            }
        }
    }
    pub(crate) fn generated(&self) -> bool {
        match self {
            Self::Provided(_) => false,
            Self::BackendRandom => true,
            Self::Gcm { generator, .. } => *generator != CKG_NO_GENERATE as u64,
        }
    }
    pub(crate) fn fixed_bits(&self) -> u64 {
        match self {
            Self::Gcm { fixed_bits, .. } => *fixed_bits,
            _ => 0,
        }
    }
    /// Authentication tag length explicitly selected by this request, in bits.
    pub fn tag_bits(&self) -> u64 {
        match self {
            Self::Gcm { tag_bits, .. } => *tag_bits,
            _ => 128,
        }
    }
    pub(crate) fn tag_bytes(&self) -> Result<usize> {
        if self.tag_bits() > 128 {
            return Err(Error::Rejected(
                crate::RejectionReason::SymmetricParameters(
                    crate::SymmetricParametersRejection::GcmTagBitLength,
                ),
            ));
        }
        Ok(((self.tag_bits() + 7) / 8) as usize)
    }
    pub(crate) fn validate_gcm(&self, aad_len: usize) -> Result<()> {
        Self::validate_gcm_dimensions(
            AeadParameterLayout::Classic,
            self.iv().len(),
            aad_len,
            self.fixed_bits(),
            self.generator()? as u64,
            self.tag_bits(),
        )?;
        if self.fixed_bits() > self.iv().len() as u64 * 8 {
            return Err(Error::Rejected(
                crate::RejectionReason::SymmetricParameters(
                    crate::SymmetricParametersRejection::GcmNormativeParameterBounds,
                ),
            ));
        }
        Ok(())
    }
    pub(crate) fn validate_gcm_message_encrypt(&self, aad_len: usize) -> Result<()> {
        self.validate_gcm_message_decrypt(aad_len)?;
        if self.fixed_bits() > self.iv().len() as u64 * 8 {
            return Err(Error::Rejected(
                crate::RejectionReason::SymmetricParameters(
                    crate::SymmetricParametersRejection::GcmNormativeParameterBounds,
                ),
            ));
        }
        Ok(())
    }
    /// MessageDecrypt ignores generator/fixed bits. Preserve their ABI values
    /// without applying encryption semantics or slicing by ignored fixed bits.
    pub(crate) fn validate_gcm_message_decrypt(&self, aad_len: usize) -> Result<()> {
        Self::validate_gcm_dimensions(
            AeadParameterLayout::Message,
            self.iv().len(),
            aad_len,
            self.fixed_bits(),
            self.generator()? as u64,
            self.tag_bits(),
        )
    }
    /// Validate borrowed wire dimensions before allocating a retained IV owner.
    /// Decryption ignores generator/fixed-bit semantics but preserves ABI bounds.
    pub(crate) fn validate_gcm_dimensions(
        layout: AeadParameterLayout,
        iv_len: usize,
        aad_len: usize,
        fixed_bits: u64,
        generator: u64,
        tag_bits: u64,
    ) -> Result<()> {
        let len = u64::try_from(iv_len).map_err(|_| {
            Error::Rejected(crate::RejectionReason::SymmetricParameters(
                crate::SymmetricParametersRejection::GcmIvLength,
            ))
        })?;
        if len == 0
            || len > u32::MAX as u64
            || layout == AeadParameterLayout::Classic && aad_len as u128 > u32::MAX as u128
        {
            return Err(Error::Rejected(
                crate::RejectionReason::SymmetricParameters(
                    crate::SymmetricParametersRejection::GcmNormativeParameterBounds,
                ),
            ));
        }
        bounds::ck_length(iv_len)?;
        bounds::ck_length(aad_len)?;
        CK_ULONG::try_from(fixed_bits).map_err(|_| {
            Error::Rejected(crate::RejectionReason::SymmetricParameters(
                crate::SymmetricParametersRejection::GcmFixedBitsAbiWidth,
            ))
        })?;
        CK_GENERATOR_FUNCTION::try_from(generator).map_err(|_| {
            Error::Rejected(crate::RejectionReason::SymmetricParameters(
                crate::SymmetricParametersRejection::GcmGeneratorAbiWidth,
            ))
        })?;
        if tag_bits > 128 {
            return Err(Error::Rejected(
                crate::RejectionReason::SymmetricParameters(
                    crate::SymmetricParametersRejection::GcmTagBitLength,
                ),
            ));
        }
        Ok(())
    }
    pub(crate) fn fixed_bits_unchanged(&self, actual: &[u8]) -> bool {
        if actual.len() != self.iv().len() {
            return false;
        }
        let whole = (self.fixed_bits() / 8) as usize;
        let partial = (self.fixed_bits() % 8) as u32;
        self.iv()[..whole] == actual[..whole]
            && (partial == 0
                || ((self.iv()[whole] ^ actual[whole]) & (0xffu8 << (8 - partial))) == 0)
    }
    pub(crate) fn retained_bytes(&self) -> usize {
        match self {
            Self::Gcm { iv, .. } => iv.len(),
            _ => 0,
        }
    }
}
/// Scalar identifier used by message Init diagnostics. No parameter value,
/// nonce, key or authentication bytes are exposed.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum MessageInitField {
    /// ulIvLen.
    IvLength,
    /// ulIvFixedBits.
    IvFixedBits,
    /// ivGenerator.
    IvGenerator,
    /// ulTagBits.
    TagBits,
    /// CCM ulNonceLen.
    NonceLength,
    /// CCM ulNonceFixedBits.
    NonceFixedBits,
    /// CCM nonceGenerator.
    NonceGenerator,
    /// CCM ulMACLen in bytes.
    MacLength,
    /// CCM ulDataLen, excluding the MAC.
    DataLength,
}

/// Caller-selected layout for the Init of a native GCM or CCM message sequence.
/// This is an interoperability choice, not a detected provider capability.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum MessageInitLayout {
    /// Init receives NULL/0; parameters are supplied to the message call.
    InitWithoutParameters,
    /// Init and message descriptors share the same owned IV/tag buffers.
    /// A module that caches and ignores later inputs remains outside the
    /// guarantees of this representation. No runtime conformance is inferred.
    InitWithOwnedMessageParameters,
}

/// Local representation selected for a completed Message request. This reports
/// what Fe11 supplied, not whether the native module used or cached each field.
/// No field values, pointer addresses or secret bytes are included.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct CallerSelectedInitLayout {
    layout: MessageInitLayout,
    mechanism: u64,
}
impl CallerSelectedInitLayout {
    pub(crate) fn gcm(layout: MessageInitLayout) -> Self {
        Self {
            layout,
            mechanism: CKM_AES_GCM as u64,
        }
    }
    pub(crate) fn ccm(layout: MessageInitLayout) -> Self {
        Self {
            layout,
            mechanism: CKM_AES_CCM as u64,
        }
    }
    /// Caller-selected representation; never inferred from a provider identity.
    pub fn layout(&self) -> MessageInitLayout {
        self.layout
    }
    /// Exact public CKM value of the message mechanism.
    pub fn mechanism(&self) -> u64 {
        self.mechanism
    }
    /// Scalars written into the retained Init block before each message.
    /// Buffer contents are prepared separately; their pointer addresses stay fixed.
    pub fn rewritten_fields(&self) -> &'static [MessageInitField] {
        if self.layout == MessageInitLayout::InitWithOwnedMessageParameters
            && self.mechanism == CKM_AES_CCM as u64
        {
            &[MessageInitField::DataLength]
        } else {
            &[]
        }
    }
}

/// Explicit nonce and authenticated additional data.
pub struct AeadParameters<'a> {
    /// Provided or native-generated nonce; decryption requires Provided.
    pub nonce: AeadNonce,
    /// Authenticated, unencrypted context, charged to the selected input limits.
    pub aad: &'a [u8],
}
/// Owned ciphertext followed by the selected tag bytes, charged until Drop.
pub struct AeadCiphertext {
    bytes: Buffer,
    nonce: Buffer,
    origin: AeadNonce,
    algorithm: SymmetricAlgorithm,
    message_init: Option<CallerSelectedInitLayout>,
    _parameters: memory::Credit,
}
impl AeadCiphertext {
    pub(crate) fn into_plaintext(self) -> AeadPlaintext {
        AeadPlaintext {
            classic: None,
            tag_bits: self.origin.tag_bits(),
            bytes: self.bytes,
            message_init: self.message_init,
        }
    }
    /// Borrow ciphertext and tag; consumer copies are outside the module budget.
    pub fn as_bytes(&self) -> &[u8] {
        self.bytes.as_slice()
    }
    /// Nonce actually used by the successful native call.
    pub fn nonce(&self) -> &[u8] {
        self.nonce.as_slice()
    }
    /// Explicit requested origin; Provided retains its exact nonce.
    pub fn nonce_origin(&self) -> AeadNonce {
        self.origin.clone()
    }
    /// Algorithm bound to the key.
    pub fn algorithm(&self) -> SymmetricAlgorithm {
        self.algorithm
    }
    /// Init representation for a Message route; absent for traditional AEAD.
    pub fn message_init(&self) -> Option<CallerSelectedInitLayout> {
        self.message_init
    }
}
pub(crate) struct ClassicRetention {
    pub(crate) nonce: Buffer,
    pub(crate) credit: memory::Credit,
}

#[doc = include_str!("../docs/api/symmetric/AeadPlaintext.md")]
pub struct AeadPlaintext {
    classic: Option<ClassicRetention>,
    bytes: Buffer,
    tag_bits: u64,
    message_init: Option<CallerSelectedInitLayout>,
}
impl AeadPlaintext {
    pub(crate) fn from_classic(
        bytes: Buffer,
        tag_bits: u64,
        nonce: Buffer,
        credit: memory::Credit,
    ) -> Self {
        Self {
            bytes,
            tag_bits,
            message_init: None,
            classic: Some(ClassicRetention { nonce, credit }),
        }
    }
    pub(crate) fn into_classic_parts(self) -> Result<(Buffer, Buffer, memory::Credit)> {
        let retained = self.classic.ok_or(Error::Rejected(
            crate::RejectionReason::SymmetricParameters(
                crate::SymmetricParametersRejection::ClassicAeadResultRequired,
            ),
        ))?;
        Ok((self.bytes, retained.nonce, retained.credit))
    }
    /// Init representation for a Message route; absent for traditional AEAD.
    pub fn message_init(&self) -> Option<CallerSelectedInitLayout> {
        self.message_init
    }
    /// Tag length selected for the successful native verification. Zero provides
    /// no authentication; success does not attest an application security profile.
    pub fn tag_bits(&self) -> u64 {
        self.tag_bits
    }
    /// Borrow completed plaintext; caller-made copies cannot be erased here.
    pub fn as_bytes(&self) -> &[u8] {
        self.bytes.as_slice()
    }
}
/// Complete native HMAC output, charged until Drop.
pub struct MessageAuthenticationCode {
    bytes: Buffer,
}
impl MessageAuthenticationCode {
    /// Borrow the complete MAC; no truncation is implicit.
    pub fn as_bytes(&self) -> &[u8] {
        self.bytes.as_slice()
    }
}

pub(crate) fn input_size(
    module: crate::CryptoLimits,
    limits: crate::InputLimits,
    parts: &[&[u8]],
    aad: &[u8],
    tag_overhead: usize,
) -> Result<usize> {
    input_size_lengths(
        module,
        limits,
        parts.len(),
        parts.iter().map(|part| Ok(part.len())),
        aad.len(),
        tag_overhead,
    )
}
pub(crate) fn input_size_lengths(
    module: crate::CryptoLimits,
    limits: crate::InputLimits,
    count: usize,
    lengths: impl Iterator<Item = Result<usize>>,
    aad_length: usize,
    tag_overhead: usize,
) -> Result<usize> {
    limits.validate(module, &[])?;
    if count > limits.maximum_parts {
        return Err(Error::Rejected(
            crate::RejectionReason::SymmetricParameters(
                crate::SymmetricParametersRejection::SymmetricFragmentCeiling,
            ),
        ));
    }
    // The trailing authentication tag is framing, not plaintext. The chosen
    // aggregate budget covers plaintext and AAD; no per-fragment ceiling is added.
    let mut n = 0usize;
    let mut observed = 0usize;
    for length in lengths {
        let length = length?;
        if observed == count {
            return Err(Error::Rejected(
                crate::RejectionReason::SymmetricParameters(
                    crate::SymmetricParametersRejection::SymmetricFragmentCountChanged,
                ),
            ));
        }
        observed += 1;
        bounds::ck_length(length)?;
        n = n.checked_add(length).ok_or(Error::Rejected(
            crate::RejectionReason::SymmetricParameters(
                crate::SymmetricParametersRejection::SymmetricInputOverflow,
            ),
        ))?;
    }
    if observed != count {
        return Err(Error::Rejected(
            crate::RejectionReason::SymmetricParameters(
                crate::SymmetricParametersRejection::SymmetricFragmentCountChanged,
            ),
        ));
    }
    bounds::ck_length(aad_length)?;
    if n.saturating_sub(tag_overhead)
        .checked_add(aad_length)
        .filter(|n| *n <= limits.maximum_total_bytes)
        .is_none()
    {
        return Err(Error::Rejected(
            crate::RejectionReason::SymmetricParameters(
                crate::SymmetricParametersRejection::SymmetricTotalInputCeiling,
            ),
        ));
    }
    bounds::ck_length(n)?;
    Ok(n)
}
