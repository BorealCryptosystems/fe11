// SPDX-License-Identifier: Apache-2.0
//! Direct native signatures on managed keys, independent of optional SPKI profiles.
use crate::mechanism_extension::*;
use crate::{
    bounds, Error, InputLimits, MessageRoute, NativeObjectRef, PqcHedging, Result, Session,
};
use fe11_sys::*;
use std::mem::{align_of, offset_of, size_of};

/// Parameterless native signature mechanism, including historical algorithms.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct NativeSignatureAlgorithm(CK_MECHANISM_TYPE);
impl NativeSignatureAlgorithm {
    /// CKM_RSA_PKCS; no support claim or automatic substitution.
    pub const RSA_PKCS: Self = Self(CKM_RSA_PKCS);
    /// CKM_RSA_9796; no support claim or automatic substitution.
    pub const RSA_9796: Self = Self(CKM_RSA_9796);
    /// CKM_RSA_X_509; no support claim or automatic substitution.
    pub const RSA_X_509: Self = Self(CKM_RSA_X_509);
    /// CKM_RSA_X9_31; no support claim or automatic substitution.
    pub const RSA_X9_31: Self = Self(CKM_RSA_X9_31);
    /// CKM_DSA; no support claim or automatic substitution.
    pub const DSA: Self = Self(CKM_DSA);
    /// CKM_ECDSA; no support claim or automatic substitution.
    pub const ECDSA: Self = Self(CKM_ECDSA);
    /// CKM_GOSTR3410; no support claim or automatic substitution.
    pub const GOSTR3410: Self = Self(CKM_GOSTR3410);
    /// CKM_FORTEZZA_TIMESTAMP; no support claim or automatic substitution.
    pub const FORTEZZA_TIMESTAMP: Self = Self(CKM_FORTEZZA_TIMESTAMP);
    /// CKM_HSS; no support claim or automatic substitution.
    pub const HSS: Self = Self(CKM_HSS);
    /// CKM_XMSS; no support claim or automatic substitution.
    pub const XMSS: Self = Self(CKM_XMSS);
    /// CKM_XMSSMT; no support claim or automatic substitution.
    pub const XMSSMT: Self = Self(CKM_XMSSMT);
    /// CKM_NULL; no support claim or automatic substitution.
    pub const NULL: Self = Self(CKM_NULL);
    /// CKM_MD2_RSA_PKCS; no support claim or automatic substitution.
    pub const MD2_RSA_PKCS: Self = Self(CKM_MD2_RSA_PKCS);
    /// CKM_MD5_RSA_PKCS; no support claim or automatic substitution.
    pub const MD5_RSA_PKCS: Self = Self(CKM_MD5_RSA_PKCS);
    /// CKM_SHA1_RSA_PKCS; no support claim or automatic substitution.
    pub const SHA1_RSA_PKCS: Self = Self(CKM_SHA1_RSA_PKCS);
    /// CKM_RIPEMD128_RSA_PKCS; no support claim or automatic substitution.
    pub const RIPEMD128_RSA_PKCS: Self = Self(CKM_RIPEMD128_RSA_PKCS);
    /// CKM_RIPEMD160_RSA_PKCS; no support claim or automatic substitution.
    pub const RIPEMD160_RSA_PKCS: Self = Self(CKM_RIPEMD160_RSA_PKCS);
    /// CKM_SHA1_RSA_X9_31; no support claim or automatic substitution.
    pub const SHA1_RSA_X9_31: Self = Self(CKM_SHA1_RSA_X9_31);
    /// CKM_DSA_SHA1; no support claim or automatic substitution.
    pub const DSA_SHA1: Self = Self(CKM_DSA_SHA1);
    /// CKM_DSA_SHA224; no support claim or automatic substitution.
    pub const DSA_SHA224: Self = Self(CKM_DSA_SHA224);
    /// CKM_DSA_SHA256; no support claim or automatic substitution.
    pub const DSA_SHA256: Self = Self(CKM_DSA_SHA256);
    /// CKM_DSA_SHA384; no support claim or automatic substitution.
    pub const DSA_SHA384: Self = Self(CKM_DSA_SHA384);
    /// CKM_DSA_SHA512; no support claim or automatic substitution.
    pub const DSA_SHA512: Self = Self(CKM_DSA_SHA512);
    /// CKM_DSA_SHA3_224; no support claim or automatic substitution.
    pub const DSA_SHA3_224: Self = Self(CKM_DSA_SHA3_224);
    /// CKM_DSA_SHA3_256; no support claim or automatic substitution.
    pub const DSA_SHA3_256: Self = Self(CKM_DSA_SHA3_256);
    /// CKM_DSA_SHA3_384; no support claim or automatic substitution.
    pub const DSA_SHA3_384: Self = Self(CKM_DSA_SHA3_384);
    /// CKM_DSA_SHA3_512; no support claim or automatic substitution.
    pub const DSA_SHA3_512: Self = Self(CKM_DSA_SHA3_512);
    /// CKM_SHA256_RSA_PKCS; no support claim or automatic substitution.
    pub const SHA256_RSA_PKCS: Self = Self(CKM_SHA256_RSA_PKCS);
    /// CKM_SHA384_RSA_PKCS; no support claim or automatic substitution.
    pub const SHA384_RSA_PKCS: Self = Self(CKM_SHA384_RSA_PKCS);
    /// CKM_SHA512_RSA_PKCS; no support claim or automatic substitution.
    pub const SHA512_RSA_PKCS: Self = Self(CKM_SHA512_RSA_PKCS);
    /// CKM_SHA224_RSA_PKCS; no support claim or automatic substitution.
    pub const SHA224_RSA_PKCS: Self = Self(CKM_SHA224_RSA_PKCS);
    /// CKM_SHA3_256_RSA_PKCS; no support claim or automatic substitution.
    pub const SHA3_256_RSA_PKCS: Self = Self(CKM_SHA3_256_RSA_PKCS);
    /// CKM_SHA3_384_RSA_PKCS; no support claim or automatic substitution.
    pub const SHA3_384_RSA_PKCS: Self = Self(CKM_SHA3_384_RSA_PKCS);
    /// CKM_SHA3_512_RSA_PKCS; no support claim or automatic substitution.
    pub const SHA3_512_RSA_PKCS: Self = Self(CKM_SHA3_512_RSA_PKCS);
    /// CKM_SHA3_224_RSA_PKCS; no support claim or automatic substitution.
    pub const SHA3_224_RSA_PKCS: Self = Self(CKM_SHA3_224_RSA_PKCS);
    /// CKM_ECDSA_SHA1; no support claim or automatic substitution.
    pub const ECDSA_SHA1: Self = Self(CKM_ECDSA_SHA1);
    /// CKM_ECDSA_SHA224; no support claim or automatic substitution.
    pub const ECDSA_SHA224: Self = Self(CKM_ECDSA_SHA224);
    /// CKM_ECDSA_SHA256; no support claim or automatic substitution.
    pub const ECDSA_SHA256: Self = Self(CKM_ECDSA_SHA256);
    /// CKM_ECDSA_SHA384; no support claim or automatic substitution.
    pub const ECDSA_SHA384: Self = Self(CKM_ECDSA_SHA384);
    /// CKM_ECDSA_SHA512; no support claim or automatic substitution.
    pub const ECDSA_SHA512: Self = Self(CKM_ECDSA_SHA512);
    /// CKM_ECDSA_SHA3_224; no support claim or automatic substitution.
    pub const ECDSA_SHA3_224: Self = Self(CKM_ECDSA_SHA3_224);
    /// CKM_ECDSA_SHA3_256; no support claim or automatic substitution.
    pub const ECDSA_SHA3_256: Self = Self(CKM_ECDSA_SHA3_256);
    /// CKM_ECDSA_SHA3_384; no support claim or automatic substitution.
    pub const ECDSA_SHA3_384: Self = Self(CKM_ECDSA_SHA3_384);
    /// CKM_ECDSA_SHA3_512; no support claim or automatic substitution.
    pub const ECDSA_SHA3_512: Self = Self(CKM_ECDSA_SHA3_512);
    /// Complete selector list, not a list of mechanisms supported by a token.
    pub const ALL: &'static [Self] = &[
        Self::RSA_PKCS,
        Self::RSA_9796,
        Self::RSA_X_509,
        Self::RSA_X9_31,
        Self::DSA,
        Self::ECDSA,
        Self::GOSTR3410,
        Self::FORTEZZA_TIMESTAMP,
        Self::HSS,
        Self::XMSS,
        Self::XMSSMT,
        Self::NULL,
        Self::MD2_RSA_PKCS,
        Self::MD5_RSA_PKCS,
        Self::SHA1_RSA_PKCS,
        Self::RIPEMD128_RSA_PKCS,
        Self::RIPEMD160_RSA_PKCS,
        Self::SHA1_RSA_X9_31,
        Self::DSA_SHA1,
        Self::DSA_SHA224,
        Self::DSA_SHA256,
        Self::DSA_SHA384,
        Self::DSA_SHA512,
        Self::DSA_SHA3_224,
        Self::DSA_SHA3_256,
        Self::DSA_SHA3_384,
        Self::DSA_SHA3_512,
        Self::SHA256_RSA_PKCS,
        Self::SHA384_RSA_PKCS,
        Self::SHA512_RSA_PKCS,
        Self::SHA224_RSA_PKCS,
        Self::SHA3_256_RSA_PKCS,
        Self::SHA3_384_RSA_PKCS,
        Self::SHA3_512_RSA_PKCS,
        Self::SHA3_224_RSA_PKCS,
        Self::ECDSA_SHA1,
        Self::ECDSA_SHA224,
        Self::ECDSA_SHA256,
        Self::ECDSA_SHA384,
        Self::ECDSA_SHA512,
        Self::ECDSA_SHA3_224,
        Self::ECDSA_SHA3_256,
        Self::ECDSA_SHA3_384,
        Self::ECDSA_SHA3_512,
    ];
    /// Exact selected mechanism identifier.
    pub fn mechanism_number(self) -> u64 {
        self.0 as u64
    }
}
/// Native RSA-PSS primitive or explicitly combined digest mechanism.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct NativePssAlgorithm(CK_MECHANISM_TYPE);
impl NativePssAlgorithm {
    /// CKM_RSA_PKCS_PSS; no support claim or automatic substitution.
    pub const RSA_PKCS_PSS: Self = Self(CKM_RSA_PKCS_PSS);
    /// CKM_SHA1_RSA_PKCS_PSS; no support claim or automatic substitution.
    pub const SHA1_RSA_PKCS_PSS: Self = Self(CKM_SHA1_RSA_PKCS_PSS);
    /// CKM_SHA256_RSA_PKCS_PSS; no support claim or automatic substitution.
    pub const SHA256_RSA_PKCS_PSS: Self = Self(CKM_SHA256_RSA_PKCS_PSS);
    /// CKM_SHA384_RSA_PKCS_PSS; no support claim or automatic substitution.
    pub const SHA384_RSA_PKCS_PSS: Self = Self(CKM_SHA384_RSA_PKCS_PSS);
    /// CKM_SHA512_RSA_PKCS_PSS; no support claim or automatic substitution.
    pub const SHA512_RSA_PKCS_PSS: Self = Self(CKM_SHA512_RSA_PKCS_PSS);
    /// CKM_SHA224_RSA_PKCS_PSS; no support claim or automatic substitution.
    pub const SHA224_RSA_PKCS_PSS: Self = Self(CKM_SHA224_RSA_PKCS_PSS);
    /// CKM_SHA3_256_RSA_PKCS_PSS; no support claim or automatic substitution.
    pub const SHA3_256_RSA_PKCS_PSS: Self = Self(CKM_SHA3_256_RSA_PKCS_PSS);
    /// CKM_SHA3_384_RSA_PKCS_PSS; no support claim or automatic substitution.
    pub const SHA3_384_RSA_PKCS_PSS: Self = Self(CKM_SHA3_384_RSA_PKCS_PSS);
    /// CKM_SHA3_512_RSA_PKCS_PSS; no support claim or automatic substitution.
    pub const SHA3_512_RSA_PKCS_PSS: Self = Self(CKM_SHA3_512_RSA_PKCS_PSS);
    /// CKM_SHA3_224_RSA_PKCS_PSS; no support claim or automatic substitution.
    pub const SHA3_224_RSA_PKCS_PSS: Self = Self(CKM_SHA3_224_RSA_PKCS_PSS);
    /// Complete selector list, not a list of mechanisms supported by a token.
    pub const ALL: &'static [Self] = &[
        Self::RSA_PKCS_PSS,
        Self::SHA1_RSA_PKCS_PSS,
        Self::SHA256_RSA_PKCS_PSS,
        Self::SHA384_RSA_PKCS_PSS,
        Self::SHA512_RSA_PKCS_PSS,
        Self::SHA224_RSA_PKCS_PSS,
        Self::SHA3_256_RSA_PKCS_PSS,
        Self::SHA3_384_RSA_PKCS_PSS,
        Self::SHA3_512_RSA_PKCS_PSS,
        Self::SHA3_224_RSA_PKCS_PSS,
    ];
    /// Exact selected mechanism identifier.
    pub fn mechanism_number(self) -> u64 {
        self.0 as u64
    }
}
/// Combined PQC message-hashing mechanism; the module hashes the original input.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct NativePqcCombined(CK_MECHANISM_TYPE);
impl NativePqcCombined {
    /// CKM_HASH_ML_DSA_SHA224; no support claim or automatic substitution.
    pub const HASH_ML_DSA_SHA224: Self = Self(CKM_HASH_ML_DSA_SHA224);
    /// CKM_HASH_ML_DSA_SHA256; no support claim or automatic substitution.
    pub const HASH_ML_DSA_SHA256: Self = Self(CKM_HASH_ML_DSA_SHA256);
    /// CKM_HASH_ML_DSA_SHA384; no support claim or automatic substitution.
    pub const HASH_ML_DSA_SHA384: Self = Self(CKM_HASH_ML_DSA_SHA384);
    /// CKM_HASH_ML_DSA_SHA512; no support claim or automatic substitution.
    pub const HASH_ML_DSA_SHA512: Self = Self(CKM_HASH_ML_DSA_SHA512);
    /// CKM_HASH_ML_DSA_SHA3_224; no support claim or automatic substitution.
    pub const HASH_ML_DSA_SHA3_224: Self = Self(CKM_HASH_ML_DSA_SHA3_224);
    /// CKM_HASH_ML_DSA_SHA3_256; no support claim or automatic substitution.
    pub const HASH_ML_DSA_SHA3_256: Self = Self(CKM_HASH_ML_DSA_SHA3_256);
    /// CKM_HASH_ML_DSA_SHA3_384; no support claim or automatic substitution.
    pub const HASH_ML_DSA_SHA3_384: Self = Self(CKM_HASH_ML_DSA_SHA3_384);
    /// CKM_HASH_ML_DSA_SHA3_512; no support claim or automatic substitution.
    pub const HASH_ML_DSA_SHA3_512: Self = Self(CKM_HASH_ML_DSA_SHA3_512);
    /// CKM_HASH_ML_DSA_SHAKE128; no support claim or automatic substitution.
    pub const HASH_ML_DSA_SHAKE128: Self = Self(CKM_HASH_ML_DSA_SHAKE128);
    /// CKM_HASH_ML_DSA_SHAKE256; no support claim or automatic substitution.
    pub const HASH_ML_DSA_SHAKE256: Self = Self(CKM_HASH_ML_DSA_SHAKE256);
    /// CKM_HASH_SLH_DSA_SHA224; no support claim or automatic substitution.
    pub const HASH_SLH_DSA_SHA224: Self = Self(CKM_HASH_SLH_DSA_SHA224);
    /// CKM_HASH_SLH_DSA_SHA256; no support claim or automatic substitution.
    pub const HASH_SLH_DSA_SHA256: Self = Self(CKM_HASH_SLH_DSA_SHA256);
    /// CKM_HASH_SLH_DSA_SHA384; no support claim or automatic substitution.
    pub const HASH_SLH_DSA_SHA384: Self = Self(CKM_HASH_SLH_DSA_SHA384);
    /// CKM_HASH_SLH_DSA_SHA512; no support claim or automatic substitution.
    pub const HASH_SLH_DSA_SHA512: Self = Self(CKM_HASH_SLH_DSA_SHA512);
    /// CKM_HASH_SLH_DSA_SHA3_224; no support claim or automatic substitution.
    pub const HASH_SLH_DSA_SHA3_224: Self = Self(CKM_HASH_SLH_DSA_SHA3_224);
    /// CKM_HASH_SLH_DSA_SHA3_256; no support claim or automatic substitution.
    pub const HASH_SLH_DSA_SHA3_256: Self = Self(CKM_HASH_SLH_DSA_SHA3_256);
    /// CKM_HASH_SLH_DSA_SHA3_384; no support claim or automatic substitution.
    pub const HASH_SLH_DSA_SHA3_384: Self = Self(CKM_HASH_SLH_DSA_SHA3_384);
    /// CKM_HASH_SLH_DSA_SHA3_512; no support claim or automatic substitution.
    pub const HASH_SLH_DSA_SHA3_512: Self = Self(CKM_HASH_SLH_DSA_SHA3_512);
    /// CKM_HASH_SLH_DSA_SHAKE128; no support claim or automatic substitution.
    pub const HASH_SLH_DSA_SHAKE128: Self = Self(CKM_HASH_SLH_DSA_SHAKE128);
    /// CKM_HASH_SLH_DSA_SHAKE256; no support claim or automatic substitution.
    pub const HASH_SLH_DSA_SHAKE256: Self = Self(CKM_HASH_SLH_DSA_SHAKE256);
    /// Complete selector list, not a list of mechanisms supported by a token.
    pub const ALL: &'static [Self] = &[
        Self::HASH_ML_DSA_SHA224,
        Self::HASH_ML_DSA_SHA256,
        Self::HASH_ML_DSA_SHA384,
        Self::HASH_ML_DSA_SHA512,
        Self::HASH_ML_DSA_SHA3_224,
        Self::HASH_ML_DSA_SHA3_256,
        Self::HASH_ML_DSA_SHA3_384,
        Self::HASH_ML_DSA_SHA3_512,
        Self::HASH_ML_DSA_SHAKE128,
        Self::HASH_ML_DSA_SHAKE256,
        Self::HASH_SLH_DSA_SHA224,
        Self::HASH_SLH_DSA_SHA256,
        Self::HASH_SLH_DSA_SHA384,
        Self::HASH_SLH_DSA_SHA512,
        Self::HASH_SLH_DSA_SHA3_224,
        Self::HASH_SLH_DSA_SHA3_256,
        Self::HASH_SLH_DSA_SHA3_384,
        Self::HASH_SLH_DSA_SHA3_512,
        Self::HASH_SLH_DSA_SHAKE128,
        Self::HASH_SLH_DSA_SHAKE256,
    ];
    /// Exact selected mechanism identifier.
    pub fn mechanism_number(self) -> u64 {
        self.0 as u64
    }
}

/// Native PQC signature family without a locally assumed parameter set or key size.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum NativePqcFamily {
    /// ML-DSA key; the module reads the actual key's parameter set.
    MlDsa,
    /// SLH-DSA key; the module reads the actual key's parameter set.
    SlhDsa,
}
/// Exact additional context and explicit hedging selection.
pub struct NativePqcContext<'a> {
    /// Native hedging request; ignored by standard native verification.
    pub hedging: PqcHedging,
    /// Exact binary context; None writes NULL/0, while Some(empty) retains a
    /// present zero-length buffer. No prefix or terminator is appended. This
    /// choice is independent of omitting the entire mechanism parameter block.
    pub context: Option<&'a [u8]>,
}
/// Exact Edwards parameter structure, including pure/prehased selection.
pub struct NativeEdDsaParameters<'a> {
    /// Native phFlag. Fe11 does not compute a prehash or reinterpret input bytes.
    pub prehash: bool,
    /// Exact context; None writes NULL/0, Some(empty) writes a present empty buffer.
    pub context: Option<&'a [u8]>,
}
/// Typed native parameters. Invalid cryptographic combinations are submitted to
/// the module after interface-width/ownership checks, without local key mathematics.
pub enum NativeSignatureParameters<'a> {
    /// No mechanism parameter. The exact selected algorithm governs input semantics.
    Parameterless(NativeSignatureAlgorithm),
    /// RSA-PSS tuple; hash/MGF/salt are independent explicit native selections.
    RsaPss {
        /// Exact native algorithm selection; declaration does not imply module support.
        algorithm: NativePssAlgorithm,

        /// Caller-selected native hash mechanism identifier (CKM); no implicit hashing substitution.
        hash: u64,

        /// Exact native mask-generation-function identifier (CKG).
        mgf: u64,

        /// Requested RSA-PSS salt length in bytes.
        salt_bytes: u64,
    },
    /// CKM_EDDSA. None omits the structure; it is distinct from a present structure.
    EdDsa(Option<NativeEdDsaParameters<'a>>),
    /// CKM_XEDDSA with the native CK_XEDDSA_HASH_TYPE scalar.
    XEdDsa {
        /// Exact CK_XEDDSA_HASH_TYPE scalar required by CKM_XEDDSA.
        hash: u64,
    },
    /// Combined GOST signature with an optional exact DER OID parameter.
    GostWithDigest {
        /// Optional DER-encoded parameter-set OID; None and present empty remain distinct.
        oid: Option<&'a [u8]>,
    },
    /// Original message with pure ML-DSA/SLH-DSA; None selects normative defaults.
    PqcPure {
        /// Native ML-DSA or SLH-DSA family for this operation.
        family: NativePqcFamily,

        /// None selects the mechanism's omitted-parameter form; Some retains its explicit context.
        parameters: Option<NativePqcContext<'a>>,
    },
    /// Already hashed input, with the exact native hash identifier supplied.
    /// No local hashing or conversion to a combined mechanism occurs.
    PqcPrehashed {
        /// Native ML-DSA or SLH-DSA family for this operation.
        family: NativePqcFamily,

        /// Caller-selected native hash mechanism identifier (CKM); no implicit hashing substitution.
        hash: u64,

        /// Explicit native context/parameter selection; no application profile inferred.
        parameters: NativePqcContext<'a>,
    },
    /// Original message hashed by the exact combined mechanism.
    PqcHashMessage {
        /// Exact native algorithm selection; declaration does not imply module support.
        algorithm: NativePqcCombined,

        /// None selects the mechanism's omitted-parameter form; Some retains its explicit context.
        parameters: Option<NativePqcContext<'a>>,
    },
}
impl NativeSignatureParameters<'_> {
    /// Native identifier, independent of advertised support and application policy.
    pub fn mechanism_number(&self) -> u64 {
        (match self {
            Self::Parameterless(algorithm) => algorithm.0,
            Self::RsaPss { algorithm, .. } => algorithm.0,
            Self::EdDsa(_) => CKM_EDDSA,
            Self::XEdDsa { .. } => CKM_XEDDSA,
            Self::GostWithDigest { .. } => CKM_GOSTR3410_WITH_GOSTR3411,
            Self::PqcPure {
                family: NativePqcFamily::MlDsa,
                ..
            } => CKM_ML_DSA,
            Self::PqcPure {
                family: NativePqcFamily::SlhDsa,
                ..
            } => CKM_SLH_DSA,
            Self::PqcPrehashed {
                family: NativePqcFamily::MlDsa,
                ..
            } => CKM_HASH_ML_DSA,
            Self::PqcPrehashed {
                family: NativePqcFamily::SlhDsa,
                ..
            } => CKM_HASH_SLH_DSA,
            Self::PqcHashMessage { algorithm, .. } => algorithm.0,
        }) as u64
    }
}
/// Native signature bytes, without an implicit DER conversion or local verifier.
pub struct NativeSignature {
    bytes: crate::symmetric::memory::Buffer,
    mechanism: u64,
}
impl NativeSignature {
    /// Borrow the exact signature returned by the module.
    pub fn as_bytes(&self) -> &[u8] {
        self.bytes.as_slice()
    }
    /// Native mechanism actually used.
    pub fn mechanism_number(&self) -> u64 {
        self.mechanism
    }
}
/// Message recovered by a successful C_VerifyRecover; no bytes escape on refusal.
pub struct NativeRecoveredMessage {
    bytes: crate::symmetric::memory::Buffer,
    mechanism: u64,
}
impl NativeRecoveredMessage {
    /// Borrow the exact recovered bytes; protocol interpretation belongs to the caller.
    pub fn as_bytes(&self) -> &[u8] {
        self.bytes.as_slice()
    }
    /// Native recovery mechanism actually used.
    pub fn mechanism_number(&self) -> u64 {
        self.mechanism
    }
}
fn put(bytes: &mut [u8], offset: usize, value: u64) -> Result<()> {
    let value = CK_ULONG::try_from(value).map_err(|_| {
        Error::Rejected(crate::RejectionReason::NativeSignature(
            crate::NativeSignatureRejection::SignatureParameterScalarAbiWidth,
        ))
    })?;
    bytes[offset..offset + size_of::<CK_ULONG>()].copy_from_slice(&value.to_ne_bytes());
    Ok(())
}
fn hedge(value: PqcHedging) -> CK_ULONG {
    match value {
        PqcHedging::Preferred => CKH_HEDGE_PREFERRED,
        PqcHedging::Required => CKH_HEDGE_REQUIRED,
        PqcHedging::DeterministicRequired => CKH_DETERMINISTIC_REQUIRED,
    }
}
fn perform(
    session: &Session,
    parameters: NativeSignatureParameters<'_>,
    input: ExtensionInput<'_>,
    operation: ExtensionOperation,
    limits: InputLimits,
    authentication: Option<crate::ContextAuthentication>,
    extension_diagnostics: &mut crate::mechanism_extension::operation::Invocation,
) -> Result<ExtensionResult> {
    with_parameters(session, parameters, operation, |request| {
        operation::execute(
            session,
            request,
            input,
            limits,
            authentication,
            extension_diagnostics,
        )
    })
}
pub(crate) fn with_parameters<T>(
    session: &Session,
    parameters: NativeSignatureParameters<'_>,
    operation: ExtensionOperation,
    consume: impl FnOnce(ExtensionRequest<'_>) -> Result<T>,
) -> Result<T> {
    let contract = MechanismExtension::standard(
        &session.inner,
        parameters.mechanism_number() as CK_MECHANISM_TYPE,
        operation,
    );
    // Largest of these standard parameter structures; only the selected exact
    // prefix is copied. No native struct padding is read into byte storage.
    let mut encoded = [0u8; size_of::<CK_HASH_SIGN_ADDITIONAL_CONTEXT>()];
    let mut context = None;
    let mut pointer_offset = None;
    let (length, external) = match &parameters {
        NativeSignatureParameters::Parameterless(_)
        | NativeSignatureParameters::EdDsa(None)
        | NativeSignatureParameters::PqcPure {
            parameters: None, ..
        }
        | NativeSignatureParameters::PqcHashMessage {
            parameters: None, ..
        } => (0, None),
        NativeSignatureParameters::GostWithDigest { oid } => (0, *oid),
        NativeSignatureParameters::RsaPss {
            hash,
            mgf,
            salt_bytes,
            ..
        } => {
            put(
                &mut encoded,
                offset_of!(CK_RSA_PKCS_PSS_PARAMS, hashAlg),
                *hash,
            )?;
            put(&mut encoded, offset_of!(CK_RSA_PKCS_PSS_PARAMS, mgf), *mgf)?;
            put(
                &mut encoded,
                offset_of!(CK_RSA_PKCS_PSS_PARAMS, sLen),
                *salt_bytes,
            )?;
            (size_of::<CK_RSA_PKCS_PSS_PARAMS>(), None)
        }
        NativeSignatureParameters::XEdDsa { hash } => {
            put(&mut encoded, offset_of!(CK_XEDDSA_PARAMS, hash), *hash)?;
            (size_of::<CK_XEDDSA_PARAMS>(), None)
        }
        NativeSignatureParameters::EdDsa(Some(parameters)) => {
            encoded[offset_of!(CK_EDDSA_PARAMS, phFlag)] = if parameters.prehash {
                CK_TRUE
            } else {
                CK_FALSE
            };
            context = parameters.context;
            put(
                &mut encoded,
                offset_of!(CK_EDDSA_PARAMS, ulContextDataLen),
                context.map_or(0, |v| v.len()) as u64,
            )?;
            pointer_offset = Some(offset_of!(CK_EDDSA_PARAMS, pContextData));
            (size_of::<CK_EDDSA_PARAMS>(), None)
        }
        NativeSignatureParameters::PqcPure {
            parameters: Some(parameters),
            ..
        }
        | NativeSignatureParameters::PqcHashMessage {
            parameters: Some(parameters),
            ..
        } => {
            context = parameters.context;
            put(
                &mut encoded,
                offset_of!(CK_SIGN_ADDITIONAL_CONTEXT, hedgeVariant),
                hedge(parameters.hedging) as u64,
            )?;
            put(
                &mut encoded,
                offset_of!(CK_SIGN_ADDITIONAL_CONTEXT, ulContextLen),
                context.map_or(0, |value| value.len()) as u64,
            )?;
            pointer_offset = Some(offset_of!(CK_SIGN_ADDITIONAL_CONTEXT, pContext));
            (size_of::<CK_SIGN_ADDITIONAL_CONTEXT>(), None)
        }
        NativeSignatureParameters::PqcPrehashed {
            hash, parameters, ..
        } => {
            context = parameters.context;
            put(
                &mut encoded,
                offset_of!(CK_HASH_SIGN_ADDITIONAL_CONTEXT, hedgeVariant),
                hedge(parameters.hedging) as u64,
            )?;
            put(
                &mut encoded,
                offset_of!(CK_HASH_SIGN_ADDITIONAL_CONTEXT, ulContextLen),
                context.map_or(0, |value| value.len()) as u64,
            )?;
            put(
                &mut encoded,
                offset_of!(CK_HASH_SIGN_ADDITIONAL_CONTEXT, hash),
                *hash,
            )?;
            pointer_offset = Some(offset_of!(CK_HASH_SIGN_ADDITIONAL_CONTEXT, pContext));
            (size_of::<CK_HASH_SIGN_ADDITIONAL_CONTEXT>(), None)
        }
    };
    let present = length != 0 || external.is_some();
    let bytes = external.unwrap_or(&encoded[..length]);
    bounds::ck_length(bytes.len())?;
    let blocks = [
        ExtensionBlock {
            initial: bytes,
            alignment: align_of::<CK_HASH_SIGN_ADDITIONAL_CONTEXT>(),
            direction: ExtensionDirection::Input,
        },
        ExtensionBlock {
            initial: context.unwrap_or(&[]),
            alignment: 1,
            direction: ExtensionDirection::Input,
        },
    ];
    let pointers = [ExtensionPointer {
        block: 0,
        offset: pointer_offset.unwrap_or(0),
        target: if context.is_some() {
            ExtensionPointerTarget::Block {
                block: 1,
                offset: 0,
            }
        } else {
            ExtensionPointerTarget::Null
        },
    }];
    let block_count = if !present {
        0
    } else if context.is_some() {
        2
    } else {
        1
    };
    consume(ExtensionRequest {
        contract: &contract,
        parameters: ExtensionParameters {
            blocks: &blocks[..block_count],
            pointers: if pointer_offset.is_some() {
                &pointers
            } else {
                &[]
            },
            root: if present { Some(0) } else { None },
            outputs: &[],
        },
    })
}

mod api;
