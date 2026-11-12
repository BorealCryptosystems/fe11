// SPDX-License-Identifier: Apache-2.0
//! Typed native MAC requests without application key-size or algorithm policy.
use crate::mechanism_extension::*;
use crate::{bounds, Error, InputLimits, MessageRoute, NativeObjectRef, Result, Session};
use fe11_sys::*;
use std::mem::{align_of, offset_of, size_of};

/// Parameterless full-MAC identity and its published general-length counterpart.
/// Choosing a historical mechanism is not a claim of modern cryptographic strength.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct NativeMacAlgorithm {
    full: CK_MECHANISM_TYPE,
    general: Option<CK_MECHANISM_TYPE>,
    output_bytes: usize,
}

impl NativeMacAlgorithm {
    /// CKM_SHA512_224_HMAC, and CKM_SHA512_224_HMAC_GENERAL when explicitly selected.
    pub const SHA512_224_HMAC: Self = Self {
        full: CKM_SHA512_224_HMAC,
        general: Some(CKM_SHA512_224_HMAC_GENERAL),
        output_bytes: 28,
    };
    /// CKM_SHA512_256_HMAC, and CKM_SHA512_256_HMAC_GENERAL when explicitly selected.
    pub const SHA512_256_HMAC: Self = Self {
        full: CKM_SHA512_256_HMAC,
        general: Some(CKM_SHA512_256_HMAC_GENERAL),
        output_bytes: 32,
    };
    /// CKM_MD2_HMAC, and CKM_MD2_HMAC_GENERAL when explicitly selected.
    pub const MD2_HMAC: Self = Self {
        full: CKM_MD2_HMAC,
        general: Some(CKM_MD2_HMAC_GENERAL),
        output_bytes: 16,
    };
    /// CKM_MD5_HMAC, and CKM_MD5_HMAC_GENERAL when explicitly selected.
    pub const MD5_HMAC: Self = Self {
        full: CKM_MD5_HMAC,
        general: Some(CKM_MD5_HMAC_GENERAL),
        output_bytes: 16,
    };
    /// CKM_SHA_1_HMAC, and CKM_SHA_1_HMAC_GENERAL when explicitly selected.
    pub const SHA_1_HMAC: Self = Self {
        full: CKM_SHA_1_HMAC,
        general: Some(CKM_SHA_1_HMAC_GENERAL),
        output_bytes: 20,
    };
    /// CKM_RIPEMD128_HMAC, and CKM_RIPEMD128_HMAC_GENERAL when explicitly selected.
    pub const RIPEMD128_HMAC: Self = Self {
        full: CKM_RIPEMD128_HMAC,
        general: Some(CKM_RIPEMD128_HMAC_GENERAL),
        output_bytes: 16,
    };
    /// CKM_RIPEMD160_HMAC, and CKM_RIPEMD160_HMAC_GENERAL when explicitly selected.
    pub const RIPEMD160_HMAC: Self = Self {
        full: CKM_RIPEMD160_HMAC,
        general: Some(CKM_RIPEMD160_HMAC_GENERAL),
        output_bytes: 20,
    };
    /// CKM_SHA224_HMAC, and CKM_SHA224_HMAC_GENERAL when explicitly selected.
    pub const SHA224_HMAC: Self = Self {
        full: CKM_SHA224_HMAC,
        general: Some(CKM_SHA224_HMAC_GENERAL),
        output_bytes: 28,
    };
    /// CKM_SHA256_HMAC, and CKM_SHA256_HMAC_GENERAL when explicitly selected.
    pub const SHA256_HMAC: Self = Self {
        full: CKM_SHA256_HMAC,
        general: Some(CKM_SHA256_HMAC_GENERAL),
        output_bytes: 32,
    };
    /// CKM_SHA384_HMAC, and CKM_SHA384_HMAC_GENERAL when explicitly selected.
    pub const SHA384_HMAC: Self = Self {
        full: CKM_SHA384_HMAC,
        general: Some(CKM_SHA384_HMAC_GENERAL),
        output_bytes: 48,
    };
    /// CKM_SHA512_HMAC, and CKM_SHA512_HMAC_GENERAL when explicitly selected.
    pub const SHA512_HMAC: Self = Self {
        full: CKM_SHA512_HMAC,
        general: Some(CKM_SHA512_HMAC_GENERAL),
        output_bytes: 64,
    };
    /// CKM_SHA3_224_HMAC, and CKM_SHA3_224_HMAC_GENERAL when explicitly selected.
    pub const SHA3_224_HMAC: Self = Self {
        full: CKM_SHA3_224_HMAC,
        general: Some(CKM_SHA3_224_HMAC_GENERAL),
        output_bytes: 28,
    };
    /// CKM_SHA3_256_HMAC, and CKM_SHA3_256_HMAC_GENERAL when explicitly selected.
    pub const SHA3_256_HMAC: Self = Self {
        full: CKM_SHA3_256_HMAC,
        general: Some(CKM_SHA3_256_HMAC_GENERAL),
        output_bytes: 32,
    };
    /// CKM_SHA3_384_HMAC, and CKM_SHA3_384_HMAC_GENERAL when explicitly selected.
    pub const SHA3_384_HMAC: Self = Self {
        full: CKM_SHA3_384_HMAC,
        general: Some(CKM_SHA3_384_HMAC_GENERAL),
        output_bytes: 48,
    };
    /// CKM_SHA3_512_HMAC, and CKM_SHA3_512_HMAC_GENERAL when explicitly selected.
    pub const SHA3_512_HMAC: Self = Self {
        full: CKM_SHA3_512_HMAC,
        general: Some(CKM_SHA3_512_HMAC_GENERAL),
        output_bytes: 64,
    };
    /// CKM_BLAKE2B_160_HMAC, and CKM_BLAKE2B_160_HMAC_GENERAL when explicitly selected.
    pub const BLAKE2B_160_HMAC: Self = Self {
        full: CKM_BLAKE2B_160_HMAC,
        general: Some(CKM_BLAKE2B_160_HMAC_GENERAL),
        output_bytes: 20,
    };
    /// CKM_BLAKE2B_256_HMAC, and CKM_BLAKE2B_256_HMAC_GENERAL when explicitly selected.
    pub const BLAKE2B_256_HMAC: Self = Self {
        full: CKM_BLAKE2B_256_HMAC,
        general: Some(CKM_BLAKE2B_256_HMAC_GENERAL),
        output_bytes: 32,
    };
    /// CKM_BLAKE2B_384_HMAC, and CKM_BLAKE2B_384_HMAC_GENERAL when explicitly selected.
    pub const BLAKE2B_384_HMAC: Self = Self {
        full: CKM_BLAKE2B_384_HMAC,
        general: Some(CKM_BLAKE2B_384_HMAC_GENERAL),
        output_bytes: 48,
    };
    /// CKM_BLAKE2B_512_HMAC, and CKM_BLAKE2B_512_HMAC_GENERAL when explicitly selected.
    pub const BLAKE2B_512_HMAC: Self = Self {
        full: CKM_BLAKE2B_512_HMAC,
        general: Some(CKM_BLAKE2B_512_HMAC_GENERAL),
        output_bytes: 64,
    };
    /// CKM_DES_MAC, and CKM_DES_MAC_GENERAL when explicitly selected.
    pub const DES_MAC: Self = Self {
        full: CKM_DES_MAC,
        general: Some(CKM_DES_MAC_GENERAL),
        output_bytes: 4,
    };
    /// CKM_DES3_MAC, and CKM_DES3_MAC_GENERAL when explicitly selected.
    pub const DES3_MAC: Self = Self {
        full: CKM_DES3_MAC,
        general: Some(CKM_DES3_MAC_GENERAL),
        output_bytes: 4,
    };
    /// CKM_DES3_CMAC, and CKM_DES3_CMAC_GENERAL when explicitly selected.
    pub const DES3_CMAC: Self = Self {
        full: CKM_DES3_CMAC,
        general: Some(CKM_DES3_CMAC_GENERAL),
        output_bytes: 8,
    };
    /// CKM_CDMF_MAC, and CKM_CDMF_MAC_GENERAL when explicitly selected.
    pub const CDMF_MAC: Self = Self {
        full: CKM_CDMF_MAC,
        general: Some(CKM_CDMF_MAC_GENERAL),
        output_bytes: 4,
    };
    /// CKM_CAST_MAC, and CKM_CAST_MAC_GENERAL when explicitly selected.
    pub const CAST_MAC: Self = Self {
        full: CKM_CAST_MAC,
        general: Some(CKM_CAST_MAC_GENERAL),
        output_bytes: 4,
    };
    /// CKM_CAST3_MAC, and CKM_CAST3_MAC_GENERAL when explicitly selected.
    pub const CAST3_MAC: Self = Self {
        full: CKM_CAST3_MAC,
        general: Some(CKM_CAST3_MAC_GENERAL),
        output_bytes: 4,
    };
    /// CKM_CAST5_MAC, and CKM_CAST5_MAC_GENERAL when explicitly selected.
    pub const CAST5_MAC: Self = Self {
        full: CKM_CAST5_MAC,
        general: Some(CKM_CAST5_MAC_GENERAL),
        output_bytes: 4,
    };
    /// CKM_CAST128_MAC, and CKM_CAST128_MAC_GENERAL when explicitly selected.
    pub const CAST128_MAC: Self = Self {
        full: CKM_CAST128_MAC,
        general: Some(CKM_CAST128_MAC_GENERAL),
        output_bytes: 4,
    };
    /// CKM_IDEA_MAC, and CKM_IDEA_MAC_GENERAL when explicitly selected.
    pub const IDEA_MAC: Self = Self {
        full: CKM_IDEA_MAC,
        general: Some(CKM_IDEA_MAC_GENERAL),
        output_bytes: 4,
    };
    /// CKM_CAMELLIA_MAC, and CKM_CAMELLIA_MAC_GENERAL when explicitly selected.
    pub const CAMELLIA_MAC: Self = Self {
        full: CKM_CAMELLIA_MAC,
        general: Some(CKM_CAMELLIA_MAC_GENERAL),
        output_bytes: 8,
    };
    /// CKM_ARIA_MAC, and CKM_ARIA_MAC_GENERAL when explicitly selected.
    pub const ARIA_MAC: Self = Self {
        full: CKM_ARIA_MAC,
        general: Some(CKM_ARIA_MAC_GENERAL),
        output_bytes: 8,
    };
    /// CKM_SEED_MAC, and CKM_SEED_MAC_GENERAL when explicitly selected.
    pub const SEED_MAC: Self = Self {
        full: CKM_SEED_MAC,
        general: Some(CKM_SEED_MAC_GENERAL),
        output_bytes: 8,
    };
    /// CKM_AES_MAC, and CKM_AES_MAC_GENERAL when explicitly selected.
    pub const AES_MAC: Self = Self {
        full: CKM_AES_MAC,
        general: Some(CKM_AES_MAC_GENERAL),
        output_bytes: 8,
    };
    /// CKM_AES_CMAC, and CKM_AES_CMAC_GENERAL when explicitly selected.
    pub const AES_CMAC: Self = Self {
        full: CKM_AES_CMAC,
        general: Some(CKM_AES_CMAC_GENERAL),
        output_bytes: 16,
    };
    /// CKM_AES_XCBC_MAC, without a general-length counterpart.
    pub const AES_XCBC_MAC: Self = Self {
        full: CKM_AES_XCBC_MAC,
        general: None,
        output_bytes: 16,
    };
    /// CKM_AES_XCBC_MAC_96, without a general-length counterpart.
    pub const AES_XCBC_MAC_96: Self = Self {
        full: CKM_AES_XCBC_MAC_96,
        general: None,
        output_bytes: 12,
    };
    /// CKM_POLY1305, without a general-length counterpart.
    pub const POLY1305: Self = Self {
        full: CKM_POLY1305,
        general: None,
        output_bytes: 16,
    };
    /// All full-MAC selectors, including the documented CAST128 alias.
    pub const ALL: &'static [Self] = &[
        Self::SHA512_224_HMAC,
        Self::SHA512_256_HMAC,
        Self::MD2_HMAC,
        Self::MD5_HMAC,
        Self::SHA_1_HMAC,
        Self::RIPEMD128_HMAC,
        Self::RIPEMD160_HMAC,
        Self::SHA224_HMAC,
        Self::SHA256_HMAC,
        Self::SHA384_HMAC,
        Self::SHA512_HMAC,
        Self::SHA3_224_HMAC,
        Self::SHA3_256_HMAC,
        Self::SHA3_384_HMAC,
        Self::SHA3_512_HMAC,
        Self::BLAKE2B_160_HMAC,
        Self::BLAKE2B_256_HMAC,
        Self::BLAKE2B_384_HMAC,
        Self::BLAKE2B_512_HMAC,
        Self::DES_MAC,
        Self::DES3_MAC,
        Self::DES3_CMAC,
        Self::CDMF_MAC,
        Self::CAST_MAC,
        Self::CAST3_MAC,
        Self::CAST5_MAC,
        Self::CAST128_MAC,
        Self::IDEA_MAC,
        Self::CAMELLIA_MAC,
        Self::ARIA_MAC,
        Self::SEED_MAC,
        Self::AES_MAC,
        Self::AES_CMAC,
        Self::AES_XCBC_MAC,
        Self::AES_XCBC_MAC_96,
        Self::POLY1305,
    ];
    /// Exact full-MAC native identifier.
    pub fn mechanism_number(self) -> u64 {
        self.full as u64
    }
}
/// Scalar interpretation asserted for the underspecified SHA512/t general HMAC.
/// Its ABI is CK_ULONG; no t value is inferred from the requested MAC length.
#[derive(Clone, Copy, Debug)]
pub struct Sha512TMacGeneral {
    scalar: CK_ULONG,
}
impl Sha512TMacGeneral {
    /// Assert the scalar meaning for the selected module's actual contract.
    ///
    /// # Safety
    /// The caller must establish this scalar's interpretation for the selected
    /// module/interface. This constructor does not assert a published t encoding.
    /// The native implementation must use the scalar ABI, obey ordinary Sign/
    /// Verify buffer capacities. The caller's output capacity is passed unchanged;
    /// this assertion does not authorize a write beyond that allocation.
    pub unsafe fn new(scalar: u64) -> Result<Self> {
        Ok(Self {
            scalar: native_scalar(scalar)?,
        })
    }
}
/// MAC parameters exactly supplied to the native module. Fe11 does not infer a
/// key type, rehash a message, choose a truncation or impose a crypto profile.
pub enum NativeMacParameters<'a> {
    /// Full output; CK_MECHANISM parameter is NULL/0.
    Full(NativeMacAlgorithm),
    /// General-length variant with CK_MAC_GENERAL_PARAMS, in bytes.
    General {
        /// Exact native algorithm selection; declaration does not imply module support.
        algorithm: NativeMacAlgorithm,

        /// Requested native MAC length in bytes, without a local truncation policy.
        output_bytes: u64,
    },
    /// CKM_SHA512_T_HMAC, with the caller's t in bits as CK_ULONG.
    Sha512T {
        /// Requested SHA-512/t hash width in bits, passed as a native scalar.
        bits: u64,
    },
    /// Explicitly asserted scalar semantics; no hidden t inference.
    Sha512TGeneral(Sha512TMacGeneral),
    /// RC2 effective key bits; Some selects RC2_MAC_GENERAL with that MAC byte length.
    Rc2 {
        /// Native RC2 effective-key width in bits.
        effective_bits: u64,

        /// Some selects the GENERAL mechanism and this byte length; None selects full MAC output.
        output_bytes: Option<u64>,
    },
    /// RC5 word size in bytes and rounds; Some selects RC5_MAC_GENERAL.
    Rc5 {
        /// Native RC5 word width in bytes.
        word_bytes: u64,

        /// Native RC5 round count; suitability is an application/module decision.
        rounds: u64,

        /// Some selects the GENERAL mechanism and this byte length; None selects full MAC output.
        output_bytes: Option<u64>,
    },
    /// SSL3 MD5 MAC and exact CK_MAC_GENERAL_PARAMS byte length.
    Ssl3Md5 {
        /// Requested native MAC length in bytes, without a local truncation policy.
        output_bytes: u64,
    },
    /// SSL3 SHA1 MAC and exact CK_MAC_GENERAL_PARAMS byte length.
    Ssl3Sha1 {
        /// Requested native MAC length in bytes, without a local truncation policy.
        output_bytes: u64,
    },
    /// CKM_TLS_MAC; role 1 is server and 2 is client, validated by the module.
    Tls {
        /// Caller-selected native hash mechanism identifier (CKM); no implicit hashing substitution.
        hash: u64,

        /// Requested native MAC length in bytes, without a local truncation policy.
        output_bytes: u64,

        /// Exact native role selector: 1 for server, 2 for client.
        server_or_client: u64,
    },
    /// CKM_TLS12_MAC with its distinct native identifier and the same struct ABI.
    Tls12 {
        /// Caller-selected native hash mechanism identifier (CKM); no implicit hashing substitution.
        hash: u64,

        /// Requested native MAC length in bytes, without a local truncation policy.
        output_bytes: u64,

        /// Exact native role selector: 1 for server, 2 for client.
        server_or_client: u64,
    },
    /// CKM_GOSTR3411_HMAC, with an exact optional DER OID. None and empty differ.
    GostR3411 {
        /// Optional DER-encoded parameter-set OID; None and present empty remain distinct.
        oid: Option<&'a [u8]>,
    },
    /// CKM_GOST28147_MAC with an exact eight-byte IV.
    Gost28147 {
        /// Exact initialization-vector bytes, copied into the native parameter owner.
        iv: &'a [u8; 8],
    },
    /// CKM_AES_GMAC with CK_GCM_PARAMS. The Sign/Verify input is the AAD.
    AesGmac {
        /// Exact initialization-vector bytes, copied into the native parameter owner.
        iv: &'a [u8],
        /// Requested authentication-tag length in bits.
        tag_bits: u64,
    },
}
fn native_scalar(value: u64) -> Result<CK_ULONG> {
    CK_ULONG::try_from(value).map_err(|_| {
        Error::Rejected(crate::RejectionReason::NativeMac(
            crate::NativeMacRejection::MacParameterNativeScalarWidth,
        ))
    })
}
impl NativeMacParameters<'_> {
    /// Exact requested identifier; absent GENERAL counterparts have no invented ID.
    pub fn mechanism_number(&self) -> Result<u64> {
        Ok(match self {
            Self::Full(algorithm) => algorithm.full,
            Self::General { algorithm, .. } => {
                algorithm
                    .general
                    .ok_or(Error::Unsupported(crate::UnsupportedReason::NativeMac(
                        crate::NativeMacUnsupported::MacHasNoGeneralLengthVariant,
                    )))?
            }
            Self::Sha512T { .. } => CKM_SHA512_T_HMAC,
            Self::Sha512TGeneral(_) => CKM_SHA512_T_HMAC_GENERAL,
            Self::Rc2 {
                output_bytes: None, ..
            } => CKM_RC2_MAC,
            Self::Rc2 {
                output_bytes: Some(_),
                ..
            } => CKM_RC2_MAC_GENERAL,
            Self::Rc5 {
                output_bytes: None, ..
            } => CKM_RC5_MAC,
            Self::Rc5 {
                output_bytes: Some(_),
                ..
            } => CKM_RC5_MAC_GENERAL,
            Self::Ssl3Md5 { .. } => CKM_SSL3_MD5_MAC,
            Self::Ssl3Sha1 { .. } => CKM_SSL3_SHA1_MAC,
            Self::Tls { .. } => CKM_TLS_MAC,
            Self::Tls12 { .. } => CKM_TLS12_MAC,
            Self::GostR3411 { .. } => CKM_GOSTR3411_HMAC,
            Self::Gost28147 { .. } => CKM_GOST28147_MAC,
            Self::AesGmac { .. } => CKM_AES_GMAC,
        } as u64)
    }
    fn expected_output_bytes(&self) -> Result<Option<usize>> {
        let bytes = match self {
            Self::Full(algorithm) => return Ok(Some(algorithm.output_bytes)),
            Self::General { output_bytes, .. }
            | Self::Ssl3Md5 { output_bytes }
            | Self::Ssl3Sha1 { output_bytes }
            | Self::Tls { output_bytes, .. }
            | Self::Tls12 { output_bytes, .. } => *output_bytes,
            Self::Sha512T { bits } => bits.div_ceil(8),
            Self::Sha512TGeneral(_) => return Ok(None),
            Self::Rc2 { output_bytes, .. } => output_bytes.unwrap_or(4),
            Self::Rc5 {
                word_bytes,
                output_bytes,
                ..
            } => output_bytes.unwrap_or(*word_bytes),
            Self::GostR3411 { .. } => 32,
            Self::Gost28147 { .. } => 4,
            Self::AesGmac { tag_bits, .. } => tag_bits.div_ceil(8),
        };
        usize::try_from(bytes).map(Some).map_err(|_| {
            Error::Rejected(crate::RejectionReason::NativeMac(
                crate::NativeMacRejection::MacOutputLengthRepresentation,
            ))
        })
    }
    fn scalar_values(&self) -> Result<([CK_ULONG; 3], usize)> {
        let (values, count) = match self {
            Self::Full(_)
            | Self::GostR3411 { .. }
            | Self::Gost28147 { .. }
            | Self::AesGmac { .. } => ([0, 0, 0], 0),
            Self::General { output_bytes, .. }
            | Self::Ssl3Md5 { output_bytes }
            | Self::Ssl3Sha1 { output_bytes } => ([*output_bytes, 0, 0], 1),
            Self::Sha512T { bits } => ([*bits, 0, 0], 1),
            Self::Sha512TGeneral(value) => ([value.scalar as u64, 0, 0], 1),
            Self::Rc2 {
                effective_bits,
                output_bytes,
            } => (
                [*effective_bits, output_bytes.unwrap_or(0), 0],
                if output_bytes.is_some() { 2 } else { 1 },
            ),
            Self::Rc5 {
                word_bytes,
                rounds,
                output_bytes,
            } => (
                [*word_bytes, *rounds, output_bytes.unwrap_or(0)],
                if output_bytes.is_some() { 3 } else { 2 },
            ),
            Self::Tls {
                hash,
                output_bytes,
                server_or_client,
            }
            | Self::Tls12 {
                hash,
                output_bytes,
                server_or_client,
            } => ([*hash, *output_bytes, *server_or_client], 3),
        };
        Ok((
            [
                native_scalar(values[0])?,
                native_scalar(values[1])?,
                native_scalar(values[2])?,
            ],
            count,
        ))
    }
}
/// Exact native MAC bytes with retained memory credit. No secret output is cloned.
pub struct NativeMac {
    pub(crate) bytes: crate::symmetric::memory::Buffer,
    mechanism: u64,
    provenance: MechanismLayoutProvenance,
}
impl NativeMac {
    /// Borrow the complete returned native value, without implicit truncation.
    pub fn as_bytes(&self) -> &[u8] {
        self.bytes.as_slice()
    }
    /// Native mechanism actually requested.
    pub fn mechanism_number(&self) -> u64 {
        self.mechanism
    }
    /// Standard representation or explicitly asserted SHA512/t semantics.
    pub fn provenance(&self) -> MechanismLayoutProvenance {
        self.provenance
    }
}
fn put_scalar(bytes: &mut [u8], offset: usize, scalar: CK_ULONG) {
    bytes[offset..offset + size_of::<CK_ULONG>()].copy_from_slice(&scalar.to_ne_bytes());
}
fn perform(
    session: &Session,
    parameters: NativeMacParameters<'_>,
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
    parameters: NativeMacParameters<'_>,
    operation: ExtensionOperation,
    consume: impl FnOnce(ExtensionRequest<'_>) -> Result<T>,
) -> Result<T> {
    let kind = parameters.mechanism_number()? as CK_MECHANISM_TYPE;
    let contract = MechanismExtension::standard(&session.inner, kind, operation);
    let contract = if matches!(&parameters, NativeMacParameters::Sha512TGeneral(_)) {
        contract.with_asserted_layout()
    } else {
        contract
    };
    let (scalars, count) = parameters.scalar_values()?;
    // These standard layouts contain only adjacent native unsigned scalars;
    // zeroed padding is used only for GCM's explicit pointer-bearing structure.
    let mut encoded = [0u8; size_of::<CK_GCM_PARAMS>()];
    for (index, scalar) in scalars[..count].iter().enumerate() {
        put_scalar(&mut encoded, index * size_of::<CK_ULONG>(), *scalar);
    }
    let scalar_length = count * size_of::<CK_ULONG>();
    let result = match &parameters {
        NativeMacParameters::AesGmac { iv, tag_bits } => {
            let iv_length = bounds::ck_length(iv.len())?;
            put_scalar(&mut encoded, offset_of!(CK_GCM_PARAMS, ulIvLen), iv_length);
            // Share GCM's auxiliary-field representation, including overflow.
            put_scalar(
                &mut encoded,
                offset_of!(CK_GCM_PARAMS, ulIvBits),
                bounds::gcm_iv_bits(iv_length),
            );
            put_scalar(&mut encoded, offset_of!(CK_GCM_PARAMS, ulAADLen), 0);
            put_scalar(
                &mut encoded,
                offset_of!(CK_GCM_PARAMS, ulTagBits),
                native_scalar(*tag_bits)?,
            );
            let blocks = [
                ExtensionBlock {
                    initial: &encoded,
                    alignment: align_of::<CK_GCM_PARAMS>(),
                    direction: ExtensionDirection::Input,
                },
                ExtensionBlock {
                    initial: iv,
                    alignment: 1,
                    direction: ExtensionDirection::Input,
                },
            ];
            let pointers = [
                ExtensionPointer {
                    block: 0,
                    offset: offset_of!(CK_GCM_PARAMS, pIv),
                    target: ExtensionPointerTarget::Block {
                        block: 1,
                        offset: 0,
                    },
                },
                ExtensionPointer {
                    block: 0,
                    offset: offset_of!(CK_GCM_PARAMS, pAAD),
                    target: ExtensionPointerTarget::Null,
                },
            ];
            consume(ExtensionRequest {
                contract: &contract,
                parameters: ExtensionParameters {
                    blocks: &blocks,
                    pointers: &pointers,
                    root: Some(0),
                    outputs: &[],
                },
            })
        }
        _ => {
            let bytes: Option<&[u8]> = match &parameters {
                NativeMacParameters::Full(_) => None,
                NativeMacParameters::GostR3411 { oid } => *oid,
                NativeMacParameters::Gost28147 { iv } => Some(&iv[..]),
                _ => Some(&encoded[..scalar_length]),
            };
            let blocks = [ExtensionBlock {
                initial: bytes.unwrap_or(&[]),
                alignment: align_of::<CK_ULONG>(),
                direction: ExtensionDirection::Input,
            }];
            consume(ExtensionRequest {
                contract: &contract,
                parameters: ExtensionParameters {
                    blocks: if bytes.is_some() { &blocks } else { &[] },
                    pointers: &[],
                    root: bytes.map(|_| 0),
                    outputs: &[],
                },
            })
        }
    }?;
    Ok(result)
}
impl Session {
    /// Native MAC, preserving the explicitly chosen single/multipart route and
    /// exact input chunks. Output capacity is storage only. Native refusals are
    /// returned without a local key-size/policy check or alternative mechanism.
    pub fn compute_native_mac(
        &self,
        key: &NativeObjectRef,
        parameters: NativeMacParameters<'_>,
        route: MessageRoute,
        parts: &[&[u8]],
        limits: InputLimits,
        output_capacity: usize,
        authentication: Option<crate::ContextAuthentication>,
    ) -> Result<NativeMac> {
        let mut extension_diagnostics =
            crate::mechanism_extension::operation::Invocation::default();
        self.compute_native_mac_with_diagnostics(
            key,
            parameters,
            route,
            parts,
            limits,
            output_capacity,
            authentication,
            &mut extension_diagnostics,
        )
    }

    // Internal callers supply their outer publication owner; no helper
    // return may release the credit of an error still being projected.
    pub(crate) fn compute_native_mac_with_diagnostics(
        &self,
        key: &NativeObjectRef,
        parameters: NativeMacParameters<'_>,
        route: MessageRoute,
        parts: &[&[u8]],
        limits: InputLimits,
        output_capacity: usize,
        authentication: Option<crate::ContextAuthentication>,
        extension_diagnostics: &mut crate::mechanism_extension::operation::Invocation,
    ) -> Result<NativeMac> {
        let mechanism = parameters.mechanism_number()?;
        let expected = parameters.expected_output_bytes()?;
        let asserted = matches!(&parameters, NativeMacParameters::Sha512TGeneral(_));
        let capacity = output_capacity;
        let (input, operation) = match route {
            MessageRoute::Single => {
                if parts.len() != 1 {
                    return Err(Error::Rejected(crate::RejectionReason::NativeMac(
                        crate::NativeMacRejection::SinglePartMacRequiresOneInput,
                    )));
                }
                (
                    ExtensionInput::Sign {
                        key,
                        input: parts[0],
                        output_capacity: capacity,
                    },
                    ExtensionOperation::Sign,
                )
            }
            MessageRoute::Multipart => (
                ExtensionInput::SignMultipart {
                    key,
                    parts,
                    output_capacity: capacity,
                },
                ExtensionOperation::SignMultipart,
            ),
        };
        with_parameters(self, parameters, operation, |request| {
            operation::execute_with_sources_and_publish(
                self,
                request,
                input,
                limits,
                authentication,
                1,
                [None; 4],
                |result| {
                    if expected.is_some_and(|length| result.as_bytes().len() != length) {
                        return Err(Error::Rejected(
                            crate::RejectionReason::NativeMac(crate::NativeMacRejection::NativeMacOutputLengthDiffersFromSelectedParameters),
                        ));
                    }
                    Ok(NativeMac {
                        bytes: result.bytes,
                        mechanism,
                        provenance: if asserted {
                            MechanismLayoutProvenance::CallerAssertedLayout
                        } else {
                            MechanismLayoutProvenance::StandardLayout
                        },
                    })
                },
                extension_diagnostics,
            )
        })
    }
    /// Native MAC verification. CKR_SIGNATURE_INVALID/LEN_RANGE remain native
    /// refusals; this method performs no software comparison or normalization.
    pub fn verify_native_mac(
        &self,
        key: &NativeObjectRef,
        parameters: NativeMacParameters<'_>,
        route: MessageRoute,
        parts: &[&[u8]],
        signature: &[u8],
        limits: InputLimits,
        authentication: Option<crate::ContextAuthentication>,
    ) -> Result<()> {
        let mut extension_diagnostics =
            crate::mechanism_extension::operation::Invocation::default();
        self.verify_native_mac_with_diagnostics(
            key,
            parameters,
            route,
            parts,
            signature,
            limits,
            authentication,
            &mut extension_diagnostics,
        )
    }

    // Internal callers supply their outer publication owner; no helper
    // return may release the credit of an error still being projected.
    pub(crate) fn verify_native_mac_with_diagnostics(
        &self,
        key: &NativeObjectRef,
        parameters: NativeMacParameters<'_>,
        route: MessageRoute,
        parts: &[&[u8]],
        signature: &[u8],
        limits: InputLimits,
        authentication: Option<crate::ContextAuthentication>,
        extension_diagnostics: &mut crate::mechanism_extension::operation::Invocation,
    ) -> Result<()> {
        let (input, operation) = match route {
            MessageRoute::Single => {
                if parts.len() != 1 {
                    return Err(Error::Rejected(crate::RejectionReason::NativeMac(
                        crate::NativeMacRejection::SinglePartMacRequiresOneInput,
                    )));
                }
                (
                    ExtensionInput::Verify {
                        key,
                        input: parts[0],
                        signature,
                    },
                    ExtensionOperation::Verify,
                )
            }
            MessageRoute::Multipart => (
                ExtensionInput::VerifyMultipart {
                    key,
                    parts,
                    signature,
                },
                ExtensionOperation::VerifyMultipart,
            ),
        };
        perform(
            self,
            parameters,
            input,
            operation,
            limits,
            authentication,
            extension_diagnostics,
        )
        .map(|_| ())
    }
    /// Verify a MAC through C_VerifySignatureInit, passing the expected
    /// bytes at Init. Single and Multipart retain their exact native calls;
    /// no fallback to C_VerifyInit or local comparison is performed.
    /// The module decides whether this standard mechanism supports the route.
    pub fn verify_signature_native_mac(
        &self,
        key: &NativeObjectRef,
        parameters: NativeMacParameters<'_>,
        route: MessageRoute,
        parts: &[&[u8]],
        signature: &[u8],
        limits: InputLimits,
        authentication: Option<crate::ContextAuthentication>,
    ) -> Result<()> {
        let mut extension_diagnostics =
            crate::mechanism_extension::operation::Invocation::default();
        let (input, operation) = match route {
            MessageRoute::Single => {
                if parts.len() != 1 {
                    return Err(Error::Rejected(crate::RejectionReason::NativeMac(
                        crate::NativeMacRejection::SinglePartMacRequiresOneInput,
                    )));
                }
                (
                    ExtensionInput::VerifySignature {
                        key,
                        input: parts[0],
                        signature,
                    },
                    ExtensionOperation::VerifySignature,
                )
            }
            MessageRoute::Multipart => (
                ExtensionInput::VerifySignatureMultipart {
                    key,
                    parts,
                    signature,
                },
                ExtensionOperation::VerifySignatureMultipart,
            ),
        };
        perform(
            self,
            parameters,
            input,
            operation,
            limits,
            authentication,
            &mut extension_diagnostics,
        )
        .map(|_| ())
    }
}
impl crate::AdvancedSession {
    /// Synchronous standard MAC through the same owner as Session.
    pub fn compute_native_mac(
        &self,
        key: &NativeObjectRef,
        parameters: NativeMacParameters<'_>,
        route: MessageRoute,
        parts: &[&[u8]],
        limits: InputLimits,
        output_capacity: usize,
        authentication: Option<crate::ContextAuthentication>,
    ) -> Result<NativeMac> {
        let mut extension_diagnostics =
            crate::mechanism_extension::operation::Invocation::default();
        self.session.compute_native_mac_with_diagnostics(
            key,
            parameters,
            route,
            parts,
            limits,
            output_capacity,
            authentication,
            &mut extension_diagnostics,
        )
    }
    /// Synchronous verification; no asynchronous PKCS#11 operation is introduced.
    pub fn verify_native_mac(
        &self,
        key: &NativeObjectRef,
        parameters: NativeMacParameters<'_>,
        route: MessageRoute,
        parts: &[&[u8]],
        signature: &[u8],
        limits: InputLimits,
        authentication: Option<crate::ContextAuthentication>,
    ) -> Result<()> {
        let mut extension_diagnostics =
            crate::mechanism_extension::operation::Invocation::default();
        self.session.verify_native_mac_with_diagnostics(
            key,
            parameters,
            route,
            parts,
            signature,
            limits,
            authentication,
            &mut extension_diagnostics,
        )
    }
    /// Verify through C_VerifySignature with the selected validation capture.
    /// Ok reports native verification success; Some contains the requested
    /// observations, while None means capture was disabled. Flags do not assert
    /// certification. Exact native refusals remain errors, without route fallback.
    /// This synchronous facade preserves context authentication and input chunks.
    pub fn verify_signature_native_mac(
        &self,
        key: &NativeObjectRef,
        parameters: NativeMacParameters<'_>,
        route: MessageRoute,
        parts: &[&[u8]],
        signature: &[u8],
        limits: InputLimits,
        authentication: Option<crate::ContextAuthentication>,
    ) -> Result<Option<crate::ValidationReport>> {
        let mut signature_diagnostics = crate::advanced::signature::batch::Invocation::default();
        let (input, operation) = match route {
            MessageRoute::Single => {
                if parts.len() != 1 {
                    return Err(Error::Rejected(crate::RejectionReason::NativeMac(
                        crate::NativeMacRejection::SinglePartMacRequiresOneInput,
                    )));
                }
                (
                    ExtensionInput::VerifySignature {
                        key,
                        input: parts[0],
                        signature,
                    },
                    ExtensionOperation::VerifySignature,
                )
            }
            MessageRoute::Multipart => (
                ExtensionInput::VerifySignatureMultipart {
                    key,
                    parts,
                    signature,
                },
                ExtensionOperation::VerifySignatureMultipart,
            ),
        };
        with_parameters(&self.session, parameters, operation, |request| {
            self.execute_signature_batch(
                request,
                input,
                limits,
                authentication,
                &mut signature_diagnostics,
            )
            .map(|(_result, report)| report)
        })
    }
}
