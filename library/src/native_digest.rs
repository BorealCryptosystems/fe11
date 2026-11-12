// SPDX-License-Identifier: Apache-2.0
//! Native digests, including an explicitly bounded variable-length NULL route.
use crate::symmetric::memory::Buffer;
use crate::{Error, Result};
use fe11_sys::*;

/// A native PKCS#11 digest with a fixed width or a caller-selected output bound.
///
/// This selection does not assert module support or recommend an algorithm.
/// In particular, legacy algorithms remain callable for interoperability.
/// It does not extend the algorithms accepted by signature prehash APIs.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum NativeDigestAlgorithm {
    /// CKM_NULL copies the input stream, including native DigestKey input.
    /// The caller supplies the maximum output capacity; this is not a hash or a
    /// signature-prehash assertion and may expose otherwise accessible key data.
    Null(NativeNullDigestCapacity),
    /// CKM_GOSTR3411 with no OID parameter (the native default parameter set).
    /// To supply an exact OID, use the explicit GOST digest entry points.
    GostR3411,
    /// CKM_SHA512_T with the exact caller-selected bit count. Use
    /// NativeDigestTruncation::new; cryptographic admissibility remains native.
    Sha512T(NativeDigestTruncation),
    /// CKM_MD2 (16 bytes).
    Md2,
    /// CKM_MD5 (16 bytes).
    Md5,
    /// Historical CKM_FASTHASH (40 bytes).
    FastHash,
    /// CKM_SHA_1 (20 bytes).
    Sha1,
    /// CKM_RIPEMD128 (16 bytes).
    Ripemd128,
    /// CKM_RIPEMD160 (20 bytes).
    Ripemd160,
    /// CKM_SHA224 (28 bytes).
    Sha224,
    /// CKM_SHA256 (32 bytes).
    Sha256,
    /// CKM_SHA384 (48 bytes).
    Sha384,
    /// CKM_SHA512 (64 bytes).
    Sha512,
    /// CKM_SHA512_224 (28 bytes).
    Sha512_224,
    /// CKM_SHA512_256 (32 bytes).
    Sha512_256,
    /// CKM_SHA3_224 (28 bytes).
    Sha3_224,
    /// CKM_SHA3_256 (32 bytes).
    Sha3_256,
    /// CKM_SHA3_384 (48 bytes).
    Sha3_384,
    /// CKM_SHA3_512 (64 bytes).
    Sha3_512,
    /// CKM_BLAKE2B_160 (20 bytes).
    Blake2b160,
    /// CKM_BLAKE2B_256 (32 bytes).
    Blake2b256,
    /// CKM_BLAKE2B_384 (48 bytes).
    Blake2b384,
    /// CKM_BLAKE2B_512 (64 bytes).
    Blake2b512,
}

impl NativeDigestAlgorithm {
    /// Parameterless fixed-width selections; SHA-512/t and NULL need explicit sizing.
    pub const ALL: [Self; 21] = [
        Self::GostR3411,
        Self::Md2,
        Self::Md5,
        Self::FastHash,
        Self::Sha1,
        Self::Ripemd128,
        Self::Ripemd160,
        Self::Sha224,
        Self::Sha256,
        Self::Sha384,
        Self::Sha512,
        Self::Sha512_224,
        Self::Sha512_256,
        Self::Sha3_224,
        Self::Sha3_256,
        Self::Sha3_384,
        Self::Sha3_512,
        Self::Blake2b160,
        Self::Blake2b256,
        Self::Blake2b384,
        Self::Blake2b512,
    ];

    /// Exact PKCS#11 mechanism identifier.
    pub fn mechanism_number(self) -> u64 {
        self.mechanism() as u64
    }

    pub(crate) fn mechanism(self) -> CK_MECHANISM_TYPE {
        match self {
            Self::Null(_) => CKM_NULL,
            Self::GostR3411 => CKM_GOSTR3411,
            Self::Sha512T(_) => CKM_SHA512_T,
            Self::Md2 => CKM_MD2,
            Self::Md5 => CKM_MD5,
            Self::FastHash => CKM_FASTHASH,
            Self::Sha1 => CKM_SHA_1,
            Self::Ripemd128 => CKM_RIPEMD128,
            Self::Ripemd160 => CKM_RIPEMD160,
            Self::Sha224 => CKM_SHA224,
            Self::Sha256 => CKM_SHA256,
            Self::Sha384 => CKM_SHA384,
            Self::Sha512 => CKM_SHA512,
            Self::Sha512_224 => CKM_SHA512_224,
            Self::Sha512_256 => CKM_SHA512_256,
            Self::Sha3_224 => CKM_SHA3_224,
            Self::Sha3_256 => CKM_SHA3_256,
            Self::Sha3_384 => CKM_SHA3_384,
            Self::Sha3_512 => CKM_SHA3_512,
            Self::Blake2b160 => CKM_BLAKE2B_160,
            Self::Blake2b256 => CKM_BLAKE2B_256,
            Self::Blake2b384 => CKM_BLAKE2B_384,
            Self::Blake2b512 => CKM_BLAKE2B_512,
        }
    }

    /// Fixed output width, or the caller's maximum capacity for CKM_NULL.
    /// A completed NULL result may contain fewer bytes.
    pub fn output_length(self) -> usize {
        match self {
            Self::Null(value) => value.bytes,
            Self::GostR3411 => 32,
            Self::Sha512T(value) => value.bytes,
            Self::Md2 | Self::Md5 | Self::Ripemd128 => 16,
            Self::FastHash => 40,
            Self::Sha1 | Self::Ripemd160 | Self::Blake2b160 => 20,
            Self::Sha224 | Self::Sha512_224 | Self::Sha3_224 => 28,
            Self::Sha256 | Self::Sha512_256 | Self::Sha3_256 | Self::Blake2b256 => 32,
            Self::Sha384 | Self::Sha3_384 | Self::Blake2b384 => 48,
            Self::Sha512 | Self::Sha3_512 | Self::Blake2b512 => 64,
        }
    }

    pub(crate) fn accepts_length(self, length: usize) -> bool {
        match self {
            Self::Null(capacity) => length <= capacity.bytes,
            _ => length == self.output_length(),
        }
    }

    /// Exact truncation bit count, when the mechanism has that scalar parameter.
    pub fn truncation_bits(self) -> Option<u64> {
        match self {
            Self::Sha512T(value) => Some(value.bits as u64),
            _ => None,
        }
    }
    pub(crate) fn parameter(self) -> Option<CK_ULONG> {
        match self {
            Self::Sha512T(value) => Some(value.bits),
            _ => None,
        }
    }

    /// Resolve an exact identifier only; no alias to a different algorithm.
    pub fn from_mechanism(number: u64) -> Option<Self> {
        Self::ALL
            .into_iter()
            .find(|item| item.mechanism_number() == number)
    }
}

/// Caller-selected output bound for CKM_NULL. No provider query, key-value
/// observation or replay is used to discover this bound. A native requirement
/// exceeding it remains a refusal with the operation's native effect retained.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct NativeNullDigestCapacity {
    bytes: usize,
}
impl NativeNullDigestCapacity {
    /// Check only ABI representability. Memory-budget admission occurs at use.
    pub fn new(maximum_output_bytes: usize) -> Result<Self> {
        crate::bounds::ck_length(maximum_output_bytes)?;
        Ok(Self {
            bytes: maximum_output_bytes,
        })
    }
    /// Selected maximum, not the eventual returned length.
    pub fn maximum_output_bytes(self) -> usize {
        self.bytes
    }
}

/// SHA-512/t scalar and its checked output allocation width.
/// This type checks ABI/host representability only, not the algorithm's allowed
/// t values. Values such as zero, 384 or 512 reach C_DigestInit unchanged so the
/// module can return its native mechanism-parameter refusal.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct NativeDigestTruncation {
    bits: CK_ULONG,
    bytes: usize,
}
impl NativeDigestTruncation {
    /// Bit count encoded exactly as CK_ULONG on this target.
    pub fn new(bits: u64) -> Result<Self> {
        let native = CK_ULONG::try_from(bits).map_err(|_| {
            Error::Rejected(crate::RejectionReason::NativeDigest(
                crate::NativeDigestRejection::DigestBitCountAbiWidth,
            ))
        })?;
        let bytes = usize::try_from(bits / 8 + u64::from(bits % 8 != 0)).map_err(|_| {
            Error::Rejected(crate::RejectionReason::NativeDigest(
                crate::NativeDigestRejection::DigestOutputHostWidth,
            ))
        })?;
        Ok(Self {
            bits: native,
            bytes,
        })
    }
    /// Original bit count, without rounding to whole bytes.
    pub fn bits(self) -> u64 {
        self.bits as u64
    }
}

/// A completed native digest. Its storage remains credited and is erased on drop.
/// It is not a signature-prehash provenance assertion.
pub struct NativeDigest {
    algorithm: NativeDigestAlgorithm,
    bytes: Buffer,
}

impl NativeDigest {
    /// Algorithm selected for the native operation.
    pub fn algorithm(&self) -> NativeDigestAlgorithm {
        self.algorithm
    }

    /// Digest bytes, available only after successful native completion.
    pub fn as_bytes(&self) -> &[u8] {
        self.bytes.as_slice()
    }

    pub(crate) fn take(algorithm: NativeDigestAlgorithm, bytes: &mut Buffer) -> Result<Self> {
        if !algorithm.accepts_length(bytes.as_slice().len()) {
            return Err(Error::Rejected(crate::RejectionReason::NativeDigest(
                crate::NativeDigestRejection::NativeDigestOutputLength,
            )));
        }
        Ok(Self {
            algorithm,
            bytes: bytes.take(),
        })
    }
}
