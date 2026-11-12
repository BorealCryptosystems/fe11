// SPDX-License-Identifier: Apache-2.0
use super::PqcAlgorithm;
use crate::{Error, Result};
use fe11_sys::*;

/// Hash functions for generic prehash and the PKCS#11 3.2 combined mechanisms.
/// Selecting a function does not imply that a module supports it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PqcHash {
    /// SHA-224.
    Sha224,
    /// SHA-256.
    Sha256,
    /// SHA-384.
    Sha384,
    /// SHA-512.
    Sha512,
    /// SHA-512/224; external prehash only in PKCS#11 3.2.
    Sha512_224,
    /// SHA-512/256; external prehash only in PKCS#11 3.2.
    Sha512_256,
    /// SHA3-224.
    Sha3_224,
    /// SHA3-256.
    Sha3_256,
    /// SHA3-384.
    Sha3_384,
    /// SHA3-512.
    Sha3_512,
    /// SHAKE128 with the FIPS 204/205 256-bit prehash output.
    Shake128,
    /// SHAKE256 with the FIPS 204/205 512-bit prehash output.
    Shake256,
}

impl PqcHash {
    pub(super) fn engine_name(self) -> &'static [u8] {
        match self {
            Self::Sha224 => b"SHA224\0",
            Self::Sha256 => b"SHA256\0",
            Self::Sha384 => b"SHA384\0",
            Self::Sha512 => b"SHA512\0",
            Self::Sha512_224 => b"SHA512-224\0",
            Self::Sha512_256 => b"SHA512-256\0",
            Self::Sha3_224 => b"SHA3-224\0",
            Self::Sha3_256 => b"SHA3-256\0",
            Self::Sha3_384 => b"SHA3-384\0",
            Self::Sha3_512 => b"SHA3-512\0",
            Self::Shake128 => b"SHAKE128\0",
            Self::Shake256 => b"SHAKE256\0",
        }
    }

    /// NIST CSOR DER OID for FIPS prehash framing, never a PKCS#11 identifier.
    pub(super) fn der_oid(self) -> [u8; 11] {
        let suffix = match self {
            Self::Sha256 => 1,
            Self::Sha384 => 2,
            Self::Sha512 => 3,
            Self::Sha224 => 4,
            Self::Sha512_224 => 5,
            Self::Sha512_256 => 6,
            Self::Sha3_224 => 7,
            Self::Sha3_256 => 8,
            Self::Sha3_384 => 9,
            Self::Sha3_512 => 10,
            Self::Shake128 => 11,
            Self::Shake256 => 12,
        };
        [
            0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, suffix,
        ]
    }

    /// Exact prehash width in bytes, including the fixed FIPS XOF widths.
    pub fn output_length(self) -> usize {
        match self {
            Self::Sha224 | Self::Sha3_224 | Self::Sha512_224 => 28,
            Self::Sha256 | Self::Sha3_256 | Self::Shake128 | Self::Sha512_256 => 32,
            Self::Sha384 | Self::Sha3_384 => 48,
            Self::Sha512 | Self::Sha3_512 | Self::Shake256 => 64,
        }
    }

    pub(super) fn digest_mechanism(self) -> Result<CK_MECHANISM_TYPE> {
        Ok(match self {
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
            // 3.2 defines combined SHAKE signatures, but no SHAKE digest
            // mechanism identifier for CK_HASH_SIGN_ADDITIONAL_CONTEXT.hash.
            // Do not substitute a key-derivation mechanism or vendor number.
            Self::Shake128 | Self::Shake256 => {
                return Err(Error::Unsupported(
                    crate::UnsupportedReason::PostQuantumKeys(crate::PostQuantumKeysUnsupported::Pkcs1132ExternalShakePrehashHasNoStandardizedHashIdentifier),
                ));
            }
        })
    }

    pub(super) fn combined_mechanisms(self) -> Result<(CK_MECHANISM_TYPE, CK_MECHANISM_TYPE)> {
        Ok(match self {
            Self::Sha224 => (CKM_HASH_ML_DSA_SHA224, CKM_HASH_SLH_DSA_SHA224),
            Self::Sha256 => (CKM_HASH_ML_DSA_SHA256, CKM_HASH_SLH_DSA_SHA256),
            Self::Sha384 => (CKM_HASH_ML_DSA_SHA384, CKM_HASH_SLH_DSA_SHA384),
            Self::Sha512 => (CKM_HASH_ML_DSA_SHA512, CKM_HASH_SLH_DSA_SHA512),
            Self::Sha3_224 => (CKM_HASH_ML_DSA_SHA3_224, CKM_HASH_SLH_DSA_SHA3_224),
            Self::Sha3_256 => (CKM_HASH_ML_DSA_SHA3_256, CKM_HASH_SLH_DSA_SHA3_256),
            Self::Sha3_384 => (CKM_HASH_ML_DSA_SHA3_384, CKM_HASH_SLH_DSA_SHA3_384),
            Self::Sha3_512 => (CKM_HASH_ML_DSA_SHA3_512, CKM_HASH_SLH_DSA_SHA3_512),
            Self::Shake128 => (CKM_HASH_ML_DSA_SHAKE128, CKM_HASH_SLH_DSA_SHAKE128),
            Self::Shake256 => (CKM_HASH_ML_DSA_SHAKE256, CKM_HASH_SLH_DSA_SHAKE256),
            Self::Sha512_224 | Self::Sha512_256 => {
                return Err(Error::Unsupported(
                    crate::UnsupportedReason::PostQuantumKeys(crate::PostQuantumKeysUnsupported::Pkcs1132HasNoCombinedPqcSignatureForTruncatedSha512),
                ))
            }
        })
    }

    pub(super) fn signature_mechanism(self, algorithm: PqcAlgorithm) -> Result<CK_MECHANISM_TYPE> {
        let (ml, slh) = self.combined_mechanisms()?;
        Ok(match algorithm {
            PqcAlgorithm::MlDsa(_) => ml,
            PqcAlgorithm::SlhDsa(_) => slh,
        })
    }
}
