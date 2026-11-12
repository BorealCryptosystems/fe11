// SPDX-License-Identifier: Apache-2.0
//! PostQuantumKeys causes, separate from native result/effect information.

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[non_exhaustive]
/// Causes belonging to post quantum keys.
#[doc = include_str!("../../../docs/diagnostics/unsupported-post_quantum_keys.md")]
pub enum PostQuantumKeysUnsupported {
    /// C_CreateObject unavailable. [Detection, owner and recovery](#cause-CCreateObjectUnavailable).
    CCreateObjectUnavailable,
    /// PKCS#11 3.2 external SHAKE prehash has no standardized hash identifier. [Detection, owner and recovery](#cause-Pkcs1132ExternalShakePrehashHasNoStandardizedHashIdentifier).
    Pkcs1132ExternalShakePrehashHasNoStandardizedHashIdentifier,
    /// PKCS#11 3.2 has no combined PQC signature for truncated SHA-512. [Detection, owner and recovery](#cause-Pkcs1132HasNoCombinedPqcSignatureForTruncatedSha512).
    Pkcs1132HasNoCombinedPqcSignatureForTruncatedSha512,
    /// PKCS#11 PQC external prehash is single-part only. [Detection, owner and recovery](#cause-Pkcs11PqcExternalPrehashIsSinglePartOnly).
    Pkcs11PqcExternalPrehashIsSinglePartOnly,
    /// PQC private representation family or parameter. [Detection, owner and recovery](#cause-PqcPrivateRepresentationFamilyOrParameter).
    PqcPrivateRepresentationFamilyOrParameter,
    /// Pure PQC multipart verification requires VerifySignature. [Detection, owner and recovery](#cause-PurePqcMultipartVerificationRequiresVerifysignature).
    PurePqcMultipartVerificationRequiresVerifysignature,
    /// VerifySignature requires the PKCS11 3.2 interface. [Detection, owner and recovery](#cause-VerifysignatureRequiresThePkcs1132Interface).
    VerifysignatureRequiresThePkcs1132Interface,
}

impl std::fmt::Display for PostQuantumKeysUnsupported {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::CCreateObjectUnavailable => f.write_str("C_CreateObject unavailable"),
            Self::Pkcs1132ExternalShakePrehashHasNoStandardizedHashIdentifier => f.write_str(
                "PKCS#11 3.2 external SHAKE prehash has no standardized hash identifier",
            ),
            Self::Pkcs1132HasNoCombinedPqcSignatureForTruncatedSha512 => {
                f.write_str("PKCS#11 3.2 has no combined PQC signature for truncated SHA-512")
            }
            Self::Pkcs11PqcExternalPrehashIsSinglePartOnly => {
                f.write_str("PKCS#11 PQC external prehash is single-part only")
            }
            Self::PqcPrivateRepresentationFamilyOrParameter => {
                f.write_str("PQC private representation family or parameter")
            }
            Self::PurePqcMultipartVerificationRequiresVerifysignature => {
                f.write_str("Pure PQC multipart verification requires VerifySignature")
            }
            Self::VerifysignatureRequiresThePkcs1132Interface => {
                f.write_str("VerifySignature requires the PKCS11 3.2 interface")
            }
        }
    }
}
