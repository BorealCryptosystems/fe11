// SPDX-License-Identifier: Apache-2.0
//! PublicVerification causes, separate from native result/effect information.

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[non_exhaustive]
/// Causes belonging to public verification.
#[doc = include_str!("../../../docs/diagnostics/rejection-public_verification.md")]
pub enum PublicVerificationRejection {
    /// C_CreateObject unavailable. [Detection, owner and recovery](#cause-CCreateObjectUnavailable).
    CCreateObjectUnavailable,
    /// EC point encoding. [Detection, owner and recovery](#cause-EcPointEncoding).
    EcPointEncoding,
    /// EdDSA instance and key curve differ. [Detection, owner and recovery](#cause-EddsaInstanceAndKeyCurveDiffer).
    EddsaInstanceAndKeyCurveDiffer,
    /// Edwards point encoding. [Detection, owner and recovery](#cause-EdwardsPointEncoding).
    EdwardsPointEncoding,
    /// Message RSA verification key required. [Detection, owner and recovery](#cause-MessageRsaVerificationKeyRequired).
    MessageRsaVerificationKeyRequired,
    /// Not an Edwards reference. [Detection, owner and recovery](#cause-NotAnEdwardsReference).
    NotAnEdwardsReference,
    /// Public SPKI DER. [Detection, owner and recovery](#cause-PublicSpkiDer).
    PublicSpkiDer,
    /// Public verification input allocation. [Detection, owner and recovery](#cause-PublicVerificationInputAllocation).
    PublicVerificationInputAllocation,
    /// Public verification owner size. [Detection, owner and recovery](#cause-PublicVerificationOwnerSize).
    PublicVerificationOwnerSize,
    /// Verification engine not selected. [Detection, owner and recovery](#cause-VerificationEngineNotSelected).
    VerificationEngineNotSelected,
    /// Verification engine request failed. [Detection, owner and recovery](#cause-VerificationEngineRequestFailed).
    VerificationEngineRequestFailed,
    /// Verification identity already observed. [Detection, owner and recovery](#cause-VerificationIdentityAlreadyObserved).
    VerificationIdentityAlreadyObserved,
    /// Verification material requires public identity. [Detection, owner and recovery](#cause-VerificationMaterialRequiresPublicIdentity).
    VerificationMaterialRequiresPublicIdentity,
    /// Verification public observation incomplete. [Detection, owner and recovery](#cause-VerificationPublicObservationIncomplete).
    VerificationPublicObservationIncomplete,
    /// Verification publication absent. [Detection, owner and recovery](#cause-VerificationPublicationAbsent).
    VerificationPublicationAbsent,
    /// Verification publication allocation. [Detection, owner and recovery](#cause-VerificationPublicationAllocation).
    VerificationPublicationAllocation,
    /// Verification publication already transferred. [Detection, owner and recovery](#cause-VerificationPublicationAlreadyTransferred).
    VerificationPublicationAlreadyTransferred,
    /// Verification publication size. [Detection, owner and recovery](#cause-VerificationPublicationSize).
    VerificationPublicationSize,
}

impl std::fmt::Display for PublicVerificationRejection {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::CCreateObjectUnavailable => f.write_str("C_CreateObject unavailable"),
            Self::EcPointEncoding => f.write_str("EC point encoding"),
            Self::EddsaInstanceAndKeyCurveDiffer => {
                f.write_str("EdDSA instance and key curve differ")
            }
            Self::EdwardsPointEncoding => f.write_str("Edwards point encoding"),
            Self::MessageRsaVerificationKeyRequired => {
                f.write_str("message RSA verification key required")
            }
            Self::NotAnEdwardsReference => f.write_str("not an Edwards reference"),
            Self::PublicSpkiDer => f.write_str("public SPKI DER"),
            Self::PublicVerificationInputAllocation => {
                f.write_str("public verification input allocation")
            }
            Self::PublicVerificationOwnerSize => f.write_str("public verification owner size"),
            Self::VerificationEngineNotSelected => f.write_str("verification engine not selected"),
            Self::VerificationEngineRequestFailed => {
                f.write_str("verification engine request failed")
            }
            Self::VerificationIdentityAlreadyObserved => {
                f.write_str("verification identity already observed")
            }
            Self::VerificationMaterialRequiresPublicIdentity => {
                f.write_str("verification material requires public identity")
            }
            Self::VerificationPublicObservationIncomplete => {
                f.write_str("verification public observation incomplete")
            }
            Self::VerificationPublicationAbsent => f.write_str("verification publication absent"),
            Self::VerificationPublicationAllocation => {
                f.write_str("verification publication allocation")
            }
            Self::VerificationPublicationAlreadyTransferred => {
                f.write_str("verification publication already transferred")
            }
            Self::VerificationPublicationSize => f.write_str("verification publication size"),
        }
    }
}
