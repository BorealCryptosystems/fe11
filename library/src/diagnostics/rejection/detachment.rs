// SPDX-License-Identifier: Apache-2.0
//! Detachment causes, separate from native result/effect information.

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[non_exhaustive]
/// Causes belonging to detachment.
#[doc = include_str!("../../../docs/diagnostics/rejection-detachment.md")]
pub enum DetachmentRejection {
    /// Asynchronous detachment session mode. [Detection, owner and recovery](#cause-AsynchronousDetachmentSessionMode).
    AsynchronousDetachmentSessionMode,
    /// Conflicting detachment owners. [Detection, owner and recovery](#cause-ConflictingDetachmentOwners).
    ConflictingDetachmentOwners,
    /// Detachment absent. [Detection, owner and recovery](#cause-DetachmentAbsent).
    DetachmentAbsent,
    /// Detachment capture owner absent. [Detection, owner and recovery](#cause-DetachmentCaptureOwnerAbsent).
    DetachmentCaptureOwnerAbsent,
    /// Detachment context absent. [Detection, owner and recovery](#cause-DetachmentContextAbsent).
    DetachmentContextAbsent,
    /// Detachment native state uncertain. [Detection, owner and recovery](#cause-DetachmentNativeStateUncertain).
    DetachmentNativeStateUncertain,
    /// Detachment owner adapter not integrated. [Detection, owner and recovery](#cause-DetachmentOwnerAdapterNotIntegrated).
    DetachmentOwnerAdapterNotIntegrated,
    /// Detachment publication credit absent. [Detection, owner and recovery](#cause-DetachmentPublicationCreditAbsent).
    DetachmentPublicationCreditAbsent,
    /// Detachment record ceiling. [Detection, owner and recovery](#cause-DetachmentRecordCeiling).
    DetachmentRecordCeiling,
    /// Detachment record phase changed. [Detection, owner and recovery](#cause-DetachmentRecordPhaseChanged).
    DetachmentRecordPhaseChanged,
    /// Detachment storage accounting. [Detection, owner and recovery](#cause-DetachmentStorageAccounting).
    DetachmentStorageAccounting,
    /// Nonterminal validation adapter not integrated. [Detection, owner and recovery](#cause-NonterminalValidationAdapterNotIntegrated).
    NonterminalValidationAdapterNotIntegrated,
}

impl std::fmt::Display for DetachmentRejection {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::AsynchronousDetachmentSessionMode => {
                f.write_str("asynchronous detachment session mode")
            }
            Self::ConflictingDetachmentOwners => f.write_str("conflicting detachment owners"),
            Self::DetachmentAbsent => f.write_str("detachment absent"),
            Self::DetachmentCaptureOwnerAbsent => f.write_str("detachment capture owner absent"),
            Self::DetachmentContextAbsent => f.write_str("detachment context absent"),
            Self::DetachmentNativeStateUncertain => {
                f.write_str("detachment native state uncertain")
            }
            Self::DetachmentOwnerAdapterNotIntegrated => {
                f.write_str("detachment owner adapter not integrated")
            }
            Self::DetachmentPublicationCreditAbsent => {
                f.write_str("detachment publication credit absent")
            }
            Self::DetachmentRecordCeiling => f.write_str("detachment record ceiling"),
            Self::DetachmentRecordPhaseChanged => f.write_str("detachment record phase changed"),
            Self::DetachmentStorageAccounting => f.write_str("detachment storage accounting"),
            Self::NonterminalValidationAdapterNotIntegrated => {
                f.write_str("nonterminal validation adapter not integrated")
            }
        }
    }
}
