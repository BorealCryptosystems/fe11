// SPDX-License-Identifier: Apache-2.0
//! CheckpointCapture causes, separate from native result/effect information.

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[non_exhaustive]
/// Causes belonging to checkpoint capture.
#[doc = include_str!("../../../docs/diagnostics/rejection-checkpoint_capture.md")]
pub enum CheckpointCaptureRejection {
    /// AEAD stream capture accounting. [Detection, owner and recovery](#cause-AeadStreamCaptureAccounting).
    AeadStreamCaptureAccounting,
    /// AEAD stream capture capacity. [Detection, owner and recovery](#cause-AeadStreamCaptureCapacity).
    AeadStreamCaptureCapacity,
    /// AEAD stream capture owner changed. [Detection, owner and recovery](#cause-AeadStreamCaptureOwnerChanged).
    AeadStreamCaptureOwnerChanged,
    /// AEAD stream validation shape changed. [Detection, owner and recovery](#cause-AeadStreamValidationShapeChanged).
    AeadStreamValidationShapeChanged,
    /// Cipher capture parameters absent. [Detection, owner and recovery](#cause-CipherCaptureParametersAbsent).
    CipherCaptureParametersAbsent,
    /// Cipher graph packet accounting. [Detection, owner and recovery](#cause-CipherGraphPacketAccounting).
    CipherGraphPacketAccounting,
    /// Cipher snapshot shape changed. [Detection, owner and recovery](#cause-CipherSnapshotShapeChanged).
    CipherSnapshotShapeChanged,
    /// Digest extension capture accounting. [Detection, owner and recovery](#cause-DigestExtensionCaptureAccounting).
    DigestExtensionCaptureAccounting,
    /// Digest extension capture capacity. [Detection, owner and recovery](#cause-DigestExtensionCaptureCapacity).
    DigestExtensionCaptureCapacity,
    /// Digest extension capture owner changed. [Detection, owner and recovery](#cause-DigestExtensionCaptureOwnerChanged).
    DigestExtensionCaptureOwnerChanged,
    /// Digest extension validation shape changed. [Detection, owner and recovery](#cause-DigestExtensionValidationShapeChanged).
    DigestExtensionValidationShapeChanged,
    /// Digest not capturable. [Detection, owner and recovery](#cause-DigestNotCapturable).
    DigestNotCapturable,
    /// Digest snapshot OID shape changed. [Detection, owner and recovery](#cause-DigestSnapshotOidShapeChanged).
    DigestSnapshotOidShapeChanged,
    /// Digest snapshot shape changed. [Detection, owner and recovery](#cause-DigestSnapshotShapeChanged).
    DigestSnapshotShapeChanged,
    /// Dual snapshot shape changed. [Detection, owner and recovery](#cause-DualSnapshotShapeChanged).
    DualSnapshotShapeChanged,
    /// Generic message capture accounting. [Detection, owner and recovery](#cause-GenericMessageCaptureAccounting).
    GenericMessageCaptureAccounting,
    /// Generic message capture capacity. [Detection, owner and recovery](#cause-GenericMessageCaptureCapacity).
    GenericMessageCaptureCapacity,
    /// Generic message capture owner changed. [Detection, owner and recovery](#cause-GenericMessageCaptureOwnerChanged).
    GenericMessageCaptureOwnerChanged,
    /// Generic message validation shape changed. [Detection, owner and recovery](#cause-GenericMessageValidationShapeChanged).
    GenericMessageValidationShapeChanged,
    /// Message snapshot shape changed. [Detection, owner and recovery](#cause-MessageSnapshotShapeChanged).
    MessageSnapshotShapeChanged,
    /// Operation family not capturable. [Detection, owner and recovery](#cause-OperationFamilyNotCapturable).
    OperationFamilyNotCapturable,
    /// Record storage accounting. [Detection, owner and recovery](#cause-RecordStorageAccounting).
    RecordStorageAccounting,
    /// Signature capture accounting. [Detection, owner and recovery](#cause-SignatureCaptureAccounting).
    SignatureCaptureAccounting,
    /// Signature capture capacity. [Detection, owner and recovery](#cause-SignatureCaptureCapacity).
    SignatureCaptureCapacity,
    /// Signature capture owner changed. [Detection, owner and recovery](#cause-SignatureCaptureOwnerChanged).
    SignatureCaptureOwnerChanged,
    /// Signature validation shape changed. [Detection, owner and recovery](#cause-SignatureValidationShapeChanged).
    SignatureValidationShapeChanged,
    /// Snapshot fragment allocation. [Detection, owner and recovery](#cause-SnapshotFragmentAllocation).
    SnapshotFragmentAllocation,
    /// Snapshot fragment count changed. [Detection, owner and recovery](#cause-SnapshotFragmentCountChanged).
    SnapshotFragmentCountChanged,
    /// Snapshot input count changed. [Detection, owner and recovery](#cause-SnapshotInputCountChanged).
    SnapshotInputCountChanged,
    /// Snapshot row absent. [Detection, owner and recovery](#cause-SnapshotRowAbsent).
    SnapshotRowAbsent,
    /// Snapshot row count changed. [Detection, owner and recovery](#cause-SnapshotRowCountChanged).
    SnapshotRowCountChanged,
    /// Snapshot shape accounting. [Detection, owner and recovery](#cause-SnapshotShapeAccounting).
    SnapshotShapeAccounting,
    /// Snapshot shape allocation. [Detection, owner and recovery](#cause-SnapshotShapeAllocation).
    SnapshotShapeAllocation,
    /// Snapshot shape incomplete. [Detection, owner and recovery](#cause-SnapshotShapeIncomplete).
    SnapshotShapeIncomplete,
    /// Snapshot storage accounting. [Detection, owner and recovery](#cause-SnapshotStorageAccounting).
    SnapshotStorageAccounting,
}

impl std::fmt::Display for CheckpointCaptureRejection {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::AeadStreamCaptureAccounting => f.write_str("AEAD stream capture accounting"),
            Self::AeadStreamCaptureCapacity => f.write_str("AEAD stream capture capacity"),
            Self::AeadStreamCaptureOwnerChanged => f.write_str("AEAD stream capture owner changed"),
            Self::AeadStreamValidationShapeChanged => {
                f.write_str("AEAD stream validation shape changed")
            }
            Self::CipherCaptureParametersAbsent => f.write_str("cipher capture parameters absent"),
            Self::CipherGraphPacketAccounting => f.write_str("cipher graph packet accounting"),
            Self::CipherSnapshotShapeChanged => f.write_str("cipher snapshot shape changed"),
            Self::DigestExtensionCaptureAccounting => {
                f.write_str("digest extension capture accounting")
            }
            Self::DigestExtensionCaptureCapacity => {
                f.write_str("digest extension capture capacity")
            }
            Self::DigestExtensionCaptureOwnerChanged => {
                f.write_str("digest extension capture owner changed")
            }
            Self::DigestExtensionValidationShapeChanged => {
                f.write_str("digest extension validation shape changed")
            }
            Self::DigestNotCapturable => f.write_str("digest not capturable"),
            Self::DigestSnapshotOidShapeChanged => f.write_str("digest snapshot OID shape changed"),
            Self::DigestSnapshotShapeChanged => f.write_str("digest snapshot shape changed"),
            Self::DualSnapshotShapeChanged => f.write_str("dual snapshot shape changed"),
            Self::GenericMessageCaptureAccounting => {
                f.write_str("generic message capture accounting")
            }
            Self::GenericMessageCaptureCapacity => f.write_str("generic message capture capacity"),
            Self::GenericMessageCaptureOwnerChanged => {
                f.write_str("generic message capture owner changed")
            }
            Self::GenericMessageValidationShapeChanged => {
                f.write_str("generic message validation shape changed")
            }
            Self::MessageSnapshotShapeChanged => f.write_str("message snapshot shape changed"),
            Self::OperationFamilyNotCapturable => f.write_str("operation family not capturable"),
            Self::RecordStorageAccounting => f.write_str("record storage accounting"),
            Self::SignatureCaptureAccounting => f.write_str("signature capture accounting"),
            Self::SignatureCaptureCapacity => f.write_str("signature capture capacity"),
            Self::SignatureCaptureOwnerChanged => f.write_str("signature capture owner changed"),
            Self::SignatureValidationShapeChanged => {
                f.write_str("signature validation shape changed")
            }
            Self::SnapshotFragmentAllocation => f.write_str("snapshot fragment allocation"),
            Self::SnapshotFragmentCountChanged => f.write_str("snapshot fragment count changed"),
            Self::SnapshotInputCountChanged => f.write_str("snapshot input count changed"),
            Self::SnapshotRowAbsent => f.write_str("snapshot row absent"),
            Self::SnapshotRowCountChanged => f.write_str("snapshot row count changed"),
            Self::SnapshotShapeAccounting => f.write_str("snapshot shape accounting"),
            Self::SnapshotShapeAllocation => f.write_str("snapshot shape allocation"),
            Self::SnapshotShapeIncomplete => f.write_str("snapshot shape incomplete"),
            Self::SnapshotStorageAccounting => f.write_str("snapshot storage accounting"),
        }
    }
}
