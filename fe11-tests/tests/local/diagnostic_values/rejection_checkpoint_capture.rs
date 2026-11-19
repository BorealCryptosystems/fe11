// SPDX-License-Identifier: Apache-2.0
//! Public CheckpointCaptureRejection values retain identity through category conversion.
use fe11::{CheckpointCaptureRejection, Error, RejectionReason};

#[test]
fn variants_preserve_category_and_payload() {
    let cases = [
        CheckpointCaptureRejection::AeadStreamCaptureAccounting,
        CheckpointCaptureRejection::AeadStreamCaptureCapacity,
        CheckpointCaptureRejection::AeadStreamCaptureOwnerChanged,
        CheckpointCaptureRejection::AeadStreamValidationShapeChanged,
        CheckpointCaptureRejection::CipherCaptureParametersAbsent,
        CheckpointCaptureRejection::CipherGraphPacketAccounting,
        CheckpointCaptureRejection::CipherSnapshotShapeChanged,
        CheckpointCaptureRejection::DigestExtensionCaptureAccounting,
        CheckpointCaptureRejection::DigestExtensionCaptureCapacity,
        CheckpointCaptureRejection::DigestExtensionCaptureOwnerChanged,
        CheckpointCaptureRejection::DigestExtensionValidationShapeChanged,
        CheckpointCaptureRejection::DigestNotCapturable,
        CheckpointCaptureRejection::DigestSnapshotOidShapeChanged,
        CheckpointCaptureRejection::DigestSnapshotShapeChanged,
        CheckpointCaptureRejection::DualSnapshotShapeChanged,
        CheckpointCaptureRejection::GenericMessageCaptureAccounting,
        CheckpointCaptureRejection::GenericMessageCaptureCapacity,
        CheckpointCaptureRejection::GenericMessageCaptureOwnerChanged,
        CheckpointCaptureRejection::GenericMessageValidationShapeChanged,
        CheckpointCaptureRejection::MessageSnapshotShapeChanged,
        CheckpointCaptureRejection::OperationFamilyNotCapturable,
        CheckpointCaptureRejection::RecordStorageAccounting,
        CheckpointCaptureRejection::SignatureCaptureAccounting,
        CheckpointCaptureRejection::SignatureCaptureCapacity,
        CheckpointCaptureRejection::SignatureCaptureOwnerChanged,
        CheckpointCaptureRejection::SignatureValidationShapeChanged,
        CheckpointCaptureRejection::SnapshotFragmentAllocation,
        CheckpointCaptureRejection::SnapshotFragmentCountChanged,
        CheckpointCaptureRejection::SnapshotInputCountChanged,
        CheckpointCaptureRejection::SnapshotRowAbsent,
        CheckpointCaptureRejection::SnapshotRowCountChanged,
        CheckpointCaptureRejection::SnapshotShapeAccounting,
        CheckpointCaptureRejection::SnapshotShapeAllocation,
        CheckpointCaptureRejection::SnapshotShapeIncomplete,
        CheckpointCaptureRejection::SnapshotStorageAccounting,
    ];
    for value in cases {
        let category: RejectionReason = value.into();
        assert!(matches!(category, RejectionReason::CheckpointCapture(actual) if actual == value));
        let error = Error::Rejected(category);
        assert_eq!(error.clone(), error);
        assert!(
            matches!(&error, Error::Rejected(RejectionReason::CheckpointCapture(actual)) if *actual == value)
        );
        assert!(!value.to_string().is_empty());
        assert!(!category.to_string().is_empty());
        assert!(!error.to_string().is_empty());
        assert!(!format!("{value:?}").is_empty());
    }
}
