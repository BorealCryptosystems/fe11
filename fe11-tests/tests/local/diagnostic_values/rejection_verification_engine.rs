// SPDX-License-Identifier: Apache-2.0
//! Public VerificationEngineRejection values retain identity through category conversion.
use fe11::{Error, RejectionReason, VerificationEngineRejection};

#[test]
fn variants_preserve_category_and_payload() {
    let cases = [
        VerificationEngineRejection::AbsoluteVerificationEnginePathRequired,
        VerificationEngineRejection::VerificationEngineAllocationFailed,
        VerificationEngineRejection::VerificationEngineCapabilityUnavailable,
        VerificationEngineRejection::VerificationEngineDigestUnavailable,
        VerificationEngineRejection::VerificationEngineFunctionMapping,
        VerificationEngineRejection::VerificationEngineGetterBelongsToAnotherImage,
        VerificationEngineRejection::VerificationEngineImagePinFailedLoadedImageRetained,
        VerificationEngineRejection::VerificationEngineInformationShape,
        VerificationEngineRejection::VerificationEngineInformationUnavailable,
        VerificationEngineRejection::VerificationEngineInterfaceChangedInPinnedImage,
        VerificationEngineRejection::VerificationEngineInterfaceExport,
        VerificationEngineRejection::VerificationEngineInterfaceShape,
        VerificationEngineRejection::VerificationEngineInvalidRequest,
        VerificationEngineRejection::VerificationEngineIsNotARegularFile,
        VerificationEngineRejection::VerificationEngineLoad,
        VerificationEngineRejection::VerificationEngineLoadingPlatformUnavailable,
        VerificationEngineRejection::VerificationEngineMetadata,
        VerificationEngineRejection::VerificationEngineNullFunction,
        VerificationEngineRejection::VerificationEngineOperationFailed,
        VerificationEngineRejection::VerificationEngineOutputShape,
        VerificationEngineRejection::VerificationEngineProbeUnavailable,
        VerificationEngineRejection::VerificationEngineRead,
        VerificationEngineRejection::VerificationEngineReleaseUnavailable,
        VerificationEngineRejection::VerificationEngineSourceChangedProcessRestartRequired,
        VerificationEngineRejection::VerificationEngineTableFunctionBelongsToAnotherImage,
        VerificationEngineRejection::VerificationEngineUnknownStatus,
        VerificationEngineRejection::VerificationEngineVerificationResult,
        VerificationEngineRejection::VerificationEngineVerificationUnavailable,
    ];
    for value in cases {
        let category: RejectionReason = value.into();
        assert!(matches!(category, RejectionReason::VerificationEngine(actual) if actual == value));
        let error = Error::Rejected(category);
        assert_eq!(error.clone(), error);
        assert!(
            matches!(&error, Error::Rejected(RejectionReason::VerificationEngine(actual)) if *actual == value)
        );
        assert!(!value.to_string().is_empty());
        assert!(!category.to_string().is_empty());
        assert!(!error.to_string().is_empty());
        assert!(!format!("{value:?}").is_empty());
    }
}
