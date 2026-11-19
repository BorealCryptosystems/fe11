// SPDX-License-Identifier: Apache-2.0
//! Public ModuleConfigurationRejection values retain identity through category conversion.
use fe11::{Error, ModuleConfigurationRejection, RejectionReason};

#[test]
fn variants_preserve_category_and_payload() {
    let cases = [
        ModuleConfigurationRejection::InitializationArgumentsDuringAttachment,
        ModuleConfigurationRejection::LocalModuleIdentityExhausted,
        ModuleConfigurationRejection::ModuleDigestMismatch,
        ModuleConfigurationRejection::ModuleFileRead,
        ModuleConfigurationRejection::ProcessExportObservationAbsent,
        ModuleConfigurationRejection::ProcessExportsDoNotShareTheObservedFile,
        ModuleConfigurationRejection::ProcessImageFileIsNotRegular,
        ModuleConfigurationRejection::ProcessImageFileMetadata,
        ModuleConfigurationRejection::ProcessImageFileUnavailable,
        ModuleConfigurationRejection::ProcessImageFilenameUnavailable,
    ];
    for value in cases {
        let category: RejectionReason = value.into();
        assert!(
            matches!(category, RejectionReason::ModuleConfiguration(actual) if actual == value)
        );
        let error = Error::Rejected(category);
        assert_eq!(error.clone(), error);
        assert!(
            matches!(&error, Error::Rejected(RejectionReason::ModuleConfiguration(actual)) if *actual == value)
        );
        assert!(!value.to_string().is_empty());
        assert!(!category.to_string().is_empty());
        assert!(!error.to_string().is_empty());
        assert!(!format!("{value:?}").is_empty());
    }
}
