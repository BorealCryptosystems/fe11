// SPDX-License-Identifier: Apache-2.0
//! VerificationEngine causes, separate from native result/effect information.

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[non_exhaustive]
/// Causes belonging to verification engine.
#[doc = include_str!("../../../docs/diagnostics/rejection-verification_engine.md")]
pub enum VerificationEngineRejection {
    /// Absolute verification engine path required. [Detection, owner and recovery](#cause-AbsoluteVerificationEnginePathRequired).
    AbsoluteVerificationEnginePathRequired,
    /// Verification engine allocation failed. [Detection, owner and recovery](#cause-VerificationEngineAllocationFailed).
    VerificationEngineAllocationFailed,
    /// Verification engine capability unavailable. [Detection, owner and recovery](#cause-VerificationEngineCapabilityUnavailable).
    VerificationEngineCapabilityUnavailable,
    /// Verification engine digest unavailable. [Detection, owner and recovery](#cause-VerificationEngineDigestUnavailable).
    VerificationEngineDigestUnavailable,
    /// Verification engine function mapping. [Detection, owner and recovery](#cause-VerificationEngineFunctionMapping).
    VerificationEngineFunctionMapping,
    /// Verification engine getter belongs to another image. [Detection, owner and recovery](#cause-VerificationEngineGetterBelongsToAnotherImage).
    VerificationEngineGetterBelongsToAnotherImage,
    /// Verification engine image pin failed; loaded image retained. [Detection, owner and recovery](#cause-VerificationEngineImagePinFailedLoadedImageRetained).
    VerificationEngineImagePinFailedLoadedImageRetained,
    /// Verification engine information shape. [Detection, owner and recovery](#cause-VerificationEngineInformationShape).
    VerificationEngineInformationShape,
    /// Verification engine information unavailable. [Detection, owner and recovery](#cause-VerificationEngineInformationUnavailable).
    VerificationEngineInformationUnavailable,
    /// Verification engine interface changed in pinned image. [Detection, owner and recovery](#cause-VerificationEngineInterfaceChangedInPinnedImage).
    VerificationEngineInterfaceChangedInPinnedImage,
    /// Verification engine interface export. [Detection, owner and recovery](#cause-VerificationEngineInterfaceExport).
    VerificationEngineInterfaceExport,
    /// Verification engine interface shape. [Detection, owner and recovery](#cause-VerificationEngineInterfaceShape).
    VerificationEngineInterfaceShape,
    /// Verification engine invalid request. [Detection, owner and recovery](#cause-VerificationEngineInvalidRequest).
    VerificationEngineInvalidRequest,
    /// Verification engine is not a regular file. [Detection, owner and recovery](#cause-VerificationEngineIsNotARegularFile).
    VerificationEngineIsNotARegularFile,
    /// Verification engine load. [Detection, owner and recovery](#cause-VerificationEngineLoad).
    VerificationEngineLoad,
    /// Verification engine loading platform unavailable. [Detection, owner and recovery](#cause-VerificationEngineLoadingPlatformUnavailable).
    VerificationEngineLoadingPlatformUnavailable,
    /// Verification engine metadata. [Detection, owner and recovery](#cause-VerificationEngineMetadata).
    VerificationEngineMetadata,
    /// Verification engine null function. [Detection, owner and recovery](#cause-VerificationEngineNullFunction).
    VerificationEngineNullFunction,
    /// Verification engine operation failed. [Detection, owner and recovery](#cause-VerificationEngineOperationFailed).
    VerificationEngineOperationFailed,
    /// Verification engine output shape. [Detection, owner and recovery](#cause-VerificationEngineOutputShape).
    VerificationEngineOutputShape,
    /// Verification engine probe unavailable. [Detection, owner and recovery](#cause-VerificationEngineProbeUnavailable).
    VerificationEngineProbeUnavailable,
    /// Verification engine read. [Detection, owner and recovery](#cause-VerificationEngineRead).
    VerificationEngineRead,
    /// Verification engine release unavailable. [Detection, owner and recovery](#cause-VerificationEngineReleaseUnavailable).
    VerificationEngineReleaseUnavailable,
    /// Verification engine source changed; process restart required. [Detection, owner and recovery](#cause-VerificationEngineSourceChangedProcessRestartRequired).
    VerificationEngineSourceChangedProcessRestartRequired,
    /// Verification engine table function belongs to another image. [Detection, owner and recovery](#cause-VerificationEngineTableFunctionBelongsToAnotherImage).
    VerificationEngineTableFunctionBelongsToAnotherImage,
    /// Verification engine unknown status. [Detection, owner and recovery](#cause-VerificationEngineUnknownStatus).
    VerificationEngineUnknownStatus,
    /// Verification engine verification result. [Detection, owner and recovery](#cause-VerificationEngineVerificationResult).
    VerificationEngineVerificationResult,
    /// Verification engine verification unavailable. [Detection, owner and recovery](#cause-VerificationEngineVerificationUnavailable).
    VerificationEngineVerificationUnavailable,


}

impl std::fmt::Display for VerificationEngineRejection {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {


            Self::AbsoluteVerificationEnginePathRequired => {
                f.write_str("absolute verification engine path required")
            }
            Self::VerificationEngineAllocationFailed => {
                f.write_str("verification engine allocation failed")
            }
            Self::VerificationEngineCapabilityUnavailable => {
                f.write_str("verification engine capability unavailable")
            }
            Self::VerificationEngineDigestUnavailable => {
                f.write_str("verification engine digest unavailable")
            }
            Self::VerificationEngineFunctionMapping => {
                f.write_str("verification engine function mapping")
            }
            Self::VerificationEngineGetterBelongsToAnotherImage => {
                f.write_str("verification engine getter belongs to another image")
            }
            Self::VerificationEngineImagePinFailedLoadedImageRetained => {
                f.write_str("verification engine image pin failed; loaded image retained")
            }
            Self::VerificationEngineInformationShape => {
                f.write_str("verification engine information shape")
            }
            Self::VerificationEngineInformationUnavailable => {
                f.write_str("verification engine information unavailable")
            }
            Self::VerificationEngineInterfaceChangedInPinnedImage => {
                f.write_str("verification engine interface changed in pinned image")
            }
            Self::VerificationEngineInterfaceExport => {
                f.write_str("verification engine interface export")
            }
            Self::VerificationEngineInterfaceShape => {
                f.write_str("verification engine interface shape")
            }
            Self::VerificationEngineInvalidRequest => {
                f.write_str("verification engine invalid request")
            }
            Self::VerificationEngineIsNotARegularFile => {
                f.write_str("verification engine is not a regular file")
            }
            Self::VerificationEngineLoad => f.write_str("verification engine load"),
            Self::VerificationEngineLoadingPlatformUnavailable => {
                f.write_str("verification engine loading platform unavailable")
            }
            Self::VerificationEngineMetadata => f.write_str("verification engine metadata"),
            Self::VerificationEngineNullFunction => {
                f.write_str("verification engine null function")
            }
            Self::VerificationEngineOperationFailed => {
                f.write_str("verification engine operation failed")
            }
            Self::VerificationEngineOutputShape => f.write_str("verification engine output shape"),
            Self::VerificationEngineProbeUnavailable => {
                f.write_str("verification engine probe unavailable")
            }
            Self::VerificationEngineRead => f.write_str("verification engine read"),
            Self::VerificationEngineReleaseUnavailable => {
                f.write_str("verification engine release unavailable")
            }
            Self::VerificationEngineSourceChangedProcessRestartRequired => {
                f.write_str("verification engine source changed; process restart required")
            }
            Self::VerificationEngineTableFunctionBelongsToAnotherImage => {
                f.write_str("verification engine table function belongs to another image")
            }
            Self::VerificationEngineUnknownStatus => {
                f.write_str("verification engine unknown status")
            }
            Self::VerificationEngineVerificationResult => {
                f.write_str("verification engine verification result")
            }
            Self::VerificationEngineVerificationUnavailable => {
                f.write_str("verification engine verification unavailable")
            }
        }
    }
}
