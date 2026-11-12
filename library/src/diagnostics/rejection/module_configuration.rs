// SPDX-License-Identifier: Apache-2.0
//! ModuleConfiguration causes, separate from native result/effect information.

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[non_exhaustive]
/// Causes belonging to module configuration.
#[doc = include_str!("../../../docs/diagnostics/rejection-module_configuration.md")]
pub enum ModuleConfigurationRejection {
    /// Initialization arguments during attachment. [Detection, owner and recovery](#cause-InitializationArgumentsDuringAttachment).
    InitializationArgumentsDuringAttachment,
    /// Local module identity exhausted. [Detection, owner and recovery](#cause-LocalModuleIdentityExhausted).
    LocalModuleIdentityExhausted,
    /// Module digest mismatch. [Detection, owner and recovery](#cause-ModuleDigestMismatch).
    ModuleDigestMismatch,
    /// Module file read. [Detection, owner and recovery](#cause-ModuleFileRead).
    ModuleFileRead,
    /// Process export observation absent. [Detection, owner and recovery](#cause-ProcessExportObservationAbsent).
    ProcessExportObservationAbsent,
    /// Process exports do not share the observed file. [Detection, owner and recovery](#cause-ProcessExportsDoNotShareTheObservedFile).
    ProcessExportsDoNotShareTheObservedFile,
    /// Process image file is not regular. [Detection, owner and recovery](#cause-ProcessImageFileIsNotRegular).
    ProcessImageFileIsNotRegular,
    /// Process image file metadata. [Detection, owner and recovery](#cause-ProcessImageFileMetadata).
    ProcessImageFileMetadata,
    /// Process image file unavailable. [Detection, owner and recovery](#cause-ProcessImageFileUnavailable).
    ProcessImageFileUnavailable,
    /// Process image filename unavailable. [Detection, owner and recovery](#cause-ProcessImageFilenameUnavailable).
    ProcessImageFilenameUnavailable,
}

impl std::fmt::Display for ModuleConfigurationRejection {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::InitializationArgumentsDuringAttachment => {
                f.write_str("initialization arguments during attachment")
            }
            Self::LocalModuleIdentityExhausted => f.write_str("local module identity exhausted"),
            Self::ModuleDigestMismatch => f.write_str("module digest mismatch"),
            Self::ModuleFileRead => f.write_str("module file read"),
            Self::ProcessExportObservationAbsent => {
                f.write_str("process export observation absent")
            }
            Self::ProcessExportsDoNotShareTheObservedFile => {
                f.write_str("process exports do not share the observed file")
            }
            Self::ProcessImageFileIsNotRegular => f.write_str("process image file is not regular"),
            Self::ProcessImageFileMetadata => f.write_str("process image file metadata"),
            Self::ProcessImageFileUnavailable => f.write_str("process image file unavailable"),
            Self::ProcessImageFilenameUnavailable => {
                f.write_str("process image filename unavailable")
            }
        }
    }
}
