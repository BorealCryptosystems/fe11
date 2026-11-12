// SPDX-License-Identifier: Apache-2.0
//! ModuleConfiguration causes, separate from native result/effect information.

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[non_exhaustive]
/// Causes belonging to module configuration.
#[doc = include_str!("../../../docs/diagnostics/unsupported-module_configuration.md")]
pub enum ModuleConfigurationUnsupported {
    /// Process image file identity observation. [Detection, owner and recovery](#cause-ProcessImageFileIdentityObservation).
    ProcessImageFileIdentityObservation,
}

impl std::fmt::Display for ModuleConfigurationUnsupported {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::ProcessImageFileIdentityObservation => {
                f.write_str("process image file identity observation")
            }
        }
    }
}
