// SPDX-License-Identifier: Apache-2.0
//! ModuleLifecycle causes, separate from native result/effect information.

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[non_exhaustive]
/// Causes belonging to module lifecycle.
#[doc = include_str!("../../../docs/diagnostics/unsupported-module_lifecycle.md")]
pub enum ModuleLifecycleUnsupported {
    /// Autonomous archive requires an observed module file. [Detection, owner and recovery](#cause-AutonomousArchiveRequiresAnObservedModuleFile).
    AutonomousArchiveRequiresAnObservedModuleFile,
    /// File loading options for process source. [Detection, owner and recovery](#cause-FileLoadingOptionsForProcessSource).
    FileLoadingOptionsForProcessSource,
}

impl std::fmt::Display for ModuleLifecycleUnsupported {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::AutonomousArchiveRequiresAnObservedModuleFile => {
                f.write_str("autonomous archive requires an observed module file")
            }
            Self::FileLoadingOptionsForProcessSource => {
                f.write_str("file loading options for process source")
            }
        }
    }
}
