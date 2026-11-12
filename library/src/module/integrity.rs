// SPDX-License-Identifier: Apache-2.0
//! Optional file pinning at the application-selected native-code trust boundary.

use crate::{Error, Result};

/// Handling of a module-file digest mismatch, before the file is loaded.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ModuleDigestMismatch {
    /// Reject this module load.
    Refuse,
    /// Load the selected file and expose the mismatch in its report.
    Report,
}

/// Explicit file pinning; no trust policy is inferred from a file identity.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ModuleIntegrity {
    /// Observe the file identity without comparing it with an expected digest.
    NotRequested,
    /// Compare the opened file with the application's exact SHA-256 digest.
    Sha256 {
        /// Public digest supplied by the application.
        expected: [u8; 32],
        /// Handling selected specifically for this module load.
        on_mismatch: ModuleDigestMismatch,
    },
}

/// File comparison result; this is not an attestation of native-code safety.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ModuleDigestObservation {
    /// No expected digest was supplied.
    NotRequested,
    /// The opened file's digest matched the expected digest.
    Matched,
    /// Digests differed and the application selected reporting.
    Mismatched,
}

/// Comparison performed on the opened file before loading it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ModuleIntegrityReport {
    selection: ModuleIntegrity,
    observation: ModuleDigestObservation,
}
impl ModuleIntegrityReport {
    /// Exact choice made for this open.
    pub fn selection(&self) -> &ModuleIntegrity {
        &self.selection
    }
    /// Observed comparison. A file-read error never becomes an observation.
    pub fn observation(&self) -> ModuleDigestObservation {
        self.observation
    }
}
impl ModuleIntegrity {
    pub(crate) fn evaluate(self, observed: [u8; 32]) -> Result<ModuleIntegrityReport> {
        let observation = match &self {
            Self::NotRequested => ModuleDigestObservation::NotRequested,
            Self::Sha256 {
                expected,
                on_mismatch,
            } => {
                if *expected == observed {
                    ModuleDigestObservation::Matched
                } else {
                    if *on_mismatch == ModuleDigestMismatch::Refuse {
                        return Err(Error::Rejected(
                            crate::RejectionReason::ModuleConfiguration(
                                crate::ModuleConfigurationRejection::ModuleDigestMismatch,
                            ),
                        ));
                    }
                    ModuleDigestObservation::Mismatched
                }
            }
        };
        Ok(ModuleIntegrityReport {
            selection: self,
            observation,
        })
    }
}
