// SPDX-License-Identifier: Apache-2.0
//! ObjectObservation causes, separate from native result/effect information.

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[non_exhaustive]
/// Causes belonging to object observation.
#[doc = include_str!("../../../docs/diagnostics/busy-object_observation.md")]
pub enum ObjectObservationBusy {
    /// RSA object creation plan changed. [Detection, owner and recovery](#cause-RsaObjectCreationPlanChanged).
    RsaObjectCreationPlanChanged,
}

impl std::fmt::Display for ObjectObservationBusy {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::RsaObjectCreationPlanChanged => f.write_str("RSA object creation plan changed"),
        }
    }
}
