// SPDX-License-Identifier: Apache-2.0
//! Mechanisms causes, separate from native result/effect information.

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[non_exhaustive]
/// Causes belonging to mechanisms.
#[doc = include_str!("../../../docs/diagnostics/unsupported-mechanisms.md")]
pub enum MechanismsUnsupported {
    /// C_GetMechanismInfo unavailable. [Detection, owner and recovery](#cause-CGetMechanismInfoUnavailable).
    CGetMechanismInfoUnavailable,
    /// Mechanism list not observed. [Detection, owner and recovery](#cause-MechanismListNotObserved).
    MechanismListNotObserved,
}

impl std::fmt::Display for MechanismsUnsupported {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::CGetMechanismInfoUnavailable => f.write_str("C_GetMechanismInfo unavailable"),
            Self::MechanismListNotObserved => f.write_str("mechanism list not observed"),
        }
    }
}
