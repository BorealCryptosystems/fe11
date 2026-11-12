// SPDX-License-Identifier: Apache-2.0
//! LocalAdmission causes, separate from native result/effect information.

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[non_exhaustive]
/// Causes belonging to local admission.
#[doc = include_str!("../../../docs/diagnostics/rejection-local_admission.md")]
pub enum LocalAdmissionRejection {
    /// Admission context owner mismatch. [Detection, owner and recovery](#cause-AdmissionContextOwnerMismatch).
    AdmissionContextOwnerMismatch,
    /// Admission waiter allocation. [Detection, owner and recovery](#cause-AdmissionWaiterAllocation).
    AdmissionWaiterAllocation,
}

impl std::fmt::Display for LocalAdmissionRejection {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::AdmissionContextOwnerMismatch => f.write_str("admission context owner mismatch"),
            Self::AdmissionWaiterAllocation => f.write_str("admission waiter allocation"),
        }
    }
}
