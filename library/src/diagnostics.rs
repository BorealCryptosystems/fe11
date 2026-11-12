// SPDX-License-Identifier: Apache-2.0
//! Typed reasons for local refusals and resource admission.
//!
//! A reason identifies a cause, independently of its human-readable presentation.
//! It does not establish that an enclosing operation had no native effect. Inspect
//! the enclosing error and the retained operation before deciding how to proceed.
//! Native return codes and completed effects remain represented by `crate::Error`.

mod busy;
mod rejection;
mod unsupported;
pub use busy::*;
pub use rejection::*;
pub use unsupported::*;

/// Resource whose requested amount exceeded the caller-selected ceiling.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum ResourceKind {
    /// Bytes accounted by the configured symmetric-memory budget, including metadata.
    SymmetricByteBudget,
}

impl std::fmt::Display for ResourceKind {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::SymmetricByteBudget => f.write_str("symmetric byte budget"),
        }
    }
}
