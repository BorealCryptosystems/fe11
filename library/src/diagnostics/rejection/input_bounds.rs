// SPDX-License-Identifier: Apache-2.0
//! InputBounds causes, separate from native result/effect information.

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[non_exhaustive]
/// Causes belonging to input bounds.
#[doc = include_str!("../../../docs/diagnostics/rejection-input_bounds.md")]
pub enum InputBoundsRejection {
    /// Length bound. [Detection, owner and recovery](#cause-LengthBound).
    LengthBound,
    /// Length conversion. [Detection, owner and recovery](#cause-LengthConversion).
    LengthConversion,
}

impl std::fmt::Display for InputBoundsRejection {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::LengthBound => f.write_str("length bound"),
            Self::LengthConversion => f.write_str("length conversion"),
        }
    }
}
