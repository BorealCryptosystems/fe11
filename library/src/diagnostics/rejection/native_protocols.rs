// SPDX-License-Identifier: Apache-2.0
//! NativeProtocols causes, separate from native result/effect information.

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[non_exhaustive]
/// Causes belonging to native protocols.
#[doc = include_str!("../../../docs/diagnostics/rejection-native_protocols.md")]
pub enum NativeProtocolsRejection {
    /// CMS key field accounting. [Detection, owner and recovery](#cause-CmsKeyFieldAccounting).
    CmsKeyFieldAccounting,
    /// Native KIP MAC length differs from requested length. [Detection, owner and recovery](#cause-NativeKipMacLengthDiffersFromRequestedLength).
    NativeKipMacLengthDiffersFromRequestedLength,
    /// Protocol scalar ABI width. [Detection, owner and recovery](#cause-ProtocolScalarAbiWidth).
    ProtocolScalarAbiWidth,
    /// Single CMS call requires one input. [Detection, owner and recovery](#cause-SingleCmsCallRequiresOneInput).
    SingleCmsCallRequiresOneInput,
}

impl std::fmt::Display for NativeProtocolsRejection {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::CmsKeyFieldAccounting => f.write_str("CMS key field accounting"),
            Self::NativeKipMacLengthDiffersFromRequestedLength => {
                f.write_str("native KIP MAC length differs from requested length")
            }
            Self::ProtocolScalarAbiWidth => f.write_str("protocol scalar ABI width"),
            Self::SingleCmsCallRequiresOneInput => {
                f.write_str("single CMS call requires one input")
            }
        }
    }
}
