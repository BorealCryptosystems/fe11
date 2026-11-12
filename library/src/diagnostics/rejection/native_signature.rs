// SPDX-License-Identifier: Apache-2.0
//! NativeSignature causes, separate from native result/effect information.

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[non_exhaustive]
/// Causes belonging to native signature.
#[doc = include_str!("../../../docs/diagnostics/rejection-native_signature.md")]
pub enum NativeSignatureRejection {
    /// Signature parameter scalar ABI width. [Detection, owner and recovery](#cause-SignatureParameterScalarAbiWidth).
    SignatureParameterScalarAbiWidth,
    /// Single verification requires one input. [Detection, owner and recovery](#cause-SingleVerificationRequiresOneInput).
    SingleVerificationRequiresOneInput,
    /// Single-part signature requires one input. [Detection, owner and recovery](#cause-SinglePartSignatureRequiresOneInput).
    SinglePartSignatureRequiresOneInput,
    /// Single-part verification requires one input. [Detection, owner and recovery](#cause-SinglePartVerificationRequiresOneInput).
    SinglePartVerificationRequiresOneInput,
}

impl std::fmt::Display for NativeSignatureRejection {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::SignatureParameterScalarAbiWidth => {
                f.write_str("signature parameter scalar ABI width")
            }
            Self::SingleVerificationRequiresOneInput => {
                f.write_str("single verification requires one input")
            }
            Self::SinglePartSignatureRequiresOneInput => {
                f.write_str("single-part signature requires one input")
            }
            Self::SinglePartVerificationRequiresOneInput => {
                f.write_str("single-part verification requires one input")
            }
        }
    }
}
