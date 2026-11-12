// SPDX-License-Identifier: Apache-2.0
//! NativeOtp causes, separate from native result/effect information.

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[non_exhaustive]
/// Causes belonging to native otp.
#[doc = include_str!("../../../docs/diagnostics/rejection-native_otp.md")]
pub enum NativeOtpRejection {
    /// OTP output is not a bounded contiguous native graph. [Detection, owner and recovery](#cause-OtpOutputIsNotABoundedContiguousNativeGraph).
    OtpOutputIsNotABoundedContiguousNativeGraph,
    /// OTP scalar ABI width. [Detection, owner and recovery](#cause-OtpScalarAbiWidth).
    OtpScalarAbiWidth,
    /// OTP value accounting. [Detection, owner and recovery](#cause-OtpValueAccounting).
    OtpValueAccounting,
    /// Caller OTP parameter count bound. [Detection, owner and recovery](#cause-CallerOtpParameterCountBound).
    CallerOtpParameterCountBound,
    /// Caller OTP value byte bound. [Detection, owner and recovery](#cause-CallerOtpValueByteBound).
    CallerOtpValueByteBound,
}

impl std::fmt::Display for NativeOtpRejection {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::OtpOutputIsNotABoundedContiguousNativeGraph => {
                f.write_str("OTP output is not a bounded contiguous native graph")
            }
            Self::OtpScalarAbiWidth => f.write_str("OTP scalar ABI width"),
            Self::OtpValueAccounting => f.write_str("OTP value accounting"),
            Self::CallerOtpParameterCountBound => f.write_str("caller OTP parameter count bound"),
            Self::CallerOtpValueByteBound => f.write_str("caller OTP value byte bound"),
        }
    }
}
