// SPDX-License-Identifier: Apache-2.0
//! Scalar output observations are not permission to access or allocate buffers.

/// A native output-length observation together with the caller's storage bound.
/// This record contains no output bytes, key handle or continuation authority.
/// A successful size query does not establish completion of the enclosing
/// cryptographic operation. A failed call does not establish absence of effects.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct NativeOutputSize {
    /// Exact native function that produced the observation.
    pub function: &'static str,
    /// Exact native return code, including CKR_OK for a successful size query.
    pub code: u64,
    /// Native length as reported, without truncation or allocation-policy filtering.
    /// An accompanying integrity failure makes this an untrusted observation.
    pub reported: u64,
    /// Caller-selected ceiling or supplied capacity in native output units:
    /// bytes for byte outputs, descriptors for `C_GetInterfaceList`.
    pub limit: usize,
}

impl std::fmt::Display for NativeOutputSize {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "{} returned 0x{:08x}; output length {}, caller limit {}",
            self.function, self.code, self.reported, self.limit
        )
    }
}

/// Preserve a completed size observation even when its bound is rejected. This
/// only handles the scalar: it neither allocates output nor claims its capture.
pub(crate) fn checked_native_size(
    function: &'static str,
    code: fe11_sys::CK_RV,
    reported: fe11_sys::CK_ULONG,
    limit: usize,
) -> crate::Result<usize> {
    crate::bounds::count_reason(reported, limit).map_err(|reason| {
        crate::Error::OutputSizeRejected {
            size: NativeOutputSize {
                function,
                code: code as u64,
                reported: reported as u64,
                limit,
            },
            reason,
        }
    })
}

impl NativeOutputSize {
    /// Only a returned insufficient-buffer call defines this observation.
    /// The lazy read must address the caller-owned length slot for that call.
    pub(crate) fn buffer_refusal(
        function: &'static str,
        code: fe11_sys::CK_RV,
        limit: usize,
        read: impl FnOnce() -> fe11_sys::CK_ULONG,
    ) -> Option<Self> {
        (code == fe11_sys::CKR_BUFFER_TOO_SMALL && crate::native_return::call_memory_returned(code))
            .then(|| Self {
                function,
                code: code as u64,
                reported: read() as u64,
                limit,
            })
    }

    /// Keep the native scalar even on a target where it cannot fit usize.
    /// This observation authorizes neither allocation nor another native call.
    pub(crate) fn buffer_too_small(self) -> crate::Error {
        match fe11_sys::CK_ULONG::try_from(self.reported)
            .map_err(|_| crate::InputBoundsRejection::LengthConversion)
            .and_then(|native| crate::bounds::count_reason(native, usize::MAX))
        {
            Ok(required) => crate::Error::OutputBufferTooSmall {
                function: self.function,
                code: self.code,
                required,
                capacity: self.limit,
            },
            Err(reason) => crate::Error::OutputSizeRejected { size: self, reason },
        }
    }
}
