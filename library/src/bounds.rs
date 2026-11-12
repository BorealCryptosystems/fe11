// SPDX-License-Identifier: Apache-2.0
use crate::{Error, Result};

pub(crate) fn count(value: fe11_sys::CK_ULONG, limit: usize) -> Result<usize> {
    count_reason(value, limit)
        .map_err(|reason| Error::Rejected(crate::RejectionReason::InputBounds(reason)))
}

/// Classify the same bound without discarding a caller's native observation.
pub(crate) fn count_reason(
    value: fe11_sys::CK_ULONG,
    limit: usize,
) -> std::result::Result<usize, crate::InputBoundsRejection> {
    let n = usize::try_from(value).map_err(|_| crate::InputBoundsRejection::LengthConversion)?;
    if value == fe11_sys::CK_UNAVAILABLE_INFORMATION || n > limit {
        return Err(crate::InputBoundsRejection::LengthBound);
    }
    Ok(n)
}
pub(crate) fn final_length(value: fe11_sys::CK_ULONG, capacity: usize) -> Result<usize> {
    count(value, capacity)
}
pub(crate) fn ck_length(value: usize) -> Result<fe11_sys::CK_ULONG> {
    value.try_into().map_err(|_| {
        Error::Rejected(crate::RejectionReason::InputBounds(
            crate::InputBoundsRejection::LengthConversion,
        ))
    })
}

/// Populate the auxiliary GCM bit count without restricting the byte length.
/// PKCS#11 defines ulIvLen as authoritative. Like cryptoki, use zero when the
/// redundant bit count cannot fit CK_ULONG; never truncate or wrap that count.
pub(crate) fn gcm_iv_bits(byte_length: fe11_sys::CK_ULONG) -> fe11_sys::CK_ULONG {
    byte_length.checked_mul(8).unwrap_or(0)
}

// Attribute payloads are length-delimited. Empty IDs and UTF-8 control
// characters are not resource identities or library-defined policy violations.
pub(crate) fn metadata_lengths(id: &[u8], label: &[u8]) -> Result<()> {
    ck_length(id.len())?;
    ck_length(label.len())?;
    Ok(())
}
