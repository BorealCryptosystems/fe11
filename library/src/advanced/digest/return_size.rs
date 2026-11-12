// SPDX-License-Identifier: Apache-2.0
//! Repeated observation of a retained digest storage request.
use super::Step;
use crate::NativeOutputSize;

pub(super) fn remembered(step: Step, capacity: usize) -> Option<NativeOutputSize> {
    let Step::OutputRequired { single, required } = step else {
        return None;
    };
    Some(NativeOutputSize {
        function: if single { "C_Digest" } else { "C_DigestFinal" },
        code: fe11_sys::CKR_BUFFER_TOO_SMALL as u64,
        reported: required as u64,
        limit: capacity,
    })
}
