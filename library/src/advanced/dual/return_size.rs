// SPDX-License-Identifier: Apache-2.0
//! Observe only the defined output slot of this dual-operation step.
use super::{DualStep, Mode};
use crate::native_return::protocol::PendingInspection;
use crate::NativeOutputSize;
use fe11_sys::CK_ULONG;

pub(super) fn observe(
    returned: &PendingInspection,
    step: DualStep,
    mode: Mode,
    cipher: (usize, impl FnOnce() -> CK_ULONG),
    authentication: (usize, impl FnOnce() -> CK_ULONG),
) -> Option<NativeOutputSize> {
    // The token preserves Direct versus AsyncCompletion through forwarding.
    // Neither a completed/joined observation nor an uncertain direct return
    // permits reading an old length slot from the original invocation.
    match step {
        DualStep::Update(_) | DualStep::CipherFinal => {
            returned.direct_output_size(cipher.0, cipher.1)
        }
        DualStep::AuthFinal if mode != Mode::DecryptVerify => {
            returned.direct_output_size(authentication.0, authentication.1)
        }
        _ => None,
    }
}
