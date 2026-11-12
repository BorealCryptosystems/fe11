// SPDX-License-Identifier: Apache-2.0
//! Established-return operands carried outside the operation/session guards.
use crate::symmetric::memory::Buffer;

/// One returned input and one signature buffer can leave a drive boundary.
/// The signature slot carries either a consumed Verify input or a Sign output
/// returned after a capacity refusal. In the latter case the data input remains
/// in the operation for the exact-call continuation. The driver stops at its
/// input/capacity boundary before another submission; poll destroys these owners
/// after possession. These slots describe ownership, not a stream-size limit.
#[derive(Default)]
pub(in crate::advanced) struct ReleasedInputs {
    pub(super) fragment: Option<Buffer>,
    pub(super) signature: Option<Buffer>,
}

impl ReleasedInputs {
    pub(super) fn is_empty(&self) -> bool {
        self.fragment.is_none() && self.signature.is_none()
    }
}

impl crate::symmetric::memory::RetainedStorage for ReleasedInputs {
    fn retain_credits(
        &self,
        retained: &mut crate::symmetric::memory::RetainedBytes,
    ) -> crate::Result<()> {
        self.fragment.retain_credits(retained)?;
        self.signature.retain_credits(retained)?;
        Ok(())
    }
}
