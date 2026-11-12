// SPDX-License-Identifier: Apache-2.0
//! Private input witness: erase a consumed prefix without moving the suffix.
use crate::symmetric::memory::{Buffer, RetainedBytes, RetainedStorage};
use crate::{Error, Result};
use zeroize::Zeroize;

pub(super) struct Shadow {
    bytes: Buffer,
    first: usize,
}

impl From<Buffer> for Shadow {
    fn from(bytes: Buffer) -> Self {
        Self { bytes, first: 0 }
    }
}

impl Shadow {
    pub(super) fn as_slice(&self) -> &[u8] {
        &self.bytes.as_slice()[self.first..]
    }

    pub(super) fn as_mut(&mut self) -> &mut [u8] {
        &mut self.bytes.as_mut()[self.first..]
    }

    pub(super) fn capacity(&self) -> usize {
        self.bytes.capacity() - self.first
    }

    pub(super) fn discard_prefix_retained(&mut self, count: usize) -> Result<()> {
        if count > self.as_slice().len() {
            return Err(Error::Rejected(crate::RejectionReason::CipherContinuation(
                crate::CipherContinuationRejection::InputPrefixRange,
            )));
        }
        // Bounded by the live suffix, so the addition cannot overflow. Only
        // the private witness is erased; native input addresses never change.
        let end = self.first + count;
        self.bytes.as_mut()[self.first..end].zeroize();
        self.first = end;
        Ok(())
    }

    pub(super) fn copy_from(&mut self, source: &Self) -> Result<()> {
        if self.capacity() != source.capacity() {
            return Err(Error::Rejected(crate::RejectionReason::OperationOwnership(
                crate::OperationOwnershipRejection::ContinuationBufferCapacity,
            )));
        }
        self.as_mut().copy_from_slice(source.as_slice());
        Ok(())
    }

    pub(super) fn take(&mut self) -> Buffer {
        self.first = 0;
        self.bytes.take()
    }
}

impl RetainedStorage for Shadow {
    fn retain_credits(&self, retained: &mut RetainedBytes) -> Result<()> {
        // The full allocation remains charged until the witness is retired.
        self.bytes.retain_credits(retained)
    }
}
