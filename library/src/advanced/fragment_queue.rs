// SPDX-License-Identifier: Apache-2.0
//! Contiguous remaining fragments, with ownership transfer instead of shifting.
use crate::symmetric::memory::{Buffer, RetainedBytes, RetainedStorage};
use std::ops::{Deref, DerefMut};

/// The frame's metadata credit covers the entire vector capacity. Consuming a
/// slot transfers its buffer and credit to a retirement owner; only an empty
/// placeholder remains. Slices expose the suffix needed by native calls and
/// snapshots, so neither operation sees the consumed prefix.
pub(super) struct FragmentQueue {
    slots: Vec<Buffer>,
    first: usize,
}

impl From<Vec<Buffer>> for FragmentQueue {
    fn from(slots: Vec<Buffer>) -> Self {
        Self { slots, first: 0 }
    }
}

impl FragmentQueue {
    pub(super) fn capacity(&self) -> usize {
        self.slots.capacity()
    }

    /// The caller establishes a current fragment before issuing its native
    /// operation. Its returned owner must outlive all access guards.
    pub(super) fn pop_front(&mut self) -> Buffer {
        let buffer = self.slots[self.first].take();
        self.first += 1;
        buffer
    }

    /// Used only while preparing an empty incremental stream. No native call
    /// owns these slots; consumed operands use pop_front and explicit retirement.
    pub(super) fn clear(&mut self) {
        self.slots.clear();
        self.first = 0;
    }
}

impl Deref for FragmentQueue {
    type Target = [Buffer];

    fn deref(&self) -> &Self::Target {
        &self.slots[self.first..]
    }
}

impl DerefMut for FragmentQueue {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.slots[self.first..]
    }
}

impl<'a> IntoIterator for &'a FragmentQueue {
    type Item = &'a Buffer;
    type IntoIter = std::slice::Iter<'a, Buffer>;

    fn into_iter(self) -> Self::IntoIter {
        self.iter()
    }
}

impl<'a> IntoIterator for &'a mut FragmentQueue {
    type Item = &'a mut Buffer;
    type IntoIter = std::slice::IterMut<'a, Buffer>;

    fn into_iter(self) -> Self::IntoIter {
        self.iter_mut()
    }
}

impl RetainedStorage for FragmentQueue {
    fn retain_credits(&self, retained: &mut RetainedBytes) -> crate::Result<()> {
        // Earlier slots contain no storage or byte credit after pop_front.
        for buffer in self {
            buffer.retain_credits(retained)?;
        }
        Ok(())
    }
}
