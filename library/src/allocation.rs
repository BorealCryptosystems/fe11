// SPDX-License-Identifier: Apache-2.0
//! Fallible stable storage prepared before native possession.
use crate::{Error, Result};
use std::alloc::{alloc, Layout};

/// Move the value out and finish the box's allocation lifetime before returning.
/// Use this boundary when a prepaid payload is about to enter another stable
/// allocation: the old envelope must not overlap the new one. The value and
/// its nested owners are moved, not dropped; no native pointer may still name
/// the envelope being removed.
pub(crate) fn unbox<T>(value: Box<T>) -> T {
    *value
}

/// Allocate one stable value using the global allocator used by `Box`.
/// The caller accounts for `size_of::<T>()` in its prepared owner credit; this
/// helper neither waits for credit nor publishes a native pointer.
pub(crate) fn boxed<T>(value: T) -> Result<Box<T>> {
    let layout = Layout::new::<T>();
    if layout.size() == 0 {
        // Box does not allocate for a zero-sized type, including aligned ZSTs.
        return Ok(Box::new(value));
    }
    // SAFETY: Layout::new provides T's exact nonzero size and alignment. The
    // global allocator may return null; no pointer is used until checked below.
    let pointer = unsafe { alloc(layout) }.cast::<T>();
    if pointer.is_null() {
        return Err(Error::Rejected(crate::RejectionReason::MemoryAllocation(
            crate::MemoryAllocationRejection::StableOwnerAllocation,
        )));
    }
    // SAFETY: the checked allocation is aligned and large enough for one T.
    // Writing initializes it exactly once without reading uninitialized memory.
    // Box takes sole ownership with the same global allocator and layout; its
    // ordinary Drop then destroys T and releases this allocation exactly once.
    unsafe {
        pointer.write(value);
        Ok(Box::from_raw(pointer))
    }
}

/// An allocated but uninitialized stable slot. Dropping it before `write`
/// frees only storage: it owns no T, native address or caller-transferred input.
pub(crate) struct Slot<T> {
    storage: Box<std::mem::MaybeUninit<T>>,
}

impl<T> Slot<T> {
    /// The enclosing candidate charges size_of::<T>() before this allocation.
    pub(crate) fn new() -> Result<Self> {
        Ok(Self {
            storage: boxed(std::mem::MaybeUninit::uninit())?,
        })
    }

    /// Initialize once, after all fallible candidate preparation has succeeded.
    /// This transfer neither allocates nor exposes uninitialized storage.
    pub(crate) fn write(self, value: T) -> Box<T> {
        let pointer = Box::into_raw(self.storage).cast::<T>();
        // SAFETY: MaybeUninit<T> has T's size and alignment, including aligned
        // zero-sized T. For nonzero T the Box owns a global allocation; for a
        // zero-sized T it provides a nonnull aligned pointer without allocating.
        // into_raw transfers sole ownership here. No T occupied the slot.
        // The write cannot panic, initializes T once, and immediately restores
        // ownership as Box<T> with the same layout and allocator. No reference
        // to the uninitialized storage escapes and there is no second owner.
        unsafe {
            pointer.write(value);
            Box::from_raw(pointer)
        }
    }
}
