// SPDX-License-Identifier: Apache-2.0
//! Aligned secret storage: no temporary public byte vector and no implicit copy.
use super::*;

use crate::symmetric::memory::Credit;

use zeroize::Zeroize;

// Allocate from an already admitted graph budget. The Vec precedes its credit
// in the returned tuple so failures drop storage before returning the allowance.
pub(super) fn reserve_prepaid_entries<T>(
    prepaid: &mut Credit,
    count: usize,
) -> Result<(Vec<T>, Credit)> {
    let width = std::mem::size_of::<T>();
    let bytes = count.checked_mul(width).ok_or(Error::Rejected(
        crate::RejectionReason::AttributeValues(
            crate::AttributeValuesRejection::AttributeMetadataAccountingOverflow,
        ),
    ))?;
    let mut credit = prepaid.split(bytes)?;
    let mut entries = Vec::new();
    entries.try_reserve_exact(count).map_err(|_| {
        Error::Rejected(crate::RejectionReason::AttributeValues(
            crate::AttributeValuesRejection::AttributeMetadataAllocation,
        ))
    })?;
    let excess = (entries.capacity() - count)
        .checked_mul(width)
        .ok_or(Error::Rejected(crate::RejectionReason::AttributeValues(
            crate::AttributeValuesRejection::AttributeAllocatorAccountingOverflow,
        )))?;
    credit.cover_allocated(excess)?;
    Ok((entries, credit))
}

// Native writes may replace descriptor bytes, including padding. Never read
// those bytes to erase them and never follow the pointers they might contain.
pub(super) fn erase_descriptors(descriptors: &mut Vec<CK_ATTRIBUTE>) {
    // Vec's allocated non-ZST capacity times element size fits its allocation.
    let bytes = descriptors.capacity() * std::mem::size_of::<CK_ATTRIBUTE>();
    let pointer = descriptors.as_mut_ptr().cast::<u8>();
    for offset in 0..bytes {
        // SAFETY: the complete capacity is our live allocation. Volatile byte
        // stores do not read potentially uninitialized padding or pointer data.
        unsafe {
            pointer.add(offset).write_volatile(0);
        }
    }
    std::sync::atomic::compiler_fence(std::sync::atomic::Ordering::SeqCst);
}

/// Exact native attribute bytes in aligned, erased storage with retained credit.
/// Caller-made copies are outside this owner's erasure guarantee.
pub struct AttributeBytes {
    words: Vec<CK_ULONG>,
    length: usize,
    capacity: usize,
    _credit: Credit,
}

/// Empty aligned storage for a complete unpublished graph. Its caller measures
/// all actual capacities before binding any child or copying caller values.
pub(super) struct AttributeBytesStorage {
    words: Vec<CK_ULONG>,
    capacity: usize,
}
impl AttributeBytesStorage {
    pub(super) fn allocate(capacity: usize) -> Result<Self> {
        let count = AttributeBytes::allocation_bytes(capacity)? / std::mem::size_of::<CK_ULONG>();
        let mut words = Vec::new();
        words.try_reserve_exact(count).map_err(|_| {
            Error::Rejected(crate::RejectionReason::AttributeValues(
                crate::AttributeValuesRejection::ProtectedAttributeAllocation,
            ))
        })?;
        words.resize(words.capacity(), 0);
        Ok(Self { words, capacity })
    }

    pub(super) fn allocated_bytes(&self) -> Result<usize> {
        self.words
            .capacity()
            .checked_mul(std::mem::size_of::<CK_ULONG>())
            .ok_or(Error::Rejected(crate::RejectionReason::AttributeValues(
                crate::AttributeValuesRejection::AttributeAllocatorAccountingOverflow,
            )))
    }

    pub(super) fn bind(mut self, prepaid: &mut Credit) -> Result<AttributeBytes> {
        let credit = prepaid.split(self.allocated_bytes()?)?;
        Ok(AttributeBytes {
            words: std::mem::take(&mut self.words),
            length: self.capacity,
            capacity: self.capacity,
            _credit: credit,
        })
    }
}
impl Drop for AttributeBytesStorage {
    fn drop(&mut self) {
        self.words.zeroize();
    }
}

impl AttributeBytes {
    pub(super) fn allocation_bytes(capacity: usize) -> Result<usize> {
        bounds::ck_length(capacity)?;
        let width = std::mem::size_of::<CK_ULONG>();
        capacity
            .checked_add(width - 1)
            .and_then(|n| (n / width).checked_mul(width))
            .ok_or(Error::Rejected(crate::RejectionReason::AttributeValues(
                crate::AttributeValuesRejection::AttributeAlignmentOverflow,
            )))
    }
    // Split one pre-admitted request budget; never wait while retaining another
    // part of the same graph. Allocator excess uses immediate admission below.
    pub(super) fn new_prepaid(capacity: usize, prepaid: &mut Credit) -> Result<Self> {
        let bytes = Self::allocation_bytes(capacity)?;
        let width = std::mem::size_of::<CK_ULONG>();
        let count = bytes / width;
        let mut credit = prepaid.split(bytes)?;
        let mut words = Vec::new();
        words.try_reserve_exact(count).map_err(|_| {
            Error::Rejected(crate::RejectionReason::AttributeValues(
                crate::AttributeValuesRejection::ProtectedAttributeAllocation,
            ))
        })?;
        let excess = words
            .capacity()
            .checked_sub(count)
            .and_then(|n| n.checked_mul(width))
            .ok_or(Error::Rejected(crate::RejectionReason::AttributeValues(
                crate::AttributeValuesRejection::AttributeAllocatorAccountingOverflow,
            )))?;
        credit.cover_allocated(excess)?;
        // Initialize every allocated word. Drop erases this complete region,
        // including rounded storage and any allocator-provided excess capacity.
        words.resize(words.capacity(), 0);
        Ok(Self {
            words,
            length: capacity,
            capacity,
            _credit: credit,
        })
    }
    pub(super) fn pointer(&mut self) -> CK_VOID_PTR {
        self.words.as_mut_ptr().cast()
    }
    pub(super) fn capacity(&self) -> usize {
        self.capacity
    }
    // Used only before native dispatch to construct owned input values and
    // their independent witnesses. No temporary public Vec contains the bytes.
    pub(super) fn copy_from(&mut self, bytes: &[u8]) -> Result<()> {
        if bytes.len() != self.capacity {
            return Err(Error::Rejected(crate::RejectionReason::AttributeValues(
                crate::AttributeValuesRejection::AttributeInputByteLength,
            )));
        }
        self.copy_at(0, bytes)
    }
    pub(super) fn copy_at(&mut self, offset: usize, bytes: &[u8]) -> Result<()> {
        let end = offset
            .checked_add(bytes.len())
            .filter(|end| *end <= self.capacity)
            .ok_or(Error::Rejected(crate::RejectionReason::AttributeValues(
                crate::AttributeValuesRejection::AttributeInputCopyRange,
            )))?;
        // SAFETY: the entire allocation is initialized. The checked range is
        // within logical capacity; the exclusive borrow prevents an alias to
        // this storage, including through the input slice, in safe Rust.
        unsafe {
            std::slice::from_raw_parts_mut(self.words.as_mut_ptr().cast::<u8>(), self.capacity)
                [offset..end]
                .copy_from_slice(bytes);
        }
        Ok(())
    }
    pub(super) fn set_length(&mut self, length: usize) -> Result<()> {
        if length > self.capacity {
            return Err(Error::Rejected(
                crate::RejectionReason::AttributePreparation(
                    crate::AttributePreparationRejection::AttributeFinalLength,
                ),
            ));
        }
        // Erase withheld tail bytes before publication, including allocator
        // padding. The whole initialized allocation is erased again on Drop.
        let initialized = std::mem::size_of_val(self.words.as_slice());
        // SAFETY: the complete words slice is initialized, exclusively borrowed,
        // and byte aliasing is permitted. length is within logical capacity.
        unsafe {
            std::slice::from_raw_parts_mut(self.words.as_mut_ptr().cast::<u8>(), initialized)
                [length..]
                .zeroize();
        }
        self.length = length;
        Ok(())
    }
    /// Borrow only the returned bytes. This never exposes spare allocation space.
    pub fn as_bytes(&self) -> &[u8] {
        // SAFETY: every storage word is initialized and all bit patterns of
        // CK_ULONG are valid. Byte aliasing is permitted; length is bounded by
        // logical capacity, which fits this allocation. The borrow retains self.
        unsafe { std::slice::from_raw_parts(self.words.as_ptr().cast(), self.length) }
    }
}
impl Drop for AttributeBytes {
    fn drop(&mut self) {
        self.words.zeroize();
    }
}
