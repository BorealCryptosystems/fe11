// SPDX-License-Identifier: Apache-2.0
//! Fallible aligned allocations and checked relocations for asserted ABI graphs.
use super::*;

use crate::{
    bounds,
    symmetric::memory::{Buffer, Credit},
};
use fe11_sys::{CK_ULONG, CK_VOID_PTR};
use std::{
    alloc::{alloc_zeroed, dealloc, Layout},
    mem::{align_of, size_of},
    ptr::NonNull,
};

struct AlignedStorage {
    pointer: NonNull<u8>,
    layout: Layout,
    length: usize,
}
impl AlignedStorage {
    fn layout(length: usize, alignment: usize) -> Result<Layout> {
        bounds::ck_length(length)?;
        if !alignment.is_power_of_two() {
            return Err(Error::Rejected(
                crate::RejectionReason::MechanismExtensions(
                    crate::MechanismExtensionsRejection::ExtensionBlockAlignment,
                ),
            ));
        }
        let alignment = alignment
            .max(align_of::<CK_ULONG>())
            .max(align_of::<CK_VOID_PTR>());
        // A present empty block still has a real aligned non-NULL address.
        Layout::from_size_align(length.max(1), alignment).map_err(|_| {
            Error::Rejected(crate::RejectionReason::MechanismExtensions(
                crate::MechanismExtensionsRejection::ExtensionAllocationLayout,
            ))
        })
    }
    fn allocate(block: recipe::BlockLayout) -> Result<Self> {
        let layout = Self::layout(block.length, block.alignment)?;
        // SAFETY: validated nonzero layout; null allocation is handled locally.
        let pointer = NonNull::new(unsafe { alloc_zeroed(layout) }).ok_or(Error::Rejected(
            crate::RejectionReason::MechanismExtensions(
                crate::MechanismExtensionsRejection::ExtensionAlignedAllocation,
            ),
        ))?;
        Ok(Self {
            pointer,
            layout,
            length: block.length,
        })
    }
    fn bind(self, prepaid: &mut Credit) -> Result<Aligned> {
        let credit = prepaid.split(self.layout.size())?;
        Ok(Aligned {
            storage: self,
            _credit: credit,
        })
    }
    fn bytes(&self) -> &[u8] {
        // SAFETY: all logical bytes were initialized; address remains allocated.
        unsafe { std::slice::from_raw_parts(self.pointer.as_ptr(), self.length) }
    }
    fn bytes_mut(&mut self) -> &mut [u8] {
        // SAFETY: uniquely borrowed initialized owned storage.
        unsafe { std::slice::from_raw_parts_mut(self.pointer.as_ptr(), self.length) }
    }
}
impl Drop for AlignedStorage {
    fn drop(&mut self) {
        // SAFETY: erase the entire actual allocation without reading possibly
        // modified ABI data. No native pointer is followed, even on bad output.
        unsafe {
            for offset in 0..self.layout.size() {
                self.pointer.as_ptr().add(offset).write_volatile(0);
            }
            std::sync::atomic::compiler_fence(std::sync::atomic::Ordering::SeqCst);
            dealloc(self.pointer.as_ptr(), self.layout);
        }
    }
}
struct Aligned {
    storage: AlignedStorage,
    _credit: Credit,
}
// SAFETY: uniquely owned allocation, no borrowed/native external referents.
unsafe impl Send for Aligned {}
impl Aligned {
    fn bytes(&self) -> &[u8] {
        self.storage.bytes()
    }
}

mod preparation;
pub(crate) mod recipe;
pub(crate) mod snapshot;
pub(crate) use preparation::GraphStorage;

struct Block {
    bytes: Aligned,
    witness: Buffer,
    direction: ExtensionDirection,
}
struct Output {
    region: ExtensionOutputRegion,
    // None until all output lengths have been validated after terminal success.
    length: Option<usize>,
}
pub(crate) struct OwnedGraph {
    blocks: Vec<Block>,
    pointers: Vec<ExtensionPointer>,
    // Auxiliary ordering only; ABI declarations and archive order are retained.
    pointer_order: Vec<usize>,
    outputs: Vec<Output>,
    root: Option<usize>,
    _credit: Credit,
}
fn invalid() -> Error {
    Error::Rejected(crate::RejectionReason::MechanismExtensions(
        crate::MechanismExtensionsRejection::ExtensionGraphRangeOrOverlap,
    ))
}
fn end(offset: usize, length: usize, bound: usize) -> Result<usize> {
    offset
        .checked_add(length)
        .filter(|n| *n <= bound)
        .ok_or_else(invalid)
}
fn overlaps(a: usize, an: usize, b: usize, bn: usize) -> bool {
    an != 0 && bn != 0 && a < b + bn && b < a + an
}
impl OwnedGraph {
    pub(crate) fn allocation_bytes(input: &ExtensionParameters<'_>) -> Result<usize> {
        Self::recipe_bytes(input)
    }
    pub(crate) fn recipe_bytes(input: &dyn recipe::Recipe) -> Result<usize> {
        Self::validate_structure(input)?;
        let mut metadata = size_of::<Self>();
        for (count, width) in [
            (input.block_count(), size_of::<Block>()),
            (input.pointer_count(), size_of::<ExtensionPointer>()),
            (input.pointer_count(), size_of::<usize>()),
            (input.output_count(), size_of::<Output>()),
            (input.block_count(), size_of::<preparation::PreparedBlock>()),
        ] {
            metadata = metadata
                .checked_add(count.checked_mul(width).ok_or_else(invalid)?)
                .ok_or_else(invalid)?;
        }
        let mut total = metadata;
        input.visit_blocks(&mut |_, block| {
            total = total
                .checked_add(AlignedStorage::layout(block.length, block.alignment)?.size())
                .and_then(|n| n.checked_add(block.length))
                .ok_or_else(invalid)?;
            Ok(())
        })?;
        Ok(total)
    }
    fn validate_structure(input: &dyn recipe::Recipe) -> Result<()> {
        if input.root().is_some_and(|root| root >= input.block_count()) {
            return Err(invalid());
        }
        if input.root().is_none()
            && (input.block_count() != 0 || input.pointer_count() != 0 || input.output_count() != 0)
        {
            return Err(Error::Rejected(
                crate::RejectionReason::MechanismExtensions(crate::MechanismExtensionsRejection::NullExtensionParameterCannotOwnUnreachableBlocks),
            ));
        }
        input.visit_blocks(&mut |_, block| {
            AlignedStorage::layout(block.length, block.alignment)?;
            Ok(())
        })?;
        Ok(())
    }
    /// The recipe must provide indexed blocks. `order` contains every pointer
    /// index once, sorted by its public (block, offset) coordinates. Both are
    /// prepared under the caller's aggregate credit, before native dispatch.
    fn validate_indexed(input: &dyn recipe::Recipe, order: &[usize]) -> Result<()> {
        Self::validate_structure(input)?;
        if order.len() != input.pointer_count() {
            return Err(invalid());
        }
        let mut previous: Option<ExtensionPointer> = None;
        for &index in order {
            let pointer = input.pointer(index)?;
            let block = input.block(pointer.block)?;
            end(pointer.offset, size_of::<CK_VOID_PTR>(), block.length)?;
            if let Some(other) = previous {
                if (other.block, other.offset) >= (pointer.block, pointer.offset) {
                    return Err(invalid());
                }
                if pointer.block == other.block
                    && overlaps(
                        pointer.offset,
                        size_of::<CK_VOID_PTR>(),
                        other.offset,
                        size_of::<CK_VOID_PTR>(),
                    )
                {
                    return Err(invalid());
                }
            }
            let mut placeholder = [0; size_of::<CK_VOID_PTR>()];
            input.copy(pointer.block, pointer.offset, &mut placeholder)?;
            if placeholder.iter().any(|byte| *byte != 0) {
                return Err(Error::Rejected(
                    crate::RejectionReason::MechanismExtensions(
                        crate::MechanismExtensionsRejection::ExtensionPointerPlaceholderMustBeZero,
                    ),
                ));
            }
            if let ExtensionPointerTarget::Block { block, offset } = pointer.target {
                end(offset, 0, input.block(block)?.length)?;
            }
            previous = Some(pointer);
        }
        let without_pointer = |block: usize, offset: usize, length: usize| -> Result<()> {
            if length == 0 {
                return Ok(());
            }
            let boundary = offset.checked_add(length).ok_or_else(invalid)?;
            // Locate the last pointer starting before the end of this region.
            // Non-overlapping sorted fields make it the only possible overlap.
            let mut low = 0;
            let mut high = order.len();
            while low < high {
                let middle = low + (high - low) / 2;
                let pointer = input.pointer(order[middle])?;
                if (pointer.block, pointer.offset) < (block, boundary) {
                    low = middle + 1;
                } else {
                    high = middle;
                }
            }
            if low != 0 {
                let pointer = input.pointer(order[low - 1])?;
                if pointer.block == block
                    && overlaps(offset, length, pointer.offset, size_of::<CK_VOID_PTR>())
                {
                    return Err(invalid());
                }
            }
            Ok(())
        };
        for index in 0..input.output_count() {
            let output = input.output(index)?;
            let block = input.block(output.block)?;
            end(output.offset, output.capacity, block.length)?;
            if block.direction == ExtensionDirection::Input {
                return Err(invalid());
            }
            without_pointer(output.block, output.offset, output.capacity)?;
            if let ExtensionOutputLength::NativeUnsigned { block, offset } = output.length {
                end(offset, size_of::<CK_ULONG>(), input.block(block)?.length)?;
                without_pointer(block, offset, size_of::<CK_ULONG>())?;
            }
        }
        Ok(())
    }

    fn relocate(&mut self) {
        for pointer in &self.pointers {
            let target: CK_VOID_PTR = match pointer.target {
                ExtensionPointerTarget::Null => std::ptr::null_mut(),
                ExtensionPointerTarget::Block { block, offset } => {
                    // SAFETY: offset is within or one past an owned allocation.
                    unsafe {
                        self.blocks[block]
                            .bytes
                            .storage
                            .pointer
                            .as_ptr()
                            .add(offset)
                            .cast()
                    }
                }
            };
            let destination = &mut self.blocks[pointer.block].bytes;
            // SAFETY: validated pointer-width field within owned storage. Use
            // write_unaligned for packed ABIs; preserve pointer provenance.
            unsafe {
                destination
                    .storage
                    .pointer
                    .as_ptr()
                    .add(pointer.offset)
                    .cast::<CK_VOID_PTR>()
                    .write_unaligned(target);
            }
        }
        for block in &mut self.blocks {
            block.witness.as_mut().copy_from_slice(block.bytes.bytes());
        }
    }
    /// Compare a declared key scalar after native memory return. This reads
    /// owned bytes only; it neither follows pointers nor interprets arbitrary
    /// unmarked bytes as object handles.
    pub(crate) fn has_handle(
        &self,
        block: usize,
        offset: usize,
        handle: fe11_sys::CK_OBJECT_HANDLE,
    ) -> bool {
        let Some(end) = offset.checked_add(size_of::<fe11_sys::CK_OBJECT_HANDLE>()) else {
            return false;
        };
        self.blocks
            .get(block)
            .and_then(|block| block.bytes.bytes().get(offset..end))
            .is_some_and(|bytes| bytes == handle.to_ne_bytes())
    }

    pub(crate) fn projection(&mut self) -> (CK_VOID_PTR, CK_ULONG) {
        self.root.map_or((std::ptr::null_mut(), 0), |root| {
            let block = &mut self.blocks[root];
            (
                block.bytes.storage.pointer.as_ptr().cast(),
                block.bytes.storage.length as CK_ULONG,
            )
        })
    }
    pub(crate) fn unchanged(&self) -> bool {
        // Compare bytes without following native-written pointers. Accumulate
        // differences so secret input content does not select an early return.
        let mut difference = 0u8;
        for (index, block) in self.blocks.iter().enumerate() {
            let actual = block.bytes.bytes();
            let expected = block.witness.as_slice();
            if block.direction == ExtensionDirection::Input {
                for (actual, expected) in actual.iter().zip(expected) {
                    difference |= actual ^ expected;
                }
            } else {
                // Mutable bytes are deliberately excluded. Pointer locations
                // are public metadata; their contents never select a shortcut.
                for pointer in self.pointer_fields(index) {
                    let range = pointer.offset..pointer.offset + size_of::<CK_VOID_PTR>();
                    for (actual, expected) in actual[range.clone()].iter().zip(&expected[range]) {
                        difference |= actual ^ expected;
                    }
                }
            }
        }
        difference == 0
    }
    /// Compare only the fixed high-order bits of a generated nonce. Dimensions
    /// beyond the supplied extent remain the module's parameter decision; every
    /// existing bit in that prefix must still be unchanged on an ordinary return.
    /// No native-written pointer or reported length is dereferenced here.
    pub(crate) fn fixed_prefix_unchanged(&self, index: usize, bits: u64) -> bool {
        let Some(block) = self.blocks.get(index) else {
            return false;
        };
        let actual = block.bytes.bytes();
        let expected = block.witness.as_slice();
        let mut difference = 0u8;
        for (index, (actual, expected)) in actual.iter().zip(expected).enumerate() {
            let offset = index as u128 * 8;
            let retained = (bits as u128).saturating_sub(offset).min(8) as u32;
            let mask = if retained == 0 {
                0
            } else {
                0xffu8 << (8 - retained)
            };
            difference |= (actual ^ expected) & mask;
        }
        difference == 0
    }

    fn pointer_fields(&self, block: usize) -> impl Iterator<Item = &ExtensionPointer> {
        let start = self
            .pointer_order
            .partition_point(|index| self.pointers[*index].block < block);
        self.pointer_order[start..]
            .iter()
            .map(|index| &self.pointers[*index])
            .take_while(move |pointer| pointer.block == block)
    }
    pub(crate) fn read_only(&self) -> bool {
        self.outputs.is_empty()
            && self
                .blocks
                .iter()
                .all(|b| b.direction == ExtensionDirection::Input)
    }
    /// Inspect physical extents after successful native return, before handle
    /// registration or frame release. This never publishes a region or follows
    /// a native-written pointer; offsets belong to the validated owned recipe.
    pub(crate) fn validate_output_bounds(&self) -> Result<()> {
        for output in &self.outputs {
            self.output_length(&output.region)?;
        }
        Ok(())
    }

    fn output_length(&self, region: &ExtensionOutputRegion) -> Result<usize> {
        let length = match region.length {
            ExtensionOutputLength::Fixed => region.capacity,
            ExtensionOutputLength::NativeUnsigned { block, offset } => {
                // SAFETY: validated, initialized CK_ULONG-sized owned region;
                // no alignment requirement or foreign pointer dereference.
                let native = unsafe {
                    self.blocks[block]
                        .bytes
                        .storage
                        .pointer
                        .as_ptr()
                        .add(offset)
                        .cast::<CK_ULONG>()
                        .read_unaligned()
                };
                usize::try_from(native).map_err(|_| invalid())?
            }
        };
        if length > region.capacity {
            return Err(Error::Rejected(
                crate::RejectionReason::MechanismExtensions(
                    crate::MechanismExtensionsRejection::ExtensionOutputExceedsCapacity,
                ),
            ));
        }
        Ok(length)
    }

    pub(crate) fn finish(&mut self) -> Result<()> {
        // No publication occurs until this whole method succeeds. Fixed output
        // validity and initialization are part of the unsafe module contract.
        let result = (|| {
            for index in 0..self.outputs.len() {
                let length = self.output_length(&self.outputs[index].region)?;
                self.outputs[index].length = Some(length);
            }
            Ok(())
        })();
        if result.is_err() {
            // No partially accepted view survives a rejected region, including
            // a later validation attempt after an earlier successful finish.
            for output in &mut self.outputs {
                output.length = None;
            }
        }
        result
    }
    pub(crate) fn output(&self, index: usize) -> Option<&[u8]> {
        let output = self.outputs.get(index)?;
        let length = output.length?;
        Some(
            &self.blocks[output.region.block].bytes.bytes()
                [output.region.offset..output.region.offset + length],
        )
    }
}

impl crate::symmetric::memory::RetainedStorage for OwnedGraph {
    fn retain_credits(
        &self,
        retained: &mut crate::symmetric::memory::RetainedBytes,
    ) -> crate::Result<()> {
        // Tables and their spare capacity are already included in _credit.
        // Visit owned blocks, never follow the native pointer graph.
        retained.add_credit(&self._credit)?;
        for block in &self.blocks {
            retained.add_credit(&block.bytes._credit)?;
            block.witness.retain_credit(retained)?;
        }
        Ok(())
    }
}
