// SPDX-License-Identifier: Apache-2.0
//! Pointer-free continuation recipes for already owned ABI graphs.
//!
//! This codec preserves representation, not authority. Restoring a graph still
//! requires the original live declaration or an explicit destination ABI
//! declaration for a caller-defined layout. Archive integrity does not grant
//! that declaration. Native layouts are not
//! portable between pointer widths, CK_ULONG widths, or byte orders.
use super::{
    invalid,
    recipe::{BlockLayout, Recipe},
    OwnedGraph,
};
use crate::{
    Error, ExtensionDirection, ExtensionOutputLength, ExtensionOutputRegion, ExtensionPointer,
    ExtensionPointerTarget, Result,
};
use fe11_sys::{CK_ULONG, CK_VOID_PTR};
use std::mem::size_of;

const MAGIC: &[u8; 4] = b"FG01";
const POINTER_BYTES: usize = 33;
const OUTPUT_BYTES: usize = 41;

mod index;
pub(crate) use index::SnapshotIndex;

fn word(value: usize, write: &mut impl FnMut(&[u8]) -> Result<()>) -> Result<()> {
    let value = u64::try_from(value).map_err(|_| invalid())?;
    write(&value.to_le_bytes())
}

impl OwnedGraph {
    /// Storage for a reconstructed graph, including temporary vector capacity.
    /// No allocation or native pointer traversal occurs while inspecting it.
    pub(crate) fn snapshot_allocation_bytes(&self) -> Result<usize> {
        let mut total = size_of::<Self>();
        for (count, width) in [
            (self.blocks.len(), size_of::<super::Block>()),
            (
                self.blocks.len(),
                size_of::<super::preparation::PreparedBlock>(),
            ),
            (self.pointers.len(), size_of::<ExtensionPointer>()),
            (self.pointers.len(), size_of::<usize>()),
            (self.outputs.len(), size_of::<super::Output>()),
        ] {
            total = total
                .checked_add(count.checked_mul(width).ok_or_else(invalid)?)
                .ok_or_else(invalid)?;
        }
        self.blocks.iter().try_fold(total, |total, block| {
            total
                .checked_add(block.bytes.storage.layout.size())
                .and_then(|n| n.checked_add(block.bytes.bytes().len()))
                .ok_or_else(invalid)
        })
    }

    /// Count using exactly the serializer, before reserving a destination.
    pub(crate) fn snapshot_bytes(&self) -> Result<usize> {
        let mut length = 0usize;
        self.write_snapshot(&mut |bytes| {
            length = length.checked_add(bytes.len()).ok_or_else(invalid)?;
            Ok(())
        })?;
        Ok(length)
    }

    /// Write without allocating or following native pointers. Every declared
    /// pointer field becomes zero; its referent is encoded by owned block index.
    /// Call only at an established native return while the operation is held.
    pub(crate) fn write_snapshot(&self, write: &mut impl FnMut(&[u8]) -> Result<()>) -> Result<()> {
        if !self.unchanged() {
            return Err(Error::Rejected(
                crate::RejectionReason::MechanismExtensions(
                    crate::MechanismExtensionsRejection::ChangedGraphCannotBeCaptured,
                ),
            ));
        }
        write(MAGIC)?;
        write(&[
            size_of::<CK_VOID_PTR>() as u8,
            size_of::<CK_ULONG>() as u8,
            u8::from(cfg!(target_endian = "little")),
            0,
        ])?;
        word(
            self.root
                .map(|index| index.checked_add(1).ok_or_else(invalid))
                .transpose()?
                .unwrap_or(0),
            write,
        )?;
        word(self.blocks.len(), write)?;
        word(self.pointers.len(), write)?;
        word(self.outputs.len(), write)?;
        for (index, block) in self.blocks.iter().enumerate() {
            let bytes = block.bytes.bytes();
            word(bytes.len(), write)?;
            word(block.bytes.storage.layout.align(), write)?;
            write(&[match block.direction {
                ExtensionDirection::Input => 0,
                ExtensionDirection::Output => 1,
                ExtensionDirection::InOut => 2,
            }])?;
            let mut cursor = 0;
            for pointer in self.pointer_fields(index) {
                write(&bytes[cursor..pointer.offset])?;
                write(&[0; size_of::<CK_VOID_PTR>()])?;
                cursor = pointer.offset + size_of::<CK_VOID_PTR>();
            }
            write(&bytes[cursor..])?;
        }
        for pointer in &self.pointers {
            word(pointer.block, write)?;
            word(pointer.offset, write)?;
            match pointer.target {
                ExtensionPointerTarget::Null => {
                    write(&[0])?;
                    word(0, write)?;
                    word(0, write)?;
                }
                ExtensionPointerTarget::Block { block, offset } => {
                    write(&[1])?;
                    word(block, write)?;
                    word(offset, write)?;
                }
            }
        }
        for output in &self.outputs {
            word(output.region.block, write)?;
            word(output.region.offset, write)?;
            word(output.region.capacity, write)?;
            match output.region.length {
                ExtensionOutputLength::Fixed => {
                    write(&[0])?;
                    word(0, write)?;
                    word(0, write)?;
                }
                ExtensionOutputLength::NativeUnsigned { block, offset } => {
                    write(&[1])?;
                    word(block, write)?;
                    word(offset, write)?;
                }
            }
        }
        Ok(())
    }
}

#[derive(Clone, Copy)]
struct Reader<'a> {
    bytes: &'a [u8],
    position: usize,
}
impl<'a> Reader<'a> {
    fn take(&mut self, length: usize) -> Result<&'a [u8]> {
        let end = self.position.checked_add(length).ok_or_else(invalid)?;
        let bytes = self.bytes.get(self.position..end).ok_or_else(invalid)?;
        self.position = end;
        Ok(bytes)
    }
    fn byte(&mut self) -> Result<u8> {
        Ok(self.take(1)?[0])
    }
    fn word(&mut self) -> Result<usize> {
        usize::try_from(u64::from_le_bytes(
            self.take(8)?.try_into().map_err(|_| invalid())?,
        ))
        .map_err(|_| invalid())
    }
    fn block(&mut self) -> Result<(BlockLayout, &'a [u8])> {
        let length = self.word()?;
        let alignment = self.word()?;
        let direction = match self.byte()? {
            0 => ExtensionDirection::Input,
            1 => ExtensionDirection::Output,
            2 => ExtensionDirection::InOut,
            _ => return Err(invalid()),
        };
        Ok((
            BlockLayout {
                length,
                alignment,
                direction,
            },
            self.take(length)?,
        ))
    }
}

/// Structurally decoded immutable graph bytes, without an authority claim.
/// Semantic validation belongs to SnapshotIndex at import and GraphStorage at
/// materialization. Inspection never allocates, admits resources or dispatches C.
#[derive(Clone, Copy)]
pub(crate) struct SnapshotRecipe<'a> {
    bytes: &'a [u8],
    root: Option<usize>,
    blocks: usize,
    pointers: usize,
    outputs: usize,
    pointer_offset: usize,
    output_offset: usize,
}
impl<'a> SnapshotRecipe<'a> {
    /// Structural pass only. All count-controlled reads consume bounded input;
    /// semantic pointer/output checks require the caller's prepaid index. This
    /// representation is not a validated archive or authority for native use.
    pub(crate) fn decode(bytes: &'a [u8]) -> Result<Self> {
        let mut reader = Reader { bytes, position: 0 };
        if reader.take(4)? != MAGIC
            || reader.take(4)?
                != [
                    size_of::<CK_VOID_PTR>() as u8,
                    size_of::<CK_ULONG>() as u8,
                    u8::from(cfg!(target_endian = "little")),
                    0,
                ]
        {
            return Err(Error::Rejected(
                crate::RejectionReason::MechanismExtensions(
                    crate::MechanismExtensionsRejection::GraphSnapshotAbiOrVersion,
                ),
            ));
        }
        let root = reader.word()?.checked_sub(1);
        let blocks = reader.word()?;
        let pointers = reader.word()?;
        let outputs = reader.word()?;
        // Every loop consumes at least this much input, independently of counts
        // asserted by an external record. No count-controlled allocation occurs.
        if blocks > bytes.len() / 17 {
            return Err(invalid());
        }
        for _ in 0..blocks {
            reader.block()?;
        }
        let pointer_offset = reader.position;
        reader.take(pointers.checked_mul(POINTER_BYTES).ok_or_else(invalid)?)?;
        let output_offset = reader.position;
        reader.take(outputs.checked_mul(OUTPUT_BYTES).ok_or_else(invalid)?)?;
        if reader.position != bytes.len() {
            return Err(invalid());
        }
        let recipe = Self {
            bytes,
            root,
            blocks,
            pointers,
            outputs,
            pointer_offset,
            output_offset,
        };
        OwnedGraph::validate_structure(&recipe)?;
        Ok(recipe)
    }
    pub(crate) fn index_counts(&self) -> (usize, usize) {
        (self.blocks, self.pointers)
    }
    fn block_at(&self, index: usize) -> Result<(BlockLayout, &'a [u8])> {
        if index >= self.blocks {
            return Err(invalid());
        }
        let mut reader = Reader {
            bytes: self.bytes,
            position: 40,
        };
        for _ in 0..index {
            reader.block()?;
        }
        reader.block()
    }
}
impl Recipe for SnapshotRecipe<'_> {
    fn root(&self) -> Option<usize> {
        self.root
    }
    fn block_count(&self) -> usize {
        self.blocks
    }
    fn pointer_count(&self) -> usize {
        self.pointers
    }
    fn output_count(&self) -> usize {
        self.outputs
    }
    fn block(&self, index: usize) -> Result<BlockLayout> {
        self.block_at(index).map(|(layout, _)| layout)
    }
    fn visit_blocks(&self, visit: &mut dyn FnMut(usize, BlockLayout) -> Result<()>) -> Result<()> {
        let mut reader = Reader {
            bytes: self.bytes,
            position: 40,
        };
        for index in 0..self.blocks {
            let (layout, _) = reader.block()?;
            visit(index, layout)?;
        }
        Ok(())
    }
    fn copy(&self, block: usize, offset: usize, target: &mut [u8]) -> Result<()> {
        super::recipe::copy_range(self.block_at(block)?.1, offset, target)
    }
    fn visit_copies(
        &self,
        visit: &mut dyn FnMut(
            usize,
            BlockLayout,
            &dyn Fn(usize, &mut [u8]) -> Result<()>,
        ) -> Result<()>,
    ) -> Result<()> {
        let mut reader = Reader {
            bytes: self.bytes,
            position: 40,
        };
        for index in 0..self.blocks {
            let (layout, bytes) = reader.block()?;
            visit(index, layout, &|offset, target| {
                super::recipe::copy_range(bytes, offset, target)
            })?;
        }
        Ok(())
    }
    fn pointer(&self, index: usize) -> Result<ExtensionPointer> {
        if index >= self.pointers {
            return Err(invalid());
        }
        let mut reader = Reader {
            bytes: self.bytes,
            position: self.pointer_offset + index * POINTER_BYTES,
        };
        let block = reader.word()?;
        let offset = reader.word()?;
        let kind = reader.byte()?;
        let target_block = reader.word()?;
        let target_offset = reader.word()?;
        let target = match (kind, target_block, target_offset) {
            (0, 0, 0) => ExtensionPointerTarget::Null,
            (1, block, offset) => ExtensionPointerTarget::Block { block, offset },
            _ => return Err(invalid()),
        };
        Ok(ExtensionPointer {
            block,
            offset,
            target,
        })
    }
    fn output(&self, index: usize) -> Result<ExtensionOutputRegion> {
        if index >= self.outputs {
            return Err(invalid());
        }
        let mut reader = Reader {
            bytes: self.bytes,
            position: self.output_offset + index * OUTPUT_BYTES,
        };
        let block = reader.word()?;
        let offset = reader.word()?;
        let capacity = reader.word()?;
        let kind = reader.byte()?;
        let length_block = reader.word()?;
        let length_offset = reader.word()?;
        let length = match (kind, length_block, length_offset) {
            (0, 0, 0) => ExtensionOutputLength::Fixed,
            (1, block, offset) => ExtensionOutputLength::NativeUnsigned { block, offset },
            _ => return Err(invalid()),
        };
        Ok(ExtensionOutputRegion {
            block,
            offset,
            capacity,
            length,
        })
    }
}
