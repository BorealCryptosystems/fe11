// SPDX-License-Identifier: Apache-2.0
//! Private graph staging capacities, admitted with the complete enclosing candidate.
use super::{invalid, AlignedStorage, Block, Output, OwnedGraph};
use crate::{
    mechanism_extension::{ExtensionParameters, ExtensionPointer},
    symmetric::memory::{Credit, UnboundBuffer},
    Error, Result,
};
use std::mem::{size_of, take};

pub(super) struct PreparedBlock {
    bytes: AlignedStorage,
    witness: UnboundBuffer,
    direction: crate::ExtensionDirection,
}

pub(crate) struct GraphStorage<'a> {
    input: super::recipe::Input<'a>,
    prepared: Vec<PreparedBlock>,
    blocks: Vec<Block>,
    pointers: Vec<ExtensionPointer>,
    pointer_order: Vec<usize>,
    outputs: Vec<Output>,
    // Last: all still-unbound allocations must leave before this remainder.
    credit: Option<Credit>,
}

fn entries<T>(count: usize) -> Result<Vec<T>> {
    let mut values = Vec::new();
    values.try_reserve_exact(count).map_err(|_| {
        Error::Rejected(crate::RejectionReason::MechanismExtensions(
            crate::MechanismExtensionsRejection::ExtensionGraphMetadataAllocation,
        ))
    })?;
    Ok(values)
}

/// Indexed view of the private staging allocations. No native address has been
/// published, and block lookups cannot restart an encoded recipe's traversal.
struct PreparedRecipe<'a> {
    root: Option<usize>,
    blocks: &'a [PreparedBlock],
    pointers: &'a [ExtensionPointer],
    outputs: &'a [Output],
}
impl super::recipe::Recipe for PreparedRecipe<'_> {
    fn root(&self) -> Option<usize> {
        self.root
    }
    fn block_count(&self) -> usize {
        self.blocks.len()
    }
    fn pointer_count(&self) -> usize {
        self.pointers.len()
    }
    fn output_count(&self) -> usize {
        self.outputs.len()
    }
    fn block(&self, index: usize) -> Result<super::recipe::BlockLayout> {
        let block = self.blocks.get(index).ok_or_else(invalid)?;
        Ok(super::recipe::BlockLayout {
            length: block.bytes.length,
            alignment: block.bytes.layout.align(),
            direction: block.direction,
        })
    }
    fn pointer(&self, index: usize) -> Result<ExtensionPointer> {
        self.pointers.get(index).copied().ok_or_else(invalid)
    }
    fn output(&self, index: usize) -> Result<crate::ExtensionOutputRegion> {
        self.outputs
            .get(index)
            .map(|output| output.region)
            .ok_or_else(invalid)
    }
    fn copy(&self, block: usize, offset: usize, target: &mut [u8]) -> Result<()> {
        let block = self.blocks.get(block).ok_or_else(invalid)?;
        super::recipe::copy_range(block.bytes.bytes(), offset, target)
    }
}

impl<'a> GraphStorage<'a> {
    pub(crate) fn allocate(input: &ExtensionParameters<'a>) -> Result<Self> {
        Self::allocate_input(super::recipe::Input::Borrowed(*input))
    }
    pub(crate) fn allocate_input(input: super::recipe::Input<'a>) -> Result<Self> {
        let recipe = input.recipe();
        OwnedGraph::validate_structure(recipe)?;
        let mut prepared = entries(recipe.block_count())?;
        let blocks = entries(recipe.block_count())?;
        let mut pointers = entries(recipe.pointer_count())?;
        let mut pointer_order = entries(recipe.pointer_count())?;
        for index in 0..recipe.pointer_count() {
            pointers.push(recipe.pointer(index)?);
            pointer_order.push(index);
        }
        pointer_order.sort_unstable_by_key(|index| {
            let pointer = &pointers[*index];
            (pointer.block, pointer.offset)
        });
        let mut outputs = entries(recipe.output_count())?;
        for index in 0..recipe.output_count() {
            outputs.push(Output {
                region: recipe.output(index)?,
                length: None,
            });
        }
        recipe.visit_copies(&mut |index, block, copy| {
            if index != prepared.len() {
                return Err(invalid());
            }
            let mut bytes = AlignedStorage::allocate(block)?;
            copy(0, bytes.bytes_mut())?;
            prepared.push(PreparedBlock {
                bytes,
                witness: UnboundBuffer::allocate(block.length)?,
                direction: block.direction,
            });
            Ok(())
        })?;
        OwnedGraph::validate_indexed(
            &PreparedRecipe {
                root: recipe.root(),
                blocks: &prepared,
                pointers: &pointers,
                outputs: &outputs,
            },
            &pointer_order,
        )?;
        Ok(Self {
            input,
            prepared,
            blocks,
            pointers,
            pointer_order,
            outputs,
            credit: None,
        })
    }

    fn metadata_bytes(&self) -> Result<usize> {
        size_of::<OwnedGraph>()
            .checked_add(
                self.blocks
                    .capacity()
                    .checked_mul(size_of::<Block>())
                    .ok_or_else(invalid)?,
            )
            .and_then(|n| {
                n.checked_add(
                    self.pointers
                        .capacity()
                        .checked_mul(size_of::<ExtensionPointer>())?,
                )
            })
            .and_then(|n| n.checked_add(self.outputs.capacity().checked_mul(size_of::<Output>())?))
            .and_then(|n| {
                n.checked_add(
                    self.pointer_order
                        .capacity()
                        .checked_mul(size_of::<usize>())?,
                )
            })
            .ok_or_else(invalid)
    }

    pub(crate) fn allocated_bytes(&self) -> Result<usize> {
        let metadata = self
            .metadata_bytes()?
            .checked_add(
                self.prepared
                    .capacity()
                    .checked_mul(size_of::<PreparedBlock>())
                    .ok_or_else(invalid)?,
            )
            .ok_or_else(invalid)?;
        self.prepared.iter().try_fold(metadata, |bytes, block| {
            bytes
                .checked_add(block.bytes.layout.size())
                .and_then(|n| n.checked_add(block.witness.allocated()))
                .ok_or_else(invalid)
        })
    }

    pub(crate) fn bind(mut self, prepaid: &mut Credit) -> Result<OwnedGraph> {
        let actual = self.allocated_bytes()?;
        let metadata = self.metadata_bytes()?;
        self.credit = Some(prepaid.split(actual)?);
        let credit = self
            .credit
            .as_mut()
            .expect("extension graph credit attached");
        let mut result = OwnedGraph {
            blocks: take(&mut self.blocks),
            pointers: take(&mut self.pointers),
            pointer_order: take(&mut self.pointer_order),
            outputs: take(&mut self.outputs),
            root: self.input.recipe().root(),
            _credit: credit.split(metadata)?,
        };
        for prepared in self.prepared.drain(..) {
            let bytes = prepared.bytes.bind(credit)?;
            result.blocks.push(Block {
                bytes,
                witness: prepared.witness.bind(credit)?,
                direction: prepared.direction,
            });
        }
        result.relocate();
        Ok(result)
    }
}
