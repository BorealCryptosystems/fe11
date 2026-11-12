// SPDX-License-Identifier: Apache-2.0
//! Reusable, externally credited validation scratch for encoded graph inputs.
use super::{invalid, Reader, SnapshotRecipe};
use crate::mechanism_extension::graph::{
    recipe::{BlockLayout, Recipe},
    OwnedGraph,
};
use crate::{Error, ExtensionOutputRegion, ExtensionPointer, Result};
use std::mem::size_of;

/// The archive owner reserves these capacities before constructing this value.
/// No growth is allowed during validation; one scratch serves successive graphs.
pub(crate) struct SnapshotIndex {
    // Block offsets precede pointer indices for the current graph. Reusing one
    // allocation avoids adding maxima belonging to two different graphs.
    entries: Vec<usize>,
}
impl SnapshotIndex {
    pub(crate) fn required_bytes(entries: usize) -> Result<usize> {
        entries.checked_mul(size_of::<usize>()).ok_or_else(invalid)
    }
    pub(crate) fn allocate(entries: usize) -> Result<Self> {
        fn offsets(count: usize) -> Result<Vec<usize>> {
            let mut values = Vec::new();
            values.try_reserve_exact(count).map_err(|_| {
                Error::Rejected(crate::RejectionReason::MechanismExtensions(
                    crate::MechanismExtensionsRejection::GraphValidationIndexAllocation,
                ))
            })?;
            Ok(values)
        }
        Ok(Self {
            entries: offsets(entries)?,
        })
    }
    pub(crate) fn allocated_bytes(&self) -> Result<usize> {
        Self::required_bytes(self.entries.capacity())
    }
    pub(crate) fn validate(&mut self, bytes: &[u8]) -> Result<()> {
        let recipe = SnapshotRecipe::decode(bytes)?;
        if recipe
            .blocks
            .checked_add(recipe.pointers)
            .ok_or_else(invalid)?
            > self.entries.capacity()
        {
            return Err(Error::Rejected(
                crate::RejectionReason::MechanismExtensions(
                    crate::MechanismExtensionsRejection::GraphValidationIndexCapacity,
                ),
            ));
        }
        self.entries.clear();
        let mut reader = Reader {
            bytes,
            position: 40,
        };
        for _ in 0..recipe.blocks {
            self.entries.push(reader.position);
            reader.block()?;
        }
        for index in 0..recipe.pointers {
            // Validate fixed records before the infallible sort comparator.
            // The immutable bytes cannot change while this recipe is borrowed.
            recipe.pointer(index)?;
            self.entries.push(index);
        }
        let (blocks, pointers) = self.entries.split_at_mut(recipe.blocks);
        pointers.sort_unstable_by_key(|index| {
            let pointer = recipe
                .pointer(*index)
                .expect("checked immutable pointer record");
            (pointer.block, pointer.offset)
        });
        let indexed = IndexedSnapshot { recipe, blocks };
        OwnedGraph::validate_indexed(&indexed, pointers)
    }
}

/// Indexed structural view, scoped to one complete semantic validation. It
/// cannot escape the scratch borrow, so later reuse cannot invalidate a proof.
struct IndexedSnapshot<'a, 'b> {
    recipe: SnapshotRecipe<'a>,
    blocks: &'b [usize],
}
impl<'a> IndexedSnapshot<'a, '_> {
    fn block_bytes(&self, index: usize) -> Result<(BlockLayout, &'a [u8])> {
        let position = *self.blocks.get(index).ok_or_else(invalid)?;
        Reader {
            bytes: self.recipe.bytes,
            position,
        }
        .block()
    }
}
impl Recipe for IndexedSnapshot<'_, '_> {
    fn root(&self) -> Option<usize> {
        self.recipe.root()
    }
    fn block_count(&self) -> usize {
        self.recipe.block_count()
    }
    fn pointer_count(&self) -> usize {
        self.recipe.pointer_count()
    }
    fn output_count(&self) -> usize {
        self.recipe.output_count()
    }
    fn block(&self, index: usize) -> Result<BlockLayout> {
        self.block_bytes(index).map(|(layout, _)| layout)
    }
    fn pointer(&self, index: usize) -> Result<ExtensionPointer> {
        self.recipe.pointer(index)
    }
    fn output(&self, index: usize) -> Result<ExtensionOutputRegion> {
        self.recipe.output(index)
    }
    fn copy(&self, block: usize, offset: usize, target: &mut [u8]) -> Result<()> {
        crate::mechanism_extension::graph::recipe::copy_range(
            self.block_bytes(block)?.1,
            offset,
            target,
        )
    }
}
