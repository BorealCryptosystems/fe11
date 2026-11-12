// SPDX-License-Identifier: Apache-2.0
//! Borrowed, immutable recipes; generated ABI scalars need no staging allocation.
use crate::mechanism_extension::{
    ExtensionDirection, ExtensionOutputRegion, ExtensionParameters, ExtensionPointer,
    ExtensionRequest, MechanismExtension,
};
use crate::Result;

#[derive(Clone, Copy)]
pub(crate) struct BlockLayout {
    pub length: usize,
    pub alignment: usize,
    pub direction: ExtensionDirection,
}

/// Implementations describe fixed caller input only: no native call, allocation,
/// mutation or resource admission is permitted while inspecting or copying it.
pub(crate) trait Recipe {
    fn root(&self) -> Option<usize>;
    fn block_count(&self) -> usize;
    fn pointer_count(&self) -> usize;
    fn output_count(&self) -> usize;
    fn block(&self, index: usize) -> Result<BlockLayout>;
    /// Inspect each layout once, in its original block order. Encoded recipes
    /// override this traversal so planning does not repeatedly decode prefixes.
    /// The visitor must not dispatch native work or mutate the borrowed source.
    fn visit_blocks(&self, visit: &mut dyn FnMut(usize, BlockLayout) -> Result<()>) -> Result<()> {
        for index in 0..self.block_count() {
            visit(index, self.block(index)?)?;
        }
        Ok(())
    }
    fn pointer(&self, index: usize) -> Result<ExtensionPointer>;
    fn output(&self, index: usize) -> Result<ExtensionOutputRegion>;
    fn copy(&self, block: usize, offset: usize, target: &mut [u8]) -> Result<()>;
    /// Copy a whole immutable recipe under one source-return observation.
    /// Neither the visitor nor a block copier may dispatch C or mutate the
    /// source. A copier is borrowed only for its current callback, so no proof
    /// can be kept across another native call or an owned-graph mutation.
    fn visit_copies(
        &self,
        visit: &mut dyn FnMut(
            usize,
            BlockLayout,
            &dyn Fn(usize, &mut [u8]) -> Result<()>,
        ) -> Result<()>,
    ) -> Result<()> {
        self.visit_blocks(&mut |index, layout| {
            visit(index, layout, &|offset, target| {
                self.copy(index, offset, target)
            })
        })
    }
}

/// A retained graph can describe a new private allocation without exposing its
/// addresses. Callers must hold its owner at an established native return; this
/// borrow never authorizes reading a graph still lent to a pending native call.
impl Recipe for super::OwnedGraph {
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
    fn block(&self, index: usize) -> Result<BlockLayout> {
        let block = self.blocks.get(index).ok_or_else(super::invalid)?;
        Ok(BlockLayout {
            length: block.bytes.bytes().len(),
            alignment: block.bytes.storage.layout.align(),
            direction: block.direction,
        })
    }
    fn pointer(&self, index: usize) -> Result<ExtensionPointer> {
        self.pointers.get(index).copied().ok_or_else(super::invalid)
    }
    fn output(&self, index: usize) -> Result<ExtensionOutputRegion> {
        self.outputs
            .get(index)
            .map(|output| output.region)
            .ok_or_else(super::invalid)
    }
    fn copy(&self, block: usize, offset: usize, target: &mut [u8]) -> Result<()> {
        if !self.unchanged() {
            return Err(crate::Error::Rejected(
                crate::RejectionReason::MechanismExtensions(
                    crate::MechanismExtensionsRejection::ChangedRetainedExtensionGraph,
                ),
            ));
        }
        self.copy_returned_block(block, offset, target)
    }
    fn visit_copies(
        &self,
        visit: &mut dyn FnMut(
            usize,
            BlockLayout,
            &dyn Fn(usize, &mut [u8]) -> Result<()>,
        ) -> Result<()>,
    ) -> Result<()> {
        if !self.unchanged() {
            return Err(crate::Error::Rejected(
                crate::RejectionReason::MechanismExtensions(
                    crate::MechanismExtensionsRejection::ChangedRetainedExtensionGraph,
                ),
            ));
        }
        // No mutation or native dispatch is possible through this recipe's
        // immutable borrow. Check the whole witness once for the entire copy.
        self.visit_blocks(&mut |index, layout| {
            visit(index, layout, &|offset, target| {
                self.copy_returned_block(index, offset, target)
            })
        })
    }
}

impl super::OwnedGraph {
    fn copy_returned_block(&self, block: usize, offset: usize, target: &mut [u8]) -> Result<()> {
        let bytes = self
            .blocks
            .get(block)
            .ok_or_else(super::invalid)?
            .bytes
            .bytes();
        let end = offset
            .checked_add(target.len())
            .ok_or_else(super::invalid)?;
        bytes.get(offset..end).ok_or_else(super::invalid)?;
        let pointer_width = std::mem::size_of::<fe11_sys::CK_VOID_PTR>();
        let mut cursor = offset;
        for pointer in self
            .pointer_fields(block)
            .take_while(|pointer| pointer.offset < end)
            .filter(|pointer| pointer.offset + pointer_width > offset)
        {
            let gap_end = pointer.offset.max(cursor).min(end);
            target[cursor - offset..gap_end - offset].copy_from_slice(&bytes[cursor..gap_end]);
            cursor = gap_end;
            let pointer_end = (pointer.offset + pointer_width).min(end);
            target[cursor - offset..pointer_end - offset].fill(0);
            cursor = pointer_end;
        }
        target[cursor - offset..].copy_from_slice(&bytes[cursor..end]);
        Ok(())
    }
}

pub(crate) fn copy_range(source: &[u8], offset: usize, target: &mut [u8]) -> Result<()> {
    let end = offset
        .checked_add(target.len())
        .ok_or_else(super::invalid)?;
    target.copy_from_slice(source.get(offset..end).ok_or_else(super::invalid)?);
    Ok(())
}

impl Recipe for ExtensionParameters<'_> {
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
    fn block(&self, index: usize) -> Result<BlockLayout> {
        let block = self.blocks.get(index).ok_or_else(super::invalid)?;
        Ok(BlockLayout {
            length: block.initial.len(),
            alignment: block.alignment,
            direction: block.direction,
        })
    }
    fn pointer(&self, index: usize) -> Result<ExtensionPointer> {
        self.pointers.get(index).copied().ok_or_else(super::invalid)
    }
    fn output(&self, index: usize) -> Result<ExtensionOutputRegion> {
        self.outputs.get(index).copied().ok_or_else(super::invalid)
    }
    fn copy(&self, block: usize, offset: usize, target: &mut [u8]) -> Result<()> {
        copy_range(
            self.blocks.get(block).ok_or_else(super::invalid)?.initial,
            offset,
            target,
        )
    }
}

#[derive(Clone, Copy)]
pub(crate) enum Input<'a> {
    Borrowed(ExtensionParameters<'a>),
    Generated(&'a dyn Recipe),
    Snapshot(super::snapshot::SnapshotRecipe<'a>),
    Rebound(crate::mechanism_extension::parameter_keys::ReboundRecipe<'a>),
}
impl Input<'_> {
    pub(crate) fn recipe(&self) -> &dyn Recipe {
        match self {
            Self::Borrowed(input) => input,
            Self::Generated(recipe) => *recipe,
            Self::Snapshot(recipe) => recipe,
            Self::Rebound(recipe) => recipe,
        }
    }
}

#[derive(Clone, Copy)]
pub(crate) struct Request<'a> {
    pub contract: &'a MechanismExtension,
    pub parameters: Input<'a>,
}
impl<'a> From<ExtensionRequest<'a>> for Request<'a> {
    fn from(request: ExtensionRequest<'a>) -> Self {
        Self {
            contract: request.contract,
            parameters: Input::Borrowed(request.parameters),
        }
    }
}
