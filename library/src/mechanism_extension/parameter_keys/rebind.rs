// SPDX-License-Identifier: Apache-2.0
//! Explicit destination handles for private copies of retained parameter graphs.
use super::{invalid, ParameterKeys, RetainedParameterKeys};
use crate::mechanism_extension::{
    graph::{recipe::Recipe, snapshot::SnapshotRecipe},
    OwnedGraph,
};
use crate::{Error, NativeObjectRef, Result};

impl RetainedParameterKeys {
    /// Describe a private copy with explicitly selected destination keys. The
    /// caller must hold the source at an established native return. Destination
    /// references follow the same first-occurrence order as `references()`;
    /// repeated fields of one source object use one destination reference.
    ///
    /// This only relocates declared scalar fields. It neither acquires object
    /// roles nor proves destination session access or native-state equivalence.
    /// Those checks belong to the enclosing restoration transaction, before C.
    pub(crate) fn rebind<'a>(
        &self,
        graph: &'a OwnedGraph,
        destinations: &[&'a NativeObjectRef],
    ) -> Result<ReboundRecipe<'a>> {
        if !graph.unchanged() || !self.unchanged(graph) {
            return Err(Error::Rejected(
                crate::RejectionReason::MechanismExtensions(
                    crate::MechanismExtensionsRejection::ChangedParameterGraphCannotBeRebound,
                ),
            ));
        }
        self.locations()?.rebind(graph, destinations)
    }
}

/// The base recipe has no reference back to its containing reconstruction
/// plan. GraphStorage can own the overlay while that plan is moved or consumed.
#[derive(Clone, Copy)]
enum Source<'a> {
    Live(&'a OwnedGraph),
    Snapshot(SnapshotRecipe<'a>),
}
impl Source<'_> {
    fn recipe(&self) -> &dyn Recipe {
        match self {
            Self::Live(graph) => *graph,
            Self::Snapshot(graph) => graph,
        }
    }
}

/// Borrowed preparation recipe: only encoder-declared handles change. Native
/// pointers are cleared by the live graph or validated snapshot recipe and rebuilt
/// by GraphStorage in the new allocation. No live source bytes are modified.
#[derive(Clone, Copy)]
pub(crate) struct ReboundRecipe<'a> {
    graph: Source<'a>,
    keys: ParameterKeys<'a>,
}

impl<'a> ReboundRecipe<'a> {
    pub(super) fn live(graph: &'a OwnedGraph, keys: ParameterKeys<'a>) -> Result<Self> {
        Self::new(Source::Live(graph), keys)
    }
    pub(super) fn snapshot(graph: SnapshotRecipe<'a>, keys: ParameterKeys<'a>) -> Result<Self> {
        Self::new(Source::Snapshot(graph), keys)
    }
    fn new(graph: Source<'a>, keys: ParameterKeys<'a>) -> Result<Self> {
        let recipe = Self { graph, keys };
        // Includes input-only layout, pointer/scalar separation and every
        // destination handle. No partially rebound graph is exposed on error.
        recipe.keys.validate(&recipe)?;
        Ok(recipe)
    }

    /// Destination references for the enclosing transaction's role admission
    /// and retained identity owner. Copying this metadata grants no authority.
    pub(crate) fn keys(&self) -> ParameterKeys<'a> {
        self.keys
    }
}

impl Recipe for ReboundRecipe<'_> {
    fn root(&self) -> Option<usize> {
        self.graph.recipe().root()
    }

    fn block_count(&self) -> usize {
        self.graph.recipe().block_count()
    }

    fn pointer_count(&self) -> usize {
        self.graph.recipe().pointer_count()
    }

    fn output_count(&self) -> usize {
        self.graph.recipe().output_count()
    }

    fn block(
        &self,
        index: usize,
    ) -> Result<crate::mechanism_extension::graph::recipe::BlockLayout> {
        self.graph.recipe().block(index)
    }

    fn pointer(&self, index: usize) -> Result<crate::ExtensionPointer> {
        self.graph.recipe().pointer(index)
    }

    fn visit_blocks(
        &self,
        visit: &mut dyn FnMut(
            usize,
            crate::mechanism_extension::graph::recipe::BlockLayout,
        ) -> Result<()>,
    ) -> Result<()> {
        // Rebinding replaces only declared handle bytes. Layout order and the
        // underlying snapshot's sequential traversal remain unchanged.
        self.graph.recipe().visit_blocks(visit)
    }

    fn output(&self, index: usize) -> Result<crate::ExtensionOutputRegion> {
        self.graph.recipe().output(index)
    }

    fn copy(&self, block: usize, offset: usize, target: &mut [u8]) -> Result<()> {
        self.graph.recipe().copy(block, offset, target)?;
        self.copy_handles(block, offset, target)
    }
    fn visit_copies(
        &self,
        visit: &mut dyn FnMut(
            usize,
            crate::mechanism_extension::graph::recipe::BlockLayout,
            &dyn Fn(usize, &mut [u8]) -> Result<()>,
        ) -> Result<()>,
    ) -> Result<()> {
        self.graph
            .recipe()
            .visit_copies(&mut |index, layout, copy| {
                visit(index, layout, &|offset, target| {
                    copy(offset, target)?;
                    self.copy_handles(index, offset, target)
                })
            })
    }
}
impl ReboundRecipe<'_> {
    fn copy_handles(&self, block: usize, offset: usize, target: &mut [u8]) -> Result<()> {
        let end = offset.checked_add(target.len()).ok_or_else(invalid)?;
        for field in self.keys.fields.iter().flatten() {
            if field.block != block {
                continue;
            }
            let handle = field.reference.identity.handle.to_ne_bytes();
            let field_end = field.offset.checked_add(handle.len()).ok_or_else(invalid)?;
            let start = offset.max(field.offset);
            let stop = end.min(field_end);
            if start < stop {
                // Recipe clients may copy any subrange, including a fragment
                // of this scalar. Never assume a full CK_OBJECT_HANDLE read.
                target[start - offset..stop - offset]
                    .copy_from_slice(&handle[start - field.offset..stop - field.offset]);
            }
        }
        Ok(())
    }
}
