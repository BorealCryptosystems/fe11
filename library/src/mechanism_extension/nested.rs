// SPDX-License-Identifier: Apache-2.0
//! Borrowed nested graphs: headers and rebasing are materialized only once.
use super::graph::recipe::{copy_range, BlockLayout, Input, Recipe, Request};
use super::*;
use crate::{bounds, Session};
use fe11_sys::*;
use std::mem::{align_of, offset_of, size_of};

pub(crate) struct Child<'a> {
    pub offset: usize,
    pub request: Option<&'a ExtensionRequest<'a>>,
}
fn invalid() -> Error {
    Error::Rejected(crate::RejectionReason::MechanismExtensions(
        crate::MechanismExtensionsRejection::NestedMechanismGraphAccounting,
    ))
}
fn add(a: usize, b: usize) -> Result<usize> {
    a.checked_add(b).ok_or_else(invalid)
}
fn target(value: ExtensionPointerTarget, base: usize) -> Result<ExtensionPointerTarget> {
    Ok(match value {
        ExtensionPointerTarget::Null => ExtensionPointerTarget::Null,
        ExtensionPointerTarget::Block { block, offset } => ExtensionPointerTarget::Block {
            block: add(base, block)?,
            offset,
        },
    })
}
struct Nested<'a, 'c> {
    parent: ExtensionParameters<'a>,
    children: &'c [Child<'a>],
    root: usize,
    blocks: usize,
    pointers: usize,
    outputs: usize,
}
enum Location<'a> {
    Borrowed(ExtensionParameters<'a>, usize),
    Header(&'a ExtensionRequest<'a>),
}
impl<'a> Nested<'a, '_> {
    fn locate(&self, index: usize) -> Result<Location<'a>> {
        if index < self.parent.blocks.len() {
            return Ok(Location::Borrowed(self.parent, index));
        }
        let mut next = index - self.parent.blocks.len();
        for child in self.children.iter().filter_map(|child| child.request) {
            if next == 0 {
                return Ok(Location::Header(child));
            }
            next -= 1;
            if next < child.parameters.blocks.len() {
                return Ok(Location::Borrowed(child.parameters, next));
            }
            next -= child.parameters.blocks.len();
        }
        Err(invalid())
    }
}
impl Recipe for Nested<'_, '_> {
    fn root(&self) -> Option<usize> {
        Some(self.root)
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
        match self.locate(index)? {
            Location::Borrowed(parameters, index) => parameters.block(index),
            Location::Header(_) => Ok(BlockLayout {
                length: size_of::<CK_MECHANISM>(),
                alignment: align_of::<CK_MECHANISM>(),
                direction: ExtensionDirection::Input,
            }),
        }
    }
    fn copy(&self, block: usize, offset: usize, destination: &mut [u8]) -> Result<()> {
        match self.locate(block)? {
            Location::Borrowed(parameters, index) => parameters.copy(index, offset, destination),
            Location::Header(child) => {
                let length = child
                    .parameters
                    .root
                    .map(|index| child.parameters.block(index).map(|block| block.length))
                    .transpose()?
                    .unwrap_or(0);
                let length = bounds::ck_length(length)?;
                let mut header = [0; size_of::<CK_MECHANISM>()];
                header[offset_of!(CK_MECHANISM, mechanism)..][..size_of::<CK_MECHANISM_TYPE>()]
                    .copy_from_slice(&child.contract.mechanism.to_ne_bytes());
                header[offset_of!(CK_MECHANISM, ulParameterLen)..][..size_of::<CK_ULONG>()]
                    .copy_from_slice(&length.to_ne_bytes());
                copy_range(&header, offset, destination)
            }
        }
    }
    fn pointer(&self, index: usize) -> Result<ExtensionPointer> {
        if index < self.parent.pointers.len() {
            return self.parent.pointer(index);
        }
        let mut next = index - self.parent.pointers.len();
        let mut header = self.parent.blocks.len();
        for slot in self.children {
            if next == 0 {
                return Ok(ExtensionPointer {
                    block: self.root,
                    offset: slot.offset,
                    target: if slot.request.is_some() {
                        ExtensionPointerTarget::Block {
                            block: header,
                            offset: 0,
                        }
                    } else {
                        ExtensionPointerTarget::Null
                    },
                });
            }
            next -= 1;
            let Some(child) = slot.request else { continue };
            let base = add(header, 1)?;
            if next == 0 {
                return Ok(ExtensionPointer {
                    block: header,
                    offset: offset_of!(CK_MECHANISM, pParameter),
                    target: match child.parameters.root {
                        Some(block) => ExtensionPointerTarget::Block {
                            block: add(base, block)?,
                            offset: 0,
                        },
                        None => ExtensionPointerTarget::Null,
                    },
                });
            }
            next -= 1;
            if next < child.parameters.pointers.len() {
                let pointer = child.parameters.pointer(next)?;
                return Ok(ExtensionPointer {
                    block: add(base, pointer.block)?,
                    offset: pointer.offset,
                    target: target(pointer.target, base)?,
                });
            }
            next -= child.parameters.pointers.len();
            header = add(base, child.parameters.blocks.len())?;
        }
        Err(invalid())
    }
    fn output(&self, index: usize) -> Result<ExtensionOutputRegion> {
        if index < self.parent.outputs.len() {
            return self.parent.output(index);
        }
        let mut next = index - self.parent.outputs.len();
        let mut header = self.parent.blocks.len();
        for child in self.children.iter().filter_map(|child| child.request) {
            let base = add(header, 1)?;
            if next < child.parameters.outputs.len() {
                let output = child.parameters.output(next)?;
                return Ok(ExtensionOutputRegion {
                    block: add(base, output.block)?,
                    offset: output.offset,
                    capacity: output.capacity,
                    length: match output.length {
                        ExtensionOutputLength::Fixed => ExtensionOutputLength::Fixed,
                        ExtensionOutputLength::NativeUnsigned { block, offset } => {
                            ExtensionOutputLength::NativeUnsigned {
                                block: add(base, block)?,
                                offset,
                            }
                        }
                    },
                });
            }
            next -= child.parameters.outputs.len();
            header = add(base, child.parameters.blocks.len())?;
        }
        Err(invalid())
    }
}
pub(crate) fn compose<T>(
    _session: &Session,
    contract: &MechanismExtension,
    parent: ExtensionParameters<'_>,
    children: &[Child<'_>],
    consume: impl FnOnce(Request<'_>) -> Result<T>,
) -> Result<T> {
    let root = parent.root.ok_or(Error::Rejected(
        crate::RejectionReason::MechanismExtensions(
            crate::MechanismExtensionsRejection::NestedMechanismParentHasNoRoot,
        ),
    ))?;
    let mut blocks = parent.blocks.len();
    let mut pointers = add(parent.pointers.len(), children.len())?;
    let mut outputs = parent.outputs.len();
    for child in children.iter().filter_map(|child| child.request) {
        blocks = add(blocks, add(1, child.parameters.blocks.len())?)?;
        pointers = add(pointers, add(1, child.parameters.pointers.len())?)?;
        outputs = add(outputs, child.parameters.outputs.len())?;
    }
    let recipe = Nested {
        parent,
        children,
        root,
        blocks,
        pointers,
        outputs,
    };
    consume(Request {
        contract,
        parameters: Input::Generated(&recipe),
    })
}
