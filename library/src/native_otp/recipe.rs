// SPDX-License-Identifier: Apache-2.0
//! Borrowed OTP values and generated scalar descriptors; no intermediate graph.
use super::{invalid, write, NativeOtpParameter};
use crate::{
    mechanism_extension::graph::recipe::{copy_range, BlockLayout, Recipe},
    ExtensionDirection, ExtensionOutputRegion, ExtensionPointer, ExtensionPointerTarget, Result,
};
use fe11_sys::{CK_OTP_PARAM, CK_OTP_PARAMS, CK_ULONG};
use std::mem::{align_of, offset_of, size_of};

pub(super) struct Parameters<'a, 'p> {
    parameters: &'a [NativeOtpParameter<'p>],
    descriptors: usize,
    blocks: usize,
    pointers: usize,
}
impl<'a, 'p> Parameters<'a, 'p> {
    pub(super) fn new(parameters: &'a [NativeOtpParameter<'p>]) -> Result<Self> {
        crate::bounds::ck_length(parameters.len())?;
        Ok(Self {
            parameters,
            descriptors: parameters
                .len()
                .checked_mul(size_of::<CK_OTP_PARAM>())
                .ok_or_else(invalid)?,
            blocks: parameters.len().checked_add(2).ok_or_else(invalid)?,
            pointers: parameters.len().checked_add(1).ok_or_else(invalid)?,
        })
    }
}
impl Recipe for Parameters<'_, '_> {
    fn root(&self) -> Option<usize> {
        Some(0)
    }
    fn block_count(&self) -> usize {
        self.blocks
    }
    fn pointer_count(&self) -> usize {
        self.pointers
    }
    fn output_count(&self) -> usize {
        0
    }
    fn block(&self, index: usize) -> Result<BlockLayout> {
        let (length, alignment) = match index {
            0 => (size_of::<CK_OTP_PARAMS>(), align_of::<CK_OTP_PARAMS>()),
            1 => (self.descriptors, align_of::<CK_OTP_PARAM>()),
            index => {
                let (_, bytes, _) = self.parameters.get(index - 2).ok_or_else(invalid)?.parts();
                (
                    bytes.map_or(size_of::<CK_ULONG>(), |bytes| bytes.len()),
                    align_of::<CK_ULONG>(),
                )
            }
        };
        Ok(BlockLayout {
            length,
            alignment,
            direction: ExtensionDirection::Input,
        })
    }
    fn pointer(&self, index: usize) -> Result<ExtensionPointer> {
        if index >= self.pointers {
            return Err(invalid());
        }
        if index == 0 {
            Ok(ExtensionPointer {
                block: 0,
                offset: offset_of!(CK_OTP_PARAMS, pParams),
                target: ExtensionPointerTarget::Block {
                    block: 1,
                    offset: 0,
                },
            })
        } else {
            Ok(ExtensionPointer {
                block: 1,
                offset: (index - 1) * size_of::<CK_OTP_PARAM>() + offset_of!(CK_OTP_PARAM, pValue),
                target: ExtensionPointerTarget::Block {
                    block: index + 1,
                    offset: 0,
                },
            })
        }
    }
    fn output(&self, _: usize) -> Result<ExtensionOutputRegion> {
        Err(invalid())
    }
    fn copy(&self, block: usize, offset: usize, target: &mut [u8]) -> Result<()> {
        let length = self.block(block)?.length;
        let end = offset
            .checked_add(target.len())
            .filter(|end| *end <= length)
            .ok_or_else(invalid)?;
        match block {
            0 => {
                let mut raw = [0; size_of::<CK_OTP_PARAMS>()];
                write(
                    &mut raw,
                    offset_of!(CK_OTP_PARAMS, ulCount),
                    self.parameters.len() as u64,
                )?;
                copy_range(&raw, offset, target)
            }
            1 => {
                if target.is_empty() {
                    return Ok(());
                }
                let width = size_of::<CK_OTP_PARAM>();
                for index in offset / width..=(end - 1) / width {
                    let (tag, bytes, _) = self.parameters[index].parts();
                    let mut raw = [0; size_of::<CK_OTP_PARAM>()];
                    write(&mut raw, offset_of!(CK_OTP_PARAM, r#type), tag as u64)?;
                    write(
                        &mut raw,
                        offset_of!(CK_OTP_PARAM, ulValueLen),
                        bytes.map_or(size_of::<CK_ULONG>(), |bytes| bytes.len()) as u64,
                    )?;
                    let base = index * width;
                    let first = offset.max(base);
                    let last = end.min(base + width);
                    target[first - offset..last - offset]
                        .copy_from_slice(&raw[first - base..last - base]);
                }
                Ok(())
            }
            index => {
                let (_, bytes, scalar) = self.parameters[index - 2].parts();
                if let Some(bytes) = bytes {
                    return copy_range(bytes, offset, target);
                }
                let mut raw = [0; size_of::<CK_ULONG>()];
                write(&mut raw, 0, scalar.ok_or_else(invalid)?)?;
                let result = copy_range(&raw, offset, target);
                // Numeric input is caller-owned; erase this additional scalar
                // representation after copying into the credited native graph.
                for byte in &mut raw {
                    // SAFETY: a unique reference to a live initialized byte.
                    unsafe { std::ptr::write_volatile(byte, 0) };
                }
                std::sync::atomic::compiler_fence(std::sync::atomic::Ordering::SeqCst);
                result
            }
        }
    }
}
