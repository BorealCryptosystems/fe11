// SPDX-License-Identifier: Apache-2.0
//! Measure borrowed plans iteratively, then admit the complete owned graph once.
use super::super::storage::{erase_descriptors, reserve_prepaid_entries};
use super::*;
use crate::symmetric::memory::Budget;
use std::{mem::size_of, sync::Arc};

pub(super) enum Storage {
    Query,
    Buffer(AttributeBytes),
    Template { start: usize, count: usize },
}
pub(super) struct Node {
    pub expected: Option<AttributeType>,
    pub storage: Storage,
    // Independent of storage: only a returned parent's bounded prefix is visible.
    pub visible: bool,
}
pub(super) struct Descriptors {
    pub values: Vec<CK_ATTRIBUTE>,
    _credit: Credit,
}
impl Drop for Descriptors {
    fn drop(&mut self) {
        // A changed parent type may have caused private flat bytes to overwrite
        // this array. Erase the entire allocation, including padding, without
        // reading it: struct padding need not have remained initialized.
        erase_descriptors(&mut self.values);
    }
}
pub(super) struct ReadCall {
    pub descriptors: Descriptors,
    pub nodes: Vec<Node>,
    pub tree: TemplateAttributeTree,
    _nodes_credit: Credit,
    _owner_credit: Credit,
}
// SAFETY: descriptors refer only to buffers/arrays in this stable owner. No
// vector is resized after wiring; NativeFrame retains it during native use.
unsafe impl Send for ReadCall {}

struct Measurement {
    nodes: usize,
    groups: usize,
    values: usize,
    allocated_values: usize,
}
struct Walk<'a> {
    frames: Vec<std::slice::Iter<'a, TemplateAttributeSlot<'a>>>,
    credit: Credit,
}
impl<'a> Walk<'a> {
    fn push(&mut self, slots: &'a [TemplateAttributeSlot<'a>]) -> Result<()> {
        if self.frames.len() == self.frames.capacity() {
            let before = self.frames.capacity();
            let width = size_of::<std::slice::Iter<'a, TemplateAttributeSlot<'a>>>();
            // Scratch traversal must not wait while retaining another slice of
            // its own credit. It is freed before admitting the final graph.
            self.credit.cover_allocated(width)?;
            self.frames.try_reserve_exact(1).map_err(|_| {
                Error::Rejected(crate::RejectionReason::AttributeValues(
                    crate::AttributeValuesRejection::TemplateTraversalAllocation,
                ))
            })?;
            self.credit.cover_allocated(
                bytes::<std::slice::Iter<'a, TemplateAttributeSlot<'a>>>(
                    self.frames.capacity() - before - 1,
                )?,
            )?;
        }
        self.frames.push(slots.iter());
        Ok(())
    }
}
fn bytes<T>(count: usize) -> Result<usize> {
    count.checked_mul(size_of::<T>()).ok_or(Error::Rejected(
        crate::RejectionReason::AttributeValues(
            crate::AttributeValuesRejection::TemplateMetadataAccountingOverflow,
        ),
    ))
}
fn add(total: &mut usize, value: usize) -> Result<()> {
    *total = total.checked_add(value).ok_or(Error::Rejected(
        crate::RejectionReason::AttributeValues(
            crate::AttributeValuesRejection::TemplateAllocationAccountingOverflow,
        ),
    ))?;
    Ok(())
}
fn template_size(count: usize) -> Result<usize> {
    let size = bytes::<CK_ATTRIBUTE>(count)?;
    bounds::ck_length(size)?;
    Ok(size)
}
fn measure(
    budget: &Arc<Budget>,
    plan: TemplateAttributeReadPlan<'_>,
    limits: AttributeTemplateLimits,
) -> Result<Measurement> {
    if limits.maximum_attributes == 0 {
        return Err(Error::Rejected(crate::RejectionReason::AttributeValues(
            crate::AttributeValuesRejection::TemplateRootDescriptorLimit,
        )));
    }
    let mut measured = Measurement {
        nodes: 1,
        groups: 0,
        values: 0,
        allocated_values: 0,
    };
    let mut walk = Walk {
        frames: Vec::new(),
        credit: budget.reserve(0)?,
    };
    if let TemplateAttributeReadPlan::Slots(slots) = plan {
        template_size(slots.len())?;
        if !slots.is_empty() {
            measured.groups = 1;
            walk.push(slots)?;
        }
    }
    while let Some(frame) = walk.frames.last_mut() {
        let Some(slot) = frame.next() else {
            walk.frames.pop();
            continue;
        };
        if walk.frames.len() > limits.maximum_depth {
            return Err(Error::Rejected(crate::RejectionReason::AttributeValues(
                crate::AttributeValuesRejection::TemplateReadDepthLimit,
            )));
        }
        add(&mut measured.nodes, 1)?;
        if measured.nodes > limits.maximum_attributes {
            return Err(Error::Rejected(crate::RejectionReason::AttributeValues(
                crate::AttributeValuesRejection::TemplateReadDescriptorLimit,
            )));
        }
        match slot {
            TemplateAttributeSlot::Discover => {}
            TemplateAttributeSlot::Value {
                attribute,
                capacity,
            } => {
                if attribute.layout() == AttributeLayout::Template {
                    return Err(Error::Rejected(crate::RejectionReason::AttributeValues(
                        crate::AttributeValuesRejection::TemplateValueNeedsChildDescriptors,
                    )));
                }
                add(&mut measured.values, *capacity)?;
                if measured.values > limits.maximum_value_bytes {
                    return Err(Error::Rejected(crate::RejectionReason::AttributeValues(
                        crate::AttributeValuesRejection::TemplateReadValueLimit,
                    )));
                }
                add(
                    &mut measured.allocated_values,
                    AttributeBytes::allocation_bytes(*capacity)?,
                )?;
            }
            TemplateAttributeSlot::Template { attribute, slots } => {
                if attribute.layout() != AttributeLayout::Template {
                    return Err(Error::Rejected(crate::RejectionReason::AttributeValues(
                        crate::AttributeValuesRejection::FlatAttributeCannotOwnChildDescriptors,
                    )));
                }
                template_size(slots.len())?;
                if !slots.is_empty() {
                    add(&mut measured.groups, 1)?;
                    walk.push(slots)?;
                }
            }
        }
    }
    Ok(measured)
}
struct Group<'a> {
    slots: &'a [TemplateAttributeSlot<'a>],
    start: usize,
}

impl ReadCall {
    pub(super) fn prepare(
        budget: &Arc<Budget>,
        attribute: impl Into<AttributeType>,
        plan: TemplateAttributeReadPlan<'_>,
        limits: AttributeTemplateLimits,
        overhead: usize,
        mut reserve: impl FnMut(usize) -> Result<Credit>,
    ) -> Result<(Self, Credit)> {
        let attribute = attribute.into();
        if attribute.layout() != AttributeLayout::Template {
            return Err(Error::Rejected(crate::RejectionReason::AttributeValues(
                crate::AttributeValuesRejection::RootAttributeIsNotATemplate,
            )));
        }
        let measured = measure(budget, plan, limits)?;
        let frame_bytes = crate::native::frame::SessionFrame::<'_, Self>::allocation_bytes();
        let mut peak = size_of::<Self>();
        add(&mut peak, frame_bytes)?;
        add(&mut peak, bytes::<CK_ATTRIBUTE>(measured.nodes)?)?;
        add(&mut peak, bytes::<Node>(measured.nodes)?)?;
        add(&mut peak, bytes::<Record>(measured.nodes)?)?;
        add(&mut peak, bytes::<Group<'_>>(measured.groups)?)?;
        add(&mut peak, measured.allocated_values)?;
        add(&mut peak, overhead)?;
        // No later reserve may wait while holding part of this request's graph.
        let mut prepaid = reserve(peak)?;
        let owner_credit =
            prepaid.split(size_of::<Self>() - size_of::<TemplateAttributeTree>() + frame_bytes)?;
        let mut tree_credit =
            prepaid.split(size_of::<TemplateAttributeTree>() + bytes::<Record>(measured.nodes)?)?;
        let mut records = Vec::new();
        records.try_reserve_exact(measured.nodes).map_err(|_| {
            Error::Rejected(crate::RejectionReason::AttributeValues(
                crate::AttributeValuesRejection::TemplateResultAllocation,
            ))
        })?;
        tree_credit.cover_allocated(bytes::<Record>(records.capacity() - measured.nodes)?)?;
        records.resize_with(measured.nodes, || Record::Hidden);
        let tree = TemplateAttributeTree {
            call: AttributeBatchCall {
                code: 0,
                attribute_count: 1,
            },
            records,
            _credit: tree_credit,
        };
        let mut descriptors =
            reserve_prepaid_entries::<CK_ATTRIBUTE>(&mut prepaid, measured.nodes)?;
        // SAFETY: CK_ATTRIBUTE consists of integer and raw-pointer fields, for
        // which all-zero is valid on supported targets. Initialize all capacity,
        // including padding, before exposing the allocation to the native call.
        unsafe {
            descriptors
                .0
                .as_mut_ptr()
                .write_bytes(0, descriptors.0.capacity());
            descriptors.0.set_len(descriptors.0.capacity());
        }
        let descriptors = Descriptors {
            values: descriptors.0,
            _credit: descriptors.1,
        };
        let mut nodes = reserve_prepaid_entries::<Node>(&mut prepaid, measured.nodes)?;
        nodes.0.resize_with(measured.nodes, || Node {
            expected: None,
            storage: Storage::Query,
            visible: false,
        });
        let mut groups = reserve_prepaid_entries::<Group<'_>>(&mut prepaid, measured.groups)?;
        let mut cursor = 1;
        let root_storage = match plan {
            TemplateAttributeReadPlan::LengthOnly => Storage::Query,
            TemplateAttributeReadPlan::Slots(slots) => {
                let start = cursor;
                cursor += slots.len();
                if !slots.is_empty() {
                    groups.0.push(Group { slots, start });
                }
                Storage::Template {
                    start,
                    count: slots.len(),
                }
            }
        };
        nodes.0[0] = Node {
            expected: Some(attribute),
            storage: root_storage,
            visible: true,
        };
        while let Some(group) = groups.0.pop() {
            for (offset, slot) in group.slots.iter().enumerate() {
                let (expected, storage) = match slot {
                    TemplateAttributeSlot::Discover => (None, Storage::Query),
                    TemplateAttributeSlot::Value {
                        attribute,
                        capacity,
                    } => (
                        Some(*attribute),
                        Storage::Buffer(AttributeBytes::new_prepaid(*capacity, &mut prepaid)?),
                    ),
                    TemplateAttributeSlot::Template { attribute, slots } => {
                        let start = cursor;
                        cursor = cursor
                            .checked_add(slots.len())
                            .filter(|n| *n <= measured.nodes)
                            .ok_or(Error::Rejected(crate::RejectionReason::AttributeValues(
                                crate::AttributeValuesRejection::TemplateMeasuredChildRange,
                            )))?;
                        if !slots.is_empty() {
                            groups.0.push(Group { slots, start });
                        }
                        (
                            Some(*attribute),
                            Storage::Template {
                                start,
                                count: slots.len(),
                            },
                        )
                    }
                };
                nodes.0[group.start + offset] = Node {
                    expected,
                    storage,
                    visible: false,
                };
            }
        }
        if cursor != measured.nodes {
            return Err(Error::Rejected(crate::RejectionReason::AttributeValues(
                crate::AttributeValuesRejection::TemplateMeasuredCountChanged,
            )));
        }
        drop(groups);
        let mut call = Self {
            descriptors,
            nodes: nodes.0,
            tree,
            _nodes_credit: nodes.1,
            _owner_credit: owner_credit,
        };
        let array = call.descriptors.values.as_mut_ptr();
        for (index, node) in call.nodes.iter_mut().enumerate() {
            let (pointer, length) = match &mut node.storage {
                Storage::Query => (std::ptr::null_mut(), 0),
                Storage::Buffer(bytes) => (bytes.pointer(), bytes.capacity()),
                Storage::Template { start, count } => {
                    // SAFETY: the measured child range is within this stable
                    // allocation. An empty range may point one past its end.
                    (unsafe { array.add(*start) }.cast(), template_size(*count)?)
                }
            };
            // Child type is output-only. Expected types never select by name.
            let kind = if index == 0 { attribute.native() } else { 0 };
            let length = bounds::ck_length(length)?;
            // SAFETY: every measured descriptor is initialized and index is in
            // bounds. Write through the original allocation pointer: creating
            // a fresh mutable slice here could invalidate pointers already
            // installed in parent descriptors. Unaligned stores also support
            // the packed Windows CK_ATTRIBUTE ABI. No padding is read/copied.
            unsafe {
                let descriptor = array.add(index);
                std::ptr::addr_of_mut!((*descriptor).r#type).write_unaligned(kind);
                std::ptr::addr_of_mut!((*descriptor).pValue).write_unaligned(pointer);
                std::ptr::addr_of_mut!((*descriptor).ulValueLen).write_unaligned(length);
            }
        }
        Ok((call, prepaid))
    }
}


