// SPDX-License-Identifier: Apache-2.0
//! Typed borrowed input, copied into one stable, non-recursive ownership arena.
use super::storage::erase_descriptors;
use super::{AttributeBytes, AttributeLayout, AttributeType};
use crate::symmetric::memory::{Budget, Credit};
use crate::{bounds, Error, Result};
use crypto_bigint::subtle::{Choice, ConstantTimeEq};
use fe11_sys::*;
use std::{mem::size_of, sync::Arc};

mod preparation;
pub(crate) use preparation::InputTemplateStorage;

/// One standard or explicitly declared extension attribute and its input value.
/// Borrowed values are copied before native dispatch; no Debug exposes contents.
pub struct AttributeInput<'a> {
    /// Attribute identity with its reviewed or explicitly established ABI layout.
    pub attribute: AttributeType,
    /// Value to encode, including an explicitly nested attribute template.
    pub value: AttributeInputValue<'a>,
}

/// Representations accepted by declared attributes. A mismatched variant is an
/// encoding error; object-class, permission and policy rules remain native.
pub enum AttributeInputValue<'a> {
    /// Encode CK_TRUE or CK_FALSE, never a borrowed Rust bool pointer.
    Boolean(bool),
    /// Checked conversion to this platform's native CK_ULONG.
    Unsigned(u64),
    /// Exact bytes, including native byte strings, text or unsigned big integers.
    Bytes(&'a [u8]),
    /// Exact CK_DATE bytes; no calendar policy is imposed.
    Date([u8; 8]),
    /// CK_VERSION major and minor bytes.
    Version(u8, u8),
    /// Each element is checked and encoded as a native CK_ULONG.
    UnsignedArray(&'a [u64]),
    /// An array of attributes, including an empty array or duplicate identifiers.
    Template(&'a [AttributeInput<'a>]),
}

/// Caller-selected bounds for an entire nested input or output template. No
/// defaults are imposed. The module's physical memory budget additionally covers metadata,
/// alignment and the independently erased input witnesses.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct AttributeTemplateLimits {
    /// Largest attribute nesting depth; root attributes have depth zero.
    pub maximum_depth: usize,
    /// Total descriptor count across the root and every nested template.
    pub maximum_attributes: usize,
    /// Sum of logical non-template value bytes, before alignment and witnesses.
    pub maximum_value_bytes: usize,
}

struct Measurement {
    attributes: usize,
    values: usize,
    groups: usize,
    bytes: usize,
    allocated_values: usize,
}
type Pending<'a> = (&'a [AttributeInput<'a>], usize);
impl Measurement {
    fn peak_bytes(&self) -> Result<usize> {
        let mut peak = size_of::<InputTemplate>();
        for (count, width) in [
            (self.attributes, size_of::<CK_ATTRIBUTE>()),
            (self.attributes, size_of::<Witness>()),
            (self.values, size_of::<Leaf>()),
            (self.groups, size_of::<Pending<'_>>()),
        ] {
            peak = count
                .checked_mul(width)
                .and_then(|bytes| peak.checked_add(bytes))
                .ok_or(Error::Rejected(crate::RejectionReason::AttributeValues(
                    crate::AttributeValuesRejection::AttributeTemplateMetadataAccounting,
                )))?;
        }
        peak.checked_add(self.allocated_values)
            .ok_or(Error::Rejected(crate::RejectionReason::AttributeValues(
                crate::AttributeValuesRejection::AttributeTemplateTotalAccounting,
            )))
    }
}
struct Walk<'a> {
    frames: Vec<std::slice::Iter<'a, AttributeInput<'a>>>,
    credit: Credit,
}
impl<'a> Walk<'a> {
    fn new(budget: &Arc<Budget>) -> Result<Self> {
        Ok(Self {
            frames: Vec::new(),
            credit: budget.reserve(0)?,
        })
    }
    fn push(&mut self, attributes: &'a [AttributeInput<'a>]) -> Result<()> {
        if self.frames.len() == self.frames.capacity() {
            let before = self.frames.capacity();
            let width = size_of::<std::slice::Iter<'a, AttributeInput<'a>>>();
            // Traversal is temporary scratch, not part of the eventual admitted
            // graph. Never wait while retaining earlier traversal frames.
            self.credit.cover_allocated(width)?;
            self.frames.try_reserve_exact(1).map_err(|_| {
                Error::Rejected(crate::RejectionReason::AttributeValues(
                    crate::AttributeValuesRejection::AttributeTraversalAllocation,
                ))
            })?;
            let additional = (self.frames.capacity() - before - 1)
                .checked_mul(width)
                .ok_or(Error::Rejected(crate::RejectionReason::AttributeValues(
                    crate::AttributeValuesRejection::AttributeTraversalAllocationSize,
                )))?;
            self.credit.cover_allocated(additional)?;
        }
        self.frames.push(attributes.iter());
        Ok(())
    }
}

fn native_unsigned(value: u64) -> Result<CK_ULONG> {
    CK_ULONG::try_from(value).map_err(|_| {
        Error::Rejected(crate::RejectionReason::AttributeValues(
            crate::AttributeValuesRejection::AttributeNativeIntegerWidth,
        ))
    })
}
fn value_size(input: &AttributeInput<'_>) -> Result<Option<usize>> {
    let (layout, bytes) = match &input.value {
        AttributeInputValue::Boolean(_) => (AttributeLayout::Boolean, 1),
        AttributeInputValue::Unsigned(value) => {
            native_unsigned(*value)?;
            (AttributeLayout::Unsigned, size_of::<CK_ULONG>())
        }
        AttributeInputValue::Bytes(bytes) => (AttributeLayout::Bytes, bytes.len()),
        AttributeInputValue::Date(_) => (AttributeLayout::Date, 8),
        AttributeInputValue::Version(_, _) => (AttributeLayout::Version, 2),
        AttributeInputValue::UnsignedArray(values) => {
            for value in *values {
                native_unsigned(*value)?;
            }
            (
                AttributeLayout::UnsignedArray,
                values
                    .len()
                    .checked_mul(size_of::<CK_ULONG>())
                    .ok_or(Error::Rejected(crate::RejectionReason::AttributeValues(
                        crate::AttributeValuesRejection::AttributeIntegerArraySize,
                    )))?,
            )
        }
        AttributeInputValue::Template(attributes) => {
            if input.attribute.layout() != AttributeLayout::Template {
                return Err(Error::Rejected(crate::RejectionReason::AttributeValues(
                    crate::AttributeValuesRejection::AttributeInputRepresentation,
                )));
            }
            bounds::ck_length(
                attributes
                    .len()
                    .checked_mul(size_of::<CK_ATTRIBUTE>())
                    .ok_or(Error::Rejected(crate::RejectionReason::AttributeValues(
                        crate::AttributeValuesRejection::NestedAttributeDescriptorBytes,
                    )))?,
            )?;
            return Ok(None);
        }
    };
    if input.attribute.layout() != layout {
        return Err(Error::Rejected(crate::RejectionReason::AttributeValues(
            crate::AttributeValuesRejection::AttributeInputRepresentation,
        )));
    }
    bounds::ck_length(bytes)?;
    Ok(Some(bytes))
}
fn measure<'a>(
    input: &'a [AttributeInput<'a>],
    limits: AttributeTemplateLimits,
    budget: &Arc<Budget>,
    mut validate_scope: impl FnMut(AttributeType) -> Result<()>,
) -> Result<Measurement> {
    bounds::ck_length(input.len())?;
    let mut measured = Measurement {
        attributes: 0,
        values: 0,
        groups: 1,
        bytes: 0,
        allocated_values: 0,
    };
    let mut scope_error = None;
    let mut walk = Walk::new(budget)?;
    walk.push(input)?;
    while !walk.frames.is_empty() {
        let depth = walk.frames.len() - 1;
        let Some(attribute) = walk.frames.last_mut().expect("nonempty traversal").next() else {
            walk.frames.pop();
            continue;
        };
        // Preserve structural-error priority over extension scope while using
        // this same borrowed traversal. No second parse or retained graph.
        if scope_error.is_none() {
            scope_error = validate_scope(attribute.attribute).err();
        }
        measured.attributes = measured
            .attributes
            .checked_add(1)
            .filter(|count| *count <= limits.maximum_attributes)
            .ok_or(Error::Rejected(crate::RejectionReason::AttributeValues(
                crate::AttributeValuesRejection::AttributeTemplateCountCeiling,
            )))?;
        if let Some(bytes) = value_size(attribute)? {
            measured.values = measured.values.checked_add(1).ok_or(Error::Rejected(
                crate::RejectionReason::AttributeValues(
                    crate::AttributeValuesRejection::AttributeValueCount,
                ),
            ))?;
            measured.bytes = measured
                .bytes
                .checked_add(bytes)
                .filter(|count| *count <= limits.maximum_value_bytes)
                .ok_or(Error::Rejected(crate::RejectionReason::AttributeValues(
                    crate::AttributeValuesRejection::AttributeTemplateValueCeiling,
                )))?;
            let allocated = AttributeBytes::allocation_bytes(bytes)?
                .checked_mul(2)
                .ok_or(Error::Rejected(crate::RejectionReason::AttributeValues(
                    crate::AttributeValuesRejection::AttributeValueWitnessAccounting,
                )))?;
            measured.allocated_values =
                measured
                    .allocated_values
                    .checked_add(allocated)
                    .ok_or(Error::Rejected(crate::RejectionReason::AttributeValues(
                        crate::AttributeValuesRejection::AttributeValueAllocationAccounting,
                    )))?;
        } else if let AttributeInputValue::Template(children) = &attribute.value {
            measured.groups = measured.groups.checked_add(1).ok_or(Error::Rejected(
                crate::RejectionReason::AttributeValues(
                    crate::AttributeValuesRejection::AttributeTemplateGroupCount,
                ),
            ))?;
            if !children.is_empty() {
                depth
                    .checked_add(1)
                    .filter(|depth| *depth <= limits.maximum_depth)
                    .ok_or(Error::Rejected(crate::RejectionReason::AttributeValues(
                        crate::AttributeValuesRejection::AttributeTemplateDepthCeiling,
                    )))?;
                walk.push(children)?;
            }
        }
    }
    if let Some(error) = scope_error {
        return Err(error);
    }
    Ok(measured)
}

// No recursive owner: nested descriptors are ranges in the same stable array.
// All leaves, including public-looking values, use protected storage and an
// independently erased witness. Unknown provider mutation never changes ownership.
#[derive(Clone, Copy)]
enum Referent {
    Value(usize),
    Template { start: usize, count: usize },
}
struct Witness {
    attribute: AttributeType,
    referent: Referent,
}
struct Leaf {
    value: AttributeBytes,
    witness: AttributeBytes,
}
pub(crate) struct InputTemplate {
    descriptors: Vec<CK_ATTRIBUTE>,
    witnesses: Vec<Witness>,
    leaves: Vec<Leaf>,
    root_count: CK_ULONG,
    _descriptor_credit: Credit,
    _witness_credit: Credit,
    _leaf_credit: Credit,
    _owner_credit: Credit,
}
// SAFETY: pointers address only fixed allocations owned by this arena. The
// arrays and leaf allocations are never resized after binding native pointers.
unsafe impl Send for InputTemplate {}
impl InputTemplate {
    /// Keep an enclosing native frame's already admitted credit with its input
    /// owner, including an uncertain return. This transfers bytes without waiting.
    pub(crate) fn retain_frame_credit(&mut self, credit: Credit) -> Result<()> {
        self._owner_credit.merge(credit)
    }

    pub(crate) fn check_extensions(&self, inner: &crate::module::Inner) -> Result<()> {
        let scope = inner.attribute_extension_scope.get().copied();
        for witness in &self.witnesses {
            witness.attribute.check_scope(scope)?;
        }
        Ok(())
    }

    /// Validate immutable extension ownership during the borrowed preflight.
    /// The existing iterative Walk has temporary credited scratch; it and its
    /// credit are fully dropped before returning this allocation-free plan.
    pub(crate) fn plan_scoped<'a>(
        input: &'a [AttributeInput<'a>],
        limits: AttributeTemplateLimits,
        inner: &crate::module::Inner,
    ) -> Result<InputTemplatePlan<'a>> {
        let scope = inner.attribute_extension_scope.get().copied();
        Ok(InputTemplatePlan {
            input,
            root_count: bounds::ck_length(input.len())?,
            measured: measure(input, limits, &inner.symmetric_budget, |attribute| {
                attribute.check_scope(scope)
            })?,
        })
    }
}

/// A borrowed, measured template, consumed only with a whole-request credit.
/// Holding multiple plans retains no arena allocation or traversal scratch.
pub(crate) struct InputTemplatePlan<'a> {
    input: &'a [AttributeInput<'a>],
    root_count: CK_ULONG,
    measured: Measurement,
}
impl<'a> InputTemplatePlan<'a> {}

impl InputTemplate {
    /// Borrow the owned root only inside a stable native frame. No input caller
    /// buffer is referenced, and no native code may retain this after completion.
    pub(crate) fn as_mut_ptr(&mut self) -> CK_ATTRIBUTE_PTR {
        self.descriptors.as_mut_ptr()
    }
    pub(crate) fn count(&self) -> CK_ULONG {
        self.root_count
    }

    pub(crate) fn unchanged(&mut self) -> bool {
        let mut values_equal = Choice::from(1);
        for leaf in &self.leaves {
            values_equal &= leaf.value.as_bytes().ct_eq(leaf.witness.as_bytes());
        }
        // Inspect every byte witness before returning a mismatch. Descriptor
        // identity is public metadata and never supplies a pointer to follow.
        let values_equal = bool::from(values_equal);
        let base = self.descriptors.as_mut_ptr();
        for (index, witness) in self.witnesses.iter().enumerate() {
            let (pointer, length) = match witness.referent {
                Referent::Value(leaf) => {
                    let leaf = &mut self.leaves[leaf];
                    (leaf.value.pointer(), leaf.value.capacity())
                }
                Referent::Template { start, count } => {
                    // SAFETY: constructor checked and retained this owned range.
                    (
                        unsafe { base.add(start) }.cast(),
                        count * size_of::<CK_ATTRIBUTE>(),
                    )
                }
            };
            let descriptor = &self.descriptors[index];
            if descriptor.r#type != witness.attribute.native()
                || descriptor.pValue != pointer
                || descriptor.ulValueLen as u128 != length as u128
            {
                return false;
            }
        }
        values_equal
    }
}

impl Drop for InputTemplate {
    fn drop(&mut self) {
        erase_descriptors(&mut self.descriptors);
        // Remaining fields drop in declaration order: each allocation before
        // its credit, and every leaf erases both native value and witness.
    }
}

fn encode(value: &AttributeInputValue<'_>, output: &mut AttributeBytes) -> Result<()> {
    match value {
        AttributeInputValue::Boolean(value) => {
            output.copy_from(&[if *value { CK_TRUE } else { CK_FALSE }])
        }
        AttributeInputValue::Unsigned(value) => {
            output.copy_from(&native_unsigned(*value)?.to_ne_bytes())
        }
        AttributeInputValue::Bytes(bytes) => output.copy_from(bytes),
        AttributeInputValue::Date(bytes) => output.copy_from(bytes),
        AttributeInputValue::Version(major, minor) => output.copy_from(&[*major, *minor]),
        AttributeInputValue::UnsignedArray(values) => {
            let width = size_of::<CK_ULONG>();
            for (index, value) in values.iter().enumerate() {
                output.copy_at(index * width, &native_unsigned(*value)?.to_ne_bytes())?;
            }
            Ok(())
        }
        AttributeInputValue::Template(_) => {
            Err(Error::Rejected(crate::RejectionReason::AttributeValues(
                crate::AttributeValuesRejection::NestedInputRequiresDescriptors,
            )))
        }
    }
}
