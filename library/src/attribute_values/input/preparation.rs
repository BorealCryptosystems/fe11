// SPDX-License-Identifier: Apache-2.0
//! Whole-arena allocation before caller bytes or native pointers are bound.
use super::{
    encode, value_size, AttributeInputValue, InputTemplate, InputTemplatePlan, Leaf, Pending,
    Referent, Witness,
};
use crate::attribute_values::storage::{erase_descriptors, AttributeBytesStorage};
use crate::{bounds, symmetric::memory::Credit, Error, Result};
use fe11_sys::{CK_ATTRIBUTE, CK_ULONG};
use std::mem::size_of;

struct PreparedLeaf<'a> {
    source: &'a AttributeInputValue<'a>,
    value: AttributeBytesStorage,
    witness: AttributeBytesStorage,
}

pub(crate) struct InputTemplateStorage<'a> {
    descriptors: Vec<CK_ATTRIBUTE>,
    witnesses: Vec<Witness>,
    leaves: Vec<Leaf>,
    prepared: Vec<PreparedLeaf<'a>>,
    root_count: CK_ULONG,
    traversal_bytes: usize,
    // Binding first attaches the complete arena credit, then transfers each
    // child's share. Keep the remainder after storage so failures free every
    // unbound allocation before notifying waiters.
    temporary_credit: Option<Credit>,
}

fn bytes<T>(count: usize) -> Result<usize> {
    count.checked_mul(size_of::<T>()).ok_or(Error::Rejected(
        crate::RejectionReason::AttributeValues(
            crate::AttributeValuesRejection::AttributeMetadataAccountingOverflow,
        ),
    ))
}

fn sum(values: impl IntoIterator<Item = usize>) -> Result<usize> {
    values.into_iter().try_fold(0usize, |total, value| {
        total
            .checked_add(value)
            .ok_or(Error::Rejected(crate::RejectionReason::AttributeValues(
                crate::AttributeValuesRejection::AttributeTemplateTotalAccounting,
            )))
    })
}

fn reserve<T>(count: usize) -> Result<Vec<T>> {
    let mut values = Vec::new();
    values.try_reserve_exact(count).map_err(|_| {
        Error::Rejected(crate::RejectionReason::AttributeValues(
            crate::AttributeValuesRejection::AttributeMetadataAllocation,
        ))
    })?;
    Ok(values)
}

impl<'a> InputTemplatePlan<'a> {
    pub(crate) fn prepared_allocation_bytes(&self) -> Result<usize> {
        sum([
            self.measured.peak_bytes()?,
            bytes::<PreparedLeaf<'a>>(self.measured.values)?,
        ])
    }

    pub(crate) fn allocate(&self) -> Result<InputTemplateStorage<'a>> {
        let mut storage = InputTemplateStorage {
            descriptors: reserve(self.measured.attributes)?,
            witnesses: reserve(self.measured.attributes)?,
            leaves: reserve(self.measured.values)?,
            prepared: reserve(self.measured.values)?,
            root_count: self.root_count,
            traversal_bytes: 0,
            temporary_credit: None,
        };
        // SAFETY: CK_ATTRIBUTE contains integer/raw-pointer fields with a valid
        // all-zero representation. Initialize the full capacity, including
        // padding; Drop erases it without reading or following native pointers.
        unsafe {
            storage
                .descriptors
                .as_mut_ptr()
                .write_bytes(0, storage.descriptors.capacity());
            storage.descriptors.set_len(self.measured.attributes);
        }
        let mut pending = reserve::<Pending<'a>>(self.measured.groups)?;
        pending.push((self.input, 0));
        let mut cursor = self.input.len();
        let mut next = 0;
        while next < pending.len() {
            let (attributes, start) = pending[next];
            next += 1;
            for (offset, attribute) in attributes.iter().enumerate() {
                if start.checked_add(offset) != Some(storage.witnesses.len()) {
                    return Err(Error::Rejected(crate::RejectionReason::AttributeValues(
                        crate::AttributeValuesRejection::AttributeArenaConstructionOrder,
                    )));
                }
                let referent = match &attribute.value {
                    AttributeInputValue::Template(children) => {
                        let child_start = cursor;
                        cursor = cursor
                            .checked_add(children.len())
                            .filter(|end| *end <= self.measured.attributes)
                            .ok_or(Error::Rejected(crate::RejectionReason::AttributeValues(
                                crate::AttributeValuesRejection::AttributeArenaRange,
                            )))?;
                        pending.push((children, child_start));
                        Referent::Template {
                            start: child_start,
                            count: children.len(),
                        }
                    }
                    source => {
                        let length = value_size(attribute)?.ok_or(Error::Rejected(
                            crate::RejectionReason::AttributeValues(
                                crate::AttributeValuesRejection::FlatInputRequired,
                            ),
                        ))?;
                        let index = storage.prepared.len();
                        storage.prepared.push(PreparedLeaf {
                            source,
                            value: AttributeBytesStorage::allocate(length)?,
                            witness: AttributeBytesStorage::allocate(length)?,
                        });
                        Referent::Value(index)
                    }
                };
                storage.witnesses.push(Witness {
                    attribute: attribute.attribute,
                    referent,
                });
            }
        }
        if cursor != self.measured.attributes
            || storage.witnesses.len() != self.measured.attributes
            || storage.prepared.len() != self.measured.values
        {
            return Err(Error::Rejected(crate::RejectionReason::AttributeValues(
                crate::AttributeValuesRejection::AttributeArenaUnfinished,
            )));
        }
        storage.traversal_bytes = bytes::<Pending<'a>>(pending.capacity())?;
        // It contains borrowed source references only. No value was copied and
        // no native pointer has been installed in the descriptor array.
        drop(pending);
        Ok(storage)
    }
}

impl InputTemplateStorage<'_> {
    fn temporary_bytes(&self) -> Result<usize> {
        sum([
            bytes::<PreparedLeaf<'_>>(self.prepared.capacity())?,
            self.traversal_bytes,
        ])
    }

    pub(crate) fn allocated_bytes(&self) -> Result<usize> {
        let mut total = sum([
            size_of::<InputTemplate>(),
            bytes::<CK_ATTRIBUTE>(self.descriptors.capacity())?,
            bytes::<Witness>(self.witnesses.capacity())?,
            bytes::<Leaf>(self.leaves.capacity())?,
            self.temporary_bytes()?,
        ])?;
        for leaf in &self.prepared {
            total = sum([
                total,
                leaf.value.allocated_bytes()?,
                leaf.witness.allocated_bytes()?,
            ])?;
        }
        Ok(total)
    }

    pub(crate) fn bind(mut self, prepaid: &mut Credit) -> Result<InputTemplate> {
        self.temporary_credit = Some(prepaid.split(self.allocated_bytes()?)?);
        // Every following split is bounded by the immutable capacity sum just
        // transferred. Unbound child credit remains attached to this storage
        // if encoding fails after only some children have been constructed.
        let prepaid = self
            .temporary_credit
            .as_mut()
            .expect("admitted input arena");
        let descriptor_credit =
            prepaid.split(bytes::<CK_ATTRIBUTE>(self.descriptors.capacity())?)?;
        let witness_credit = prepaid.split(bytes::<Witness>(self.witnesses.capacity())?)?;
        let leaf_credit = prepaid.split(bytes::<Leaf>(self.leaves.capacity())?)?;
        let owner_credit = prepaid.split(size_of::<InputTemplate>())?;
        let mut template = InputTemplate {
            descriptors: std::mem::take(&mut self.descriptors),
            witnesses: std::mem::take(&mut self.witnesses),
            leaves: std::mem::take(&mut self.leaves),
            root_count: self.root_count,
            _descriptor_credit: descriptor_credit,
            _witness_credit: witness_credit,
            _leaf_credit: leaf_credit,
            _owner_credit: owner_credit,
        };
        for leaf in self.prepared.drain(..) {
            let mut value = leaf.value.bind(prepaid)?;
            encode(leaf.source, &mut value)?;
            let mut witness = leaf.witness.bind(prepaid)?;
            witness.copy_from(value.as_bytes())?;
            template.leaves.push(Leaf { value, witness });
        }
        let base = template.descriptors.as_mut_ptr();
        for (index, witness) in template.witnesses.iter().enumerate() {
            let (pointer, length) = match witness.referent {
                Referent::Value(leaf) => {
                    let value = &mut template.leaves[leaf].value;
                    (value.pointer(), value.capacity())
                }
                Referent::Template { start, count } => {
                    // SAFETY: allocation validated the complete child range.
                    // Empty child templates use a non-NULL one-past pointer.
                    (
                        unsafe { base.add(start) }.cast(),
                        bytes::<CK_ATTRIBUTE>(count)?,
                    )
                }
            };
            let length = bounds::ck_length(length)?;
            // SAFETY: index is in the complete initialized descriptor array.
            // Use its original pointer; packed ABI fields require unaligned stores.
            unsafe {
                let descriptor = base.add(index);
                std::ptr::addr_of_mut!((*descriptor).r#type)
                    .write_unaligned(witness.attribute.native());
                std::ptr::addr_of_mut!((*descriptor).pValue).write_unaligned(pointer);
                std::ptr::addr_of_mut!((*descriptor).ulValueLen).write_unaligned(length);
            }
        }
        // Temporary capacity is freed before its attached credit by field order.
        drop(self);
        Ok(template)
    }
}

impl Drop for InputTemplateStorage<'_> {
    fn drop(&mut self) {
        erase_descriptors(&mut self.descriptors);
    }
}
