// SPDX-License-Identifier: Apache-2.0
//! Explicit key fields from typed parameter encoders, never inferred from bytes.
//!
//! A location identifies an ABI scalar, not authority to use its handle. Native
//! calls still acquire/check the corresponding object roles in their session.
//! Keep every field even when several fields refer to the same object; only the
//! role-reference list is deduplicated.
use super::graph::recipe::Recipe;
use crate::{Error, ExtensionDirection, NativeObjectRef, Result};
use fe11_sys::{CK_OBJECT_HANDLE, CK_VOID_PTR};
use std::{mem::size_of, sync::Arc};

// The closed typed compositions currently have at most three fields: CMS adds
// a certificate to its two transport children; KIP adds a key to one child.
// This is the existing internal source-array capacity, not a public key quota.
const SLOTS: usize = 4;

mod rebind;
pub(crate) use rebind::ReboundRecipe;
mod locations;
pub(crate) use locations::KeyLocations;

#[derive(Clone, Copy)]
pub(crate) struct ParameterKey<'a> {
    reference: &'a NativeObjectRef,
    block: usize,
    offset: usize,
}

impl<'a> ParameterKey<'a> {
    pub(crate) fn new(reference: &'a NativeObjectRef, block: usize, offset: usize) -> Self {
        Self {
            reference,
            block,
            offset,
        }
    }
}

#[derive(Clone, Copy, Default)]
pub(crate) struct ParameterKeys<'a> {
    fields: [Option<ParameterKey<'a>>; SLOTS],
}

fn invalid() -> Error {
    Error::Rejected(crate::RejectionReason::MechanismExtensions(
        crate::MechanismExtensionsRejection::TypedParameterKeyBinding,
    ))
}

impl<'a> ParameterKeys<'a> {
    /// Transport has at most one auxiliary field; composition expands it into
    /// this collection without duplicating the source and location states.
    pub(crate) fn from_source(source: Option<ParameterKey<'a>>) -> Self {
        Self {
            fields: [source, None, None, None],
        }
    }

    pub(crate) fn insert(
        &mut self,
        reference: Option<&'a NativeObjectRef>,
        block: usize,
        offset: usize,
    ) -> Result<()> {
        if let Some(reference) = reference {
            let slot = self
                .fields
                .iter_mut()
                .find(|slot| slot.is_none())
                .ok_or_else(invalid)?;
            *slot = Some(ParameterKey::new(reference, block, offset));
        }
        Ok(())
    }

    /// Rebase child block indices across the parent's blocks and CK_MECHANISM
    /// header. No native address or handle is changed by this metadata operation.
    pub(crate) fn rebased(mut self, base: usize) -> Result<Self> {
        for field in self.fields.iter_mut().flatten() {
            field.block = field.block.checked_add(base).ok_or_else(invalid)?;
        }
        Ok(self)
    }

    pub(crate) fn append(&mut self, other: Self) -> Result<()> {
        for field in other.fields.into_iter().flatten() {
            self.insert(Some(field.reference), field.block, field.offset)?;
        }
        Ok(())
    }

    /// Preserve the previous native-role order and identity-based deduplication.
    /// Distinct locations that alias an object remain present in `fields`.
    pub(crate) fn references(&self) -> Result<[Option<&'a NativeObjectRef>; SLOTS]> {
        let mut result: [Option<&NativeObjectRef>; SLOTS] = [None; SLOTS];
        for field in self.fields.iter().flatten() {
            let activity = field.reference.identity.activity()?;
            let mut present = false;
            for previous in result.iter().flatten() {
                present |= Arc::ptr_eq(previous.identity.activity()?, activity);
            }
            if !present {
                *result
                    .iter_mut()
                    .find(|slot| slot.is_none())
                    .ok_or_else(invalid)? = Some(field.reference);
            }
        }
        Ok(result)
    }

    /// Validate only the representation of this encoder-produced relationship:
    /// one input scalar of handle width, no pointer or other binding overlap,
    /// and the exact handle of the retained reference. No object attributes,
    /// cryptographic suitability, certificate content or key equality are read.
    pub(crate) fn validate(&self, recipe: &dyn Recipe) -> Result<()> {
        for (index, field) in self.fields.iter().enumerate() {
            let Some(field) = field else { continue };
            let end = field
                .offset
                .checked_add(size_of::<CK_OBJECT_HANDLE>())
                .ok_or_else(invalid)?;
            let block = recipe.block(field.block)?;
            if block.direction != ExtensionDirection::Input || end > block.length {
                return Err(invalid());
            }
            for index in 0..recipe.pointer_count() {
                let pointer = recipe.pointer(index)?;
                let pointer_end = pointer
                    .offset
                    .checked_add(size_of::<CK_VOID_PTR>())
                    .ok_or_else(invalid)?;
                if pointer.block == field.block
                    && pointer.offset < end
                    && field.offset < pointer_end
                {
                    return Err(invalid());
                }
            }
            for previous in self.fields[..index].iter().flatten() {
                let previous_end = previous
                    .offset
                    .checked_add(size_of::<CK_OBJECT_HANDLE>())
                    .ok_or_else(invalid)?;
                if previous.block == field.block
                    && previous.offset < end
                    && field.offset < previous_end
                {
                    return Err(invalid());
                }
            }
            let mut raw = [0; size_of::<CK_OBJECT_HANDLE>()];
            recipe.copy(field.block, field.offset, &mut raw)?;
            if raw != field.reference.identity.handle.to_ne_bytes() {
                return Err(invalid());
            }
        }
        Ok(())
    }

    /// Clone identities into an already admitted enclosing owner. These Arcs do
    /// not acquire roles and contain no Inner/module owner or session guard.
    pub(crate) fn retain(self) -> RetainedParameterKeys {
        RetainedParameterKeys {
            fields: self.fields.map(|field| {
                field.map(|field| RetainedField {
                    identity: field.reference.identity.clone(),
                    block: field.block,
                    offset: field.offset,
                })
            }),
        }
    }
}

#[derive(Clone)]
struct RetainedField {
    identity: Arc<crate::managed::NativeIdentity>,
    block: usize,
    offset: usize,
}

#[derive(Clone)]
pub(crate) struct RetainedParameterKeys {
    fields: [Option<RetainedField>; SLOTS],
}
impl RetainedParameterKeys {
    /// Verify an enclosing destination binding against the exact retained
    /// references in first-occurrence order, without consulting raw handles.
    pub(crate) fn matches_references(
        &self,
        references: [Option<&Arc<crate::managed::NativeIdentity>>; SLOTS],
    ) -> Result<bool> {
        let mut seen: [Option<&Arc<crate::managed::NativeIdentity>>; SLOTS] = [None; SLOTS];
        let mut count = 0usize;
        for field in self.fields.iter().flatten() {
            let activity = field.identity.activity()?;
            let mut repeated = false;
            for previous in seen[..count].iter().flatten() {
                repeated |= Arc::ptr_eq(previous.activity()?, activity);
            }
            if !repeated {
                let Some(expected) = references[count] else {
                    return Ok(false);
                };
                if !Arc::ptr_eq(expected, &field.identity) {
                    return Ok(false);
                }
                seen[count] = Some(&field.identity);
                count += 1;
            }
        }
        Ok(references[count..].iter().all(Option::is_none))
    }

    /// Check scalar bytes only after native memory return. This neither follows
    /// native pointers nor grants authority for cross-session restoration.
    pub(crate) fn unchanged(&self, graph: &super::OwnedGraph) -> bool {
        self.fields
            .iter()
            .flatten()
            .all(|field| graph.has_handle(field.block, field.offset, field.identity.handle))
    }
}
