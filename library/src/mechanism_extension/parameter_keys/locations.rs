// SPDX-License-Identifier: Apache-2.0
//! Pointer- and handle-free locations of typed auxiliary key fields.
//!
//! The graph codec preserves parameter bytes; this separate description tells
//! restoration exactly which input scalars must receive explicit destination
//! references. An archive cannot obtain an object from the old scalar bytes.
//! This metadata grants no object role and never proves key correspondence.
use super::{invalid, ParameterKeys, ReboundRecipe, RetainedField, RetainedParameterKeys, SLOTS};
use crate::mechanism_extension::{graph::snapshot::SnapshotRecipe, OwnedGraph};
use crate::{NativeObjectRef, Result};
use fe11_sys::CK_OBJECT_HANDLE;
use std::{mem::size_of, sync::Arc};

const HEADER: usize = 8;
const FIELD_BYTES: usize = 17;
const MAGIC: &[u8; 4] = b"FK01";

#[derive(Clone, Copy, PartialEq, Eq)]
struct Location {
    role: usize,
    block: usize,
    offset: usize,
}

/// The capacity is the existing typed-composition bound, not a new caller
/// resource ceiling. Every field is retained, including repeated key aliases.
#[derive(Clone, Copy, PartialEq, Eq)]
pub(crate) struct KeyLocations {
    fields: [Option<Location>; SLOTS],
    roles: usize,
}

impl RetainedParameterKeys {
    /// First-occurrence ordering is identical to ParameterKeys::references.
    /// Identity/Activity metadata is inspected, never a native pointer.
    pub(crate) fn locations(&self) -> Result<KeyLocations> {
        let mut originals: [Option<&RetainedField>; SLOTS] = [None; SLOTS];
        let mut result = KeyLocations {
            fields: [None; SLOTS],
            roles: 0,
        };
        for (slot, field) in self.fields.iter().flatten().enumerate() {
            let activity = field.identity.activity()?;
            let mut role = None;
            for (index, previous) in originals[..result.roles].iter().enumerate() {
                if Arc::ptr_eq(previous.ok_or_else(invalid)?.identity.activity()?, activity) {
                    role = Some(index);
                    break;
                }
            }
            let role = match role {
                Some(role) => role,
                None => {
                    let role = result.roles;
                    originals[role] = Some(field);
                    result.roles += 1;
                    role
                }
            };
            result.fields[slot] = Some(Location {
                role,
                block: field.block,
                offset: field.offset,
            });
        }
        result.validate()?;
        Ok(result)
    }
}

impl KeyLocations {
    fn count(self) -> usize {
        self.fields.iter().flatten().count()
    }

    /// Canonical slot order excludes ambiguous or unused role indices. Width,
    /// overlap and addition checks are representation checks, not key policy.
    fn validate(self) -> Result<()> {
        let mut roles = 0;
        let mut gap = false;
        for (index, field) in self.fields.iter().enumerate() {
            let Some(field) = field else {
                gap = true;
                continue;
            };
            if gap || field.role > roles || field.role >= SLOTS {
                return Err(invalid());
            }
            if field.role == roles {
                roles += 1;
            }
            let end = field
                .offset
                .checked_add(size_of::<CK_OBJECT_HANDLE>())
                .ok_or_else(invalid)?;
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
        }
        if roles != self.roles {
            return Err(invalid());
        }
        Ok(())
    }

    fn bind<'a>(self, destinations: &[&'a NativeObjectRef]) -> Result<ParameterKeys<'a>> {
        self.validate()?;
        if destinations.len() != self.roles {
            return Err(invalid());
        }
        let mut keys = ParameterKeys::default();
        for field in self.fields.into_iter().flatten() {
            let reference = destinations.get(field.role).copied().ok_or_else(invalid)?;
            keys.insert(Some(reference), field.block, field.offset)?;
        }
        Ok(keys)
    }

    /// Rebind encoder-declared input scalars in a private graph recipe. This
    /// checks pointer/scalar separation through ParameterKeys::validate, but
    /// the enclosing transaction must still admit every destination role.
    pub(crate) fn rebind<'a>(
        self,
        graph: &'a OwnedGraph,
        destinations: &[&'a NativeObjectRef],
    ) -> Result<ReboundRecipe<'a>> {
        if !graph.unchanged() {
            return Err(invalid());
        }
        ReboundRecipe::live(graph, self.bind(destinations)?)
    }

    /// Overlay only the declared auxiliary handle scalars in a parsed archive
    /// recipe. No native source identity or permission is fabricated from bytes.
    /// Graph parsing has checked pointer ABI; ReboundRecipe validates the field
    /// bounds, Input direction, pointer separation and explicit destination values.
    pub(crate) fn rebind_snapshot<'a>(
        self,
        graph: SnapshotRecipe<'a>,
        destinations: &[&'a NativeObjectRef],
    ) -> Result<ReboundRecipe<'a>> {
        ReboundRecipe::snapshot(graph, self.bind(destinations)?)
    }

    pub(crate) fn encoded_len(self) -> Result<usize> {
        self.validate()?;
        self.count()
            .checked_mul(FIELD_BYTES)
            .and_then(|n| n.checked_add(HEADER))
            .ok_or_else(invalid)
    }

    /// Versioned section for the generic continuation archive. Native handles,
    /// object attributes, source sessions and addresses are never serialized.
    /// The enclosing graph section independently checks its complete native ABI.
    pub(crate) fn write(self, mut write: impl FnMut(&[u8]) -> Result<()>) -> Result<()> {
        self.validate()?;
        write(MAGIC)?;
        write(&[
            self.count() as u8,
            self.roles as u8,
            size_of::<CK_OBJECT_HANDLE>() as u8,
            0,
        ])?;
        for field in self.fields.into_iter().flatten() {
            write(&[field.role as u8])?;
            write(
                &u64::try_from(field.block)
                    .map_err(|_| invalid())?
                    .to_le_bytes(),
            )?;
            write(
                &u64::try_from(field.offset)
                    .map_err(|_| invalid())?
                    .to_le_bytes(),
            )?;
        }
        Ok(())
    }

    /// Parsing allocates nothing and accepts exactly one complete section.
    /// Graph extent/direction/pointer checks are deferred to rebind, before any
    /// native use; parsing alone supplies neither a key nor a safe ABI assertion.
    pub(crate) fn parse(bytes: &[u8]) -> Result<Self> {
        let header = bytes.get(..HEADER).ok_or_else(invalid)?;
        if &header[..4] != MAGIC
            || header[6] as usize != size_of::<CK_OBJECT_HANDLE>()
            || header[7] != 0
        {
            return Err(invalid());
        }
        let count = header[4] as usize;
        if count > SLOTS || header[5] as usize > count {
            return Err(invalid());
        }
        let expected = count
            .checked_mul(FIELD_BYTES)
            .and_then(|n| n.checked_add(HEADER))
            .ok_or_else(invalid)?;
        if bytes.len() != expected {
            return Err(invalid());
        }
        let mut result = Self {
            fields: [None; SLOTS],
            roles: header[5] as usize,
        };
        for (index, field) in bytes[HEADER..].chunks_exact(FIELD_BYTES).enumerate() {
            let word = |range: std::ops::Range<usize>| -> Result<usize> {
                let raw: [u8; 8] = field
                    .get(range)
                    .ok_or_else(invalid)?
                    .try_into()
                    .map_err(|_| invalid())?;
                usize::try_from(u64::from_le_bytes(raw)).map_err(|_| invalid())
            };
            result.fields[index] = Some(Location {
                role: field[0] as usize,
                block: word(1..9)?,
                offset: word(9..17)?,
            });
        }
        result.validate()?;
        Ok(result)
    }
}
