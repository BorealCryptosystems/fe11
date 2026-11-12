// SPDX-License-Identifier: Apache-2.0
//! Immutable destination components shared across reservation/catalogue keys.

use crate::{
    attributes::ByteParts,
    symmetric::memory::{Buffer, Credit, UnboundBuffer},
    Error, Result,
};
use std::{
    cmp::Ordering,
    hash::{Hash, Hasher},
    mem::size_of,
    ops::Deref,
    sync::Arc,
};

struct Resident {
    bytes: Buffer,
    _credit: Credit,
}
#[derive(Clone)]
pub(super) struct SharedBytes(Arc<Resident>);
impl SharedBytes {
    fn allocation_bytes(bytes: ByteParts<'_>) -> Result<usize> {
        crate::bounds::ck_length(bytes.len())?;
        // Arc's two counters are Rust ownership metadata, not allocator overhead.
        bytes
            .len()
            .checked_add(size_of::<Resident>())
            .and_then(|n| n.checked_add(2 * size_of::<usize>()))
            .ok_or(Error::Rejected(crate::RejectionReason::ObjectPublication(
                crate::ObjectPublicationRejection::DestinationByteAccounting,
            )))
    }
    fn bind(bytes: ByteParts<'_>, storage: UnboundBuffer, prepaid: &mut Credit) -> Result<Self> {
        let mut buffer = storage.bind(prepaid)?;
        bytes.copy_to(buffer.as_mut());
        let credit = prepaid.split(size_of::<Resident>() + 2 * size_of::<usize>())?;
        Ok(Self(Arc::new(Resident {
            bytes: buffer,
            _credit: credit,
        })))
    }
}
impl Deref for SharedBytes {
    type Target = [u8];
    fn deref(&self) -> &[u8] {
        self.0.bytes.as_slice()
    }
}
impl PartialEq for SharedBytes {
    fn eq(&self, other: &Self) -> bool {
        self.deref() == other.deref()
    }
}
impl Eq for SharedBytes {}
impl PartialOrd for SharedBytes {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}
impl Ord for SharedBytes {
    fn cmp(&self, other: &Self) -> Ordering {
        self.deref().cmp(other.deref())
    }
}
impl Hash for SharedBytes {
    fn hash<H: Hasher>(&self, state: &mut H) {
        self.deref().hash(state);
    }
}
/// All siblings are allocated outside possession, and their actual capacity is
/// admitted as part of the caller's complete preparation. Binding never waits.
pub(super) struct PreparedParts<'a> {
    parts: [Option<ByteParts<'a>>; 3],
    storage: [Option<UnboundBuffer>; 3],
    allocated: usize,
}

impl<'a> PreparedParts<'a> {
    pub(super) fn requested(parts: [Option<&[u8]>; 3]) -> Result<usize> {
        Self::requested_parts(parts.map(|part| part.map(ByteParts::from)))
    }
    pub(super) fn requested_parts(parts: [Option<ByteParts<'_>>; 3]) -> Result<usize> {
        parts.iter().flatten().try_fold(0usize, |total, bytes| {
            total
                .checked_add(SharedBytes::allocation_bytes(*bytes)?)
                .ok_or(Error::Rejected(crate::RejectionReason::ObjectPublication(
                    crate::ObjectPublicationRejection::DestinationTupleAccounting,
                )))
        })
    }

    pub(super) fn allocate(parts: [Option<&'a [u8]>; 3]) -> Result<Self> {
        Self::allocate_parts(parts.map(|part| part.map(ByteParts::from)))
    }
    pub(super) fn allocate_parts(parts: [Option<ByteParts<'a>>; 3]) -> Result<Self> {
        Self::requested_parts(parts)?;
        let mut storage = [None, None, None];
        let mut actual = 0usize;
        for (target, input) in storage.iter_mut().zip(parts) {
            if let Some(input) = input {
                let buffer = UnboundBuffer::allocate(input.len())?;
                actual = actual
                    .checked_add(buffer.allocated())
                    .and_then(|bytes| {
                        bytes.checked_add(size_of::<Resident>() + 2 * size_of::<usize>())
                    })
                    .ok_or(Error::Rejected(crate::RejectionReason::ObjectPublication(
                        crate::ObjectPublicationRejection::DestinationTupleAccounting,
                    )))?;
                *target = Some(buffer);
            }
        }
        Ok(Self {
            parts,
            storage,
            allocated: actual,
        })
    }

    pub(super) fn allocated_bytes(&self) -> usize {
        self.allocated
    }

    pub(super) fn bind(self, prepaid: &mut Credit) -> Result<[Option<SharedBytes>; 3]> {
        let mut owned = [None, None, None];
        for ((target, input), storage) in owned.iter_mut().zip(self.parts).zip(self.storage) {
            if let (Some(input), Some(storage)) = (input, storage) {
                *target = Some(SharedBytes::bind(input, storage, prepaid)?);
            }
        }
        Ok(owned)
    }
}
