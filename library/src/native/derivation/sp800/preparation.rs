// SPDX-License-Identifier: Apache-2.0
//! Empty multi-output arrays and segment buffers, measured before binding.
use super::{size, sum, Segment, Sp800Frame, Sp800Mode, Sp800Request, TemplateArray};
use crate::{native::derivation::InputBytesStorage, symmetric::memory::Credit, Error, Result};
use fe11_sys::{CK_DERIVED_KEY, CK_INVALID_HANDLE, CK_OBJECT_HANDLE, CK_PRF_DATA_PARAM};
use std::mem::size_of;

pub(super) enum PreparedSegment<'a> {
    Ready(Segment),
    Bytes {
        input: &'a [u8],
        storage: InputBytesStorage,
    },
}
impl PreparedSegment<'_> {
    fn allocated_bytes(&self) -> Result<usize> {
        match self {
            Self::Ready(_) => Ok(0),
            Self::Bytes { storage, .. } => storage.allocated_bytes(),
        }
    }
    pub(super) fn bind(self, credit: &mut Credit) -> Result<Segment> {
        match self {
            Self::Ready(segment) => Ok(segment),
            Self::Bytes { input, storage } => Ok(Segment::Bytes(storage.bind(input, credit)?)),
        }
    }
}

fn empty<T>(count: usize) -> Result<Vec<T>> {
    let mut values = Vec::new();
    values.try_reserve_exact(count).map_err(|_| {
        Error::Rejected(crate::RejectionReason::DerivedObjectCreation(
            crate::DerivedObjectCreationRejection::Sp800ArrayAllocation,
        ))
    })?;
    Ok(values)
}

pub(crate) struct Sp800Storage<'a> {
    pub(super) prepared: Vec<PreparedSegment<'a>>,
    pub(super) segments: Vec<Segment>,
    pub(super) descriptors: Vec<CK_PRF_DATA_PARAM>,
    pub(super) additional: Vec<CK_DERIVED_KEY>,
    pub(super) handles: Vec<CK_OBJECT_HANDLE>,
    pub(super) iv: Option<InputBytesStorage>,
    // Last: temporary storage remains credited on every partial bind exit.
    pub(super) credit: Option<Credit>,
}
impl<'a> Sp800Storage<'a> {
    pub(crate) fn allocate(input: &Sp800Request<'a>, outputs: usize) -> Result<Self> {
        Sp800Frame::allocation_bytes(input, outputs)?;
        let mut prepared = empty(input.data.len())?;
        let segments = empty(input.data.len())?;
        let descriptors = empty(input.data.len())?;
        let additional = empty(outputs - 1)?;
        let mut handles = empty(outputs)?;
        handles.resize(outputs, CK_INVALID_HANDLE);
        for part in input.data {
            prepared.push(Segment::prepare(part)?);
        }
        let iv = match input.mode {
            Sp800Mode::Feedback { iv: Some(input) } => {
                Some(InputBytesStorage::allocate(input.len())?)
            }
            _ => None,
        };
        Ok(Self {
            prepared,
            segments,
            descriptors,
            additional,
            handles,
            iv,
            credit: None,
        })
    }
    pub(super) fn metadata_bytes(&self) -> Result<usize> {
        sum(&[
            // Metadata credit follows the data through uncertain completion.
            size_of::<Sp800Frame>(),
            crate::native::frame::SessionFrame::<'_, Sp800Frame>::allocation_bytes(),
            size::<Segment>(self.segments.capacity())?,
            size::<CK_PRF_DATA_PARAM>(self.descriptors.capacity())?,
            size::<CK_DERIVED_KEY>(self.additional.capacity())?,
            size::<CK_OBJECT_HANDLE>(self.handles.capacity())?,
        ])
    }
    pub(crate) fn allocated_bytes(&self) -> Result<usize> {
        let metadata = sum(&[
            self.metadata_bytes()?,
            size::<PreparedSegment<'a>>(self.prepared.capacity())?,
        ])?;
        let parts = self
            .prepared
            .iter()
            .try_fold(metadata, |n, part| sum(&[n, part.allocated_bytes()?]))?;
        sum(&[
            parts,
            self.iv
                .as_ref()
                .map(InputBytesStorage::allocated_bytes)
                .transpose()?
                .unwrap_or(0),
        ])
    }
    pub(crate) fn bind(
        self,
        input: &Sp800Request<'_>,
        templates: TemplateArray,
        prepaid: &mut Credit,
    ) -> Result<Sp800Frame> {
        Sp800Frame::from_storage(input, templates, prepaid, self)
    }
}
