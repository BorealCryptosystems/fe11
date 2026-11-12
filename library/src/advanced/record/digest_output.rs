// SPDX-License-Identifier: Apache-2.0
//! Native capacity negotiation is separate from the selected digest parameters.
use super::{Reader, Writer};
use crate::{bounds, Error, Result};

#[derive(Clone, Copy)]
pub(in crate::advanced) struct DigestOutput {
    pub capacity: usize,
    pub waiting: Option<usize>,
}
impl DigestOutput {
    pub(in crate::advanced) fn write(self, writer: &mut Writer<'_>) -> Result<()> {
        bounds::ck_length(self.capacity)?;
        writer.u64(self.capacity as u64)?;
        writer.optional_u64(self.waiting.map(|required| required as u64))
    }
    pub(in crate::advanced) fn read(reader: &mut Reader<'_>) -> Result<Self> {
        let width = |value| {
            usize::try_from(value).map_err(|_| {
                Error::Rejected(crate::RejectionReason::OperationRecord(
                    crate::OperationRecordRejection::DigestOutputCapacityWidth,
                ))
            })
        };
        let capacity = width(reader.u64()?)?;
        let waiting = reader.optional_u64()?.map(width).transpose()?;
        bounds::ck_length(capacity)?;
        if let Some(required) = waiting {
            bounds::ck_length(required)?;
        }
        Ok(Self { capacity, waiting })
    }
}
