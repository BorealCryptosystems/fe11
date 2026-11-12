// SPDX-License-Identifier: Apache-2.0
//! Borrowed per-row operational refusals, separate from verification verdicts.
use super::{Function, Limits, Reader, Writer};
use crate::{Error, NativeMessageRejection, Result};

fn invalid() -> Error {
    Error::Rejected(crate::RejectionReason::MessageRecord(
        crate::MessageRecordRejection::MessageRefusalRepresentation,
    ))
}

#[derive(Clone, Copy)]
pub(in crate::advanced) enum MessageRejections<'a> {
    /// Historical typed streams could not retain an operationally refused row.
    Legacy,
    Live(&'a [Option<NativeMessageRejection>]),
    Encoded {
        bytes: &'a [u8],
        count: usize,
    },
}

fn read_one(reader: &mut Reader<'_>) -> Result<Option<NativeMessageRejection>> {
    if !reader.boolean(crate::RejectionReason::MessageRecord(
        crate::MessageRecordRejection::MessageRefusalPresence,
    ))? {
        return Ok(None);
    }
    let function = Function::read(reader)?.name();
    let code = reader.u64()?;
    fe11_sys::CK_RV::try_from(code).map_err(|_| invalid())?;
    Ok(Some(NativeMessageRejection { function, code }))
}

impl<'a> MessageRejections<'a> {
    pub(super) fn read(reader: &mut Reader<'a>, limits: Limits) -> Result<Self> {
        let count = reader.count(limits.messages)?;
        let start = reader.position;
        for _ in 0..count {
            read_one(reader)?;
        }
        Ok(Self::Encoded {
            bytes: &reader.bytes[start..reader.position],
            count,
        })
    }

    pub(super) fn write(self, writer: &mut Writer<'_>) -> Result<()> {
        let count = match self {
            Self::Legacy => return Err(invalid()),
            Self::Live(rows) => rows.len(),
            Self::Encoded { count, .. } => count,
        };
        writer.u32(u32::try_from(count).map_err(|_| invalid())?)?;
        for refusal in self.iter(count)? {
            let refusal = refusal?;
            writer.u8(u8::from(refusal.is_some()))?;
            if let Some(refusal) = refusal {
                Function::from_name(refusal.function)?.write(writer)?;
                writer.u64(refusal.code)?;
            }
        }
        Ok(())
    }

    pub(in crate::advanced) fn iter(self, count: usize) -> Result<RejectionIter<'a>> {
        let expected = match self {
            Self::Legacy => count,
            Self::Live(rows) => rows.len(),
            Self::Encoded { count, .. } => count,
        };
        if count != expected {
            return Err(invalid());
        }
        Ok(RejectionIter {
            source: self,
            index: 0,
            count,
            position: 0,
        })
    }
}

pub(in crate::advanced) struct RejectionIter<'a> {
    source: MessageRejections<'a>,
    index: usize,
    count: usize,
    position: usize,
}
impl Iterator for RejectionIter<'_> {
    type Item = Result<Option<NativeMessageRejection>>;
    fn next(&mut self) -> Option<Self::Item> {
        if self.index == self.count {
            return None;
        }
        let result = match self.source {
            MessageRejections::Legacy => Ok(None),
            MessageRejections::Live(rows) => rows.get(self.index).copied().ok_or_else(invalid),
            MessageRejections::Encoded { bytes, .. } => {
                let mut reader = Reader {
                    bytes,
                    position: self.position,
                    graph_observer: None,
                };
                let result = read_one(&mut reader);
                self.position = reader.position;
                result
            }
        };
        self.index += 1;
        if result.is_err() {
            self.index = self.count;
        }
        Some(result)
    }
}
