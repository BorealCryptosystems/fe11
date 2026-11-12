// SPDX-License-Identifier: Apache-2.0
//! Canonical bounded wire primitives. Structural decoding is not authentication.
//! Typed context/key/native-state adapters must validate before any restoration.

use crate::{symmetric::memory::Buffer, Error, Result};

pub(in crate::advanced) mod aead_batch;
pub(in crate::advanced) mod aead_messages;
mod checkpoint;
mod family;
mod options;
pub(in crate::advanced) mod profile;
pub(super) use family::Family;
pub(in crate::advanced) mod cipher_extension;
mod detached;
pub(in crate::advanced) mod digest_extension;
pub(in crate::advanced) mod digest_output;
mod message_output;
mod message_rejections;
mod message_stream;
pub(super) use message_rejections::MessageRejections;
mod messages;
pub(in crate::advanced) mod native_messages;
pub(super) use message_output::MessageOutput;
pub(super) use message_stream::{MessageStream, StreamBoundary};
mod restoration;
pub(in crate::advanced) mod signature;
mod terminal;
pub(super) use restoration::RestorationRecord;
mod dual_recovery;
mod recovery;
mod recovery_manifest;
pub(super) use checkpoint::{Descriptor, SavedRecord};
pub(super) use detached::DetachedRecord;
pub(super) use dual_recovery::DualRecovery;
pub(super) use recovery::RecoverySection;
pub(super) use recovery_manifest::{RecoveryManifest, RecoveryOrigin};
mod bindings;
mod functions;
pub(super) use bindings::{Context, KeyBinding, KeyBindings, KeyRole};
mod validation;
pub(super) use functions::Function;
pub(super) use messages::{Fragments, Message, MessageState, Messages, NonceOrigin, Parameters};
pub(super) use validation::ValidationRecord;
// Version 9 binds input counters, output continuations and parent stream
// boundaries to native progression, including an initialized zero-message owner.
// Earlier versions are rejected, never silently interpreted with the new
// continuation semantics. Historical archives remain untouched.
const MAGIC: &[u8; 8] = b"BPKIOP09";
const HEADER: usize = 17;
#[derive(Clone, Copy, PartialEq, Eq)]
pub(super) enum Kind {
    Saved,
    Detached,
    GcmRecovery,
    GcmRecoveryManifest,
    DualRecovery,
    DetachedCapture,
    DetachedValidation,
    DetachedRestore,
}
impl Kind {
    fn wire(self) -> u8 {
        match self {
            Self::Saved => 1,
            Self::Detached => 2,
            Self::GcmRecovery => 3,
            Self::GcmRecoveryManifest => 4,
            Self::DualRecovery => 5,
            Self::DetachedCapture => 6,
            Self::DetachedValidation => 7,
            Self::DetachedRestore => 8,
        }
    }

    fn from_wire(code: u8) -> Result<Self> {
        match code {
            1 => Ok(Self::Saved),
            2 => Ok(Self::Detached),
            3 => Ok(Self::GcmRecovery),
            4 => Ok(Self::GcmRecoveryManifest),
            5 => Ok(Self::DualRecovery),
            6 => Ok(Self::DetachedCapture),
            7 => Ok(Self::DetachedValidation),
            8 => Ok(Self::DetachedRestore),
            _ => Err(Error::Rejected(crate::RejectionReason::OperationRecord(
                crate::OperationRecordRejection::RecordKind,
            ))),
        }
    }
}

#[derive(Clone, Copy)]
pub(super) struct Limits {
    pub bytes: usize,
    pub messages: usize,
    pub fragments: usize,
}
impl Limits {
    pub(super) fn validate(self) -> Result<()> {
        if self.bytes < HEADER || self.bytes > isize::MAX as usize {
            return Err(Error::Rejected(crate::RejectionReason::OperationRecord(
                crate::OperationRecordRejection::RecordLimits,
            )));
        }
        Ok(())
    }
}
pub(super) struct Writer<'a> {
    target: Option<&'a mut [u8]>,
    position: usize,
    maximum: usize,
}
impl Writer<'_> {
    fn put(&mut self, bytes: &[u8]) -> Result<()> {
        let end = self
            .position
            .checked_add(bytes.len())
            .filter(|n| *n <= self.maximum)
            .ok_or(Error::Rejected(crate::RejectionReason::OperationRecord(
                crate::OperationRecordRejection::RecordLength,
            )))?;
        if let Some(target) = &mut self.target {
            target
                .get_mut(self.position..end)
                .ok_or(Error::Rejected(crate::RejectionReason::OperationRecord(
                    crate::OperationRecordRejection::RecordWriteRange,
                )))?
                .copy_from_slice(bytes);
        }
        self.position = end;
        Ok(())
    }
    pub(super) fn u8(&mut self, value: u8) -> Result<()> {
        self.put(&[value])
    }
    pub(super) fn u16(&mut self, value: u16) -> Result<()> {
        self.put(&value.to_be_bytes())
    }
    pub(super) fn u32(&mut self, value: u32) -> Result<()> {
        self.put(&value.to_be_bytes())
    }
    pub(super) fn u64(&mut self, value: u64) -> Result<()> {
        self.put(&value.to_be_bytes())
    }
    pub(super) fn bytes(&mut self, bytes: &[u8]) -> Result<()> {
        self.u64(u64::try_from(bytes.len()).map_err(|_| {
            Error::Rejected(crate::RejectionReason::OperationRecord(
                crate::OperationRecordRejection::RecordByteLength,
            ))
        })?)?;
        self.put(bytes)
    }
    /// Serialize an owned graph into the existing destination, without a
    /// second temporary archive. Count and actual output must agree exactly.
    pub(super) fn generated_bytes(
        &mut self,
        length: usize,
        emit: impl FnOnce(&mut dyn FnMut(&[u8]) -> Result<()>) -> Result<()>,
    ) -> Result<()> {
        self.u64(u64::try_from(length).map_err(|_| {
            Error::Rejected(crate::RejectionReason::OperationRecord(
                crate::OperationRecordRejection::RecordByteLength,
            ))
        })?)?;
        let start = self.position;
        emit(&mut |bytes| self.put(bytes))?;
        if self.position.checked_sub(start) != Some(length) {
            return Err(Error::Rejected(crate::RejectionReason::OperationRecord(
                crate::OperationRecordRejection::RecordGeneratedByteLength,
            )));
        }
        Ok(())
    }
    pub(super) fn optional_bytes(&mut self, value: Option<&[u8]>) -> Result<()> {
        match value {
            None => self.u8(0),
            Some(bytes) => {
                self.u8(1)?;
                self.bytes(bytes)
            }
        }
    }
    pub(super) fn optional_u64(&mut self, value: Option<u64>) -> Result<()> {
        match value {
            None => self.u8(0),
            Some(n) => {
                self.u8(1)?;
                self.u64(n)
            }
        }
    }
}

/// Pure measurement for a guarded source snapshot. No allocation or admission.
pub(super) fn encoded_size(
    limits: Limits,
    body: impl Fn(&mut Writer<'_>) -> Result<()>,
) -> Result<usize> {
    limits.validate()?;
    let mut writer = Writer {
        target: None,
        position: 0,
        maximum: limits.bytes - HEADER,
    };
    body(&mut writer)?;
    HEADER.checked_add(writer.position).ok_or(Error::Rejected(
        crate::RejectionReason::OperationRecord(crate::OperationRecordRejection::RecordLength),
    ))
}
/// Fill storage already admitted outside the source guards. A changed size is a
/// refusal, never a partial published record or an implicit source retry.
pub(super) fn encode_into(
    kind: Kind,
    limits: Limits,
    result: &mut Buffer,
    body: impl Fn(&mut Writer<'_>) -> Result<()>,
) -> Result<()> {
    limits.validate()?;
    let total = result.capacity();
    let payload = total
        .checked_sub(HEADER)
        .filter(|_| total <= limits.bytes)
        .ok_or(Error::Rejected(crate::RejectionReason::OperationRecord(
            crate::OperationRecordRejection::RecordLength,
        )))?;
    let mut writer = Writer {
        target: Some(result.as_mut()),
        position: 0,
        maximum: total,
    };
    writer.put(MAGIC)?;
    writer.u8(kind.wire())?;
    writer.u64(u64::try_from(payload).map_err(|_| {
        Error::Rejected(crate::RejectionReason::OperationRecord(
            crate::OperationRecordRejection::RecordByteLength,
        ))
    })?)?;
    body(&mut writer)?;
    if writer.position != total {
        return Err(Error::Rejected(crate::RejectionReason::OperationRecord(
            crate::OperationRecordRejection::RecordSizeChanged,
        )));
    }
    Ok(())
}
impl Writer<'_> {
    /// Embed a canonical child record directly, preserving its own header and
    /// byte-string length without allocating an intermediate native-state copy.
    pub(super) fn record_bytes(
        &mut self,
        kind: Kind,
        limits: Limits,
        body: impl Fn(&mut Writer<'_>) -> Result<()>,
    ) -> Result<()> {
        let total = encoded_size(limits, &body)?;
        self.u64(u64::try_from(total).map_err(|_| {
            Error::Rejected(crate::RejectionReason::OperationRecord(
                crate::OperationRecordRejection::RecordByteLength,
            ))
        })?)?;
        let start = self.position;
        self.put(MAGIC)?;
        self.u8(kind.wire())?;
        self.u64(u64::try_from(total - HEADER).map_err(|_| {
            Error::Rejected(crate::RejectionReason::OperationRecord(
                crate::OperationRecordRejection::RecordByteLength,
            ))
        })?)?;
        body(self)?;
        if self.position.checked_sub(start) != Some(total) {
            return Err(Error::Rejected(crate::RejectionReason::OperationRecord(
                crate::OperationRecordRejection::RecordSizeChanged,
            )));
        }
        Ok(())
    }
}
pub(super) type GraphObserver<'a> = Option<&'a dyn Fn(&[u8]) -> Result<()>>;
pub(super) struct Reader<'a> {
    bytes: &'a [u8],
    position: usize,
    graph_observer: GraphObserver<'a>,
}
impl<'a> Reader<'a> {
    /// Every declared graph is visited during the initial record traversal.
    /// Ordinary internal readers only inspect structure; the import boundary
    /// supplies the prepaid semantic validator before publishing ParsedRecord.
    fn inspect_graph(&self, bytes: &[u8]) -> Result<()> {
        crate::mechanism_extension::graph::snapshot::SnapshotRecipe::decode(bytes)?;
        if let Some(observer) = self.graph_observer {
            observer(bytes)?;
        }
        Ok(())
    }
    pub(super) fn remaining(&self) -> usize {
        self.bytes.len() - self.position
    }

    pub(super) fn take(&mut self, count: usize) -> Result<&'a [u8]> {
        let end = self.position.checked_add(count).ok_or(Error::Rejected(
            crate::RejectionReason::OperationRecord(
                crate::OperationRecordRejection::RecordReadOverflow,
            ),
        ))?;
        let result = self.bytes.get(self.position..end).ok_or(Error::Rejected(
            crate::RejectionReason::OperationRecord(
                crate::OperationRecordRejection::TruncatedRecord,
            ),
        ))?;
        self.position = end;
        Ok(result)
    }
    pub(super) fn u8(&mut self) -> Result<u8> {
        Ok(self.take(1)?[0])
    }
    /// The same closed 0/1 representation is shared by several fields. Keep
    /// each field's diagnostic and call position; do not reorder validations.
    pub(super) fn boolean(&mut self, rejection: crate::RejectionReason) -> Result<bool> {
        match self.u8()? {
            0 => Ok(false),
            1 => Ok(true),
            _ => Err(Error::Rejected(rejection)),
        }
    }

    pub(super) fn u16(&mut self) -> Result<u16> {
        Ok(u16::from_be_bytes(self.take(2)?.try_into().map_err(
            |_| {
                Error::Rejected(crate::RejectionReason::OperationRecord(
                    crate::OperationRecordRejection::RecordIntegerWidth,
                ))
            },
        )?))
    }
    pub(super) fn u32(&mut self) -> Result<u32> {
        Ok(u32::from_be_bytes(self.take(4)?.try_into().map_err(
            |_| {
                Error::Rejected(crate::RejectionReason::OperationRecord(
                    crate::OperationRecordRejection::RecordIntegerWidth,
                ))
            },
        )?))
    }
    pub(super) fn u64(&mut self) -> Result<u64> {
        Ok(u64::from_be_bytes(self.take(8)?.try_into().map_err(
            |_| {
                Error::Rejected(crate::RejectionReason::OperationRecord(
                    crate::OperationRecordRejection::RecordIntegerWidth,
                ))
            },
        )?))
    }
    pub(super) fn count(&mut self, maximum: usize) -> Result<usize> {
        let n = self.u32()? as usize;
        if n > maximum {
            return Err(Error::Rejected(crate::RejectionReason::OperationRecord(
                crate::OperationRecordRejection::RecordCount,
            )));
        }
        Ok(n)
    }
    pub(super) fn bytes(&mut self, maximum: usize) -> Result<&'a [u8]> {
        let n = usize::try_from(self.u64()?).map_err(|_| {
            Error::Rejected(crate::RejectionReason::OperationRecord(
                crate::OperationRecordRejection::RecordByteLength,
            ))
        })?;
        if n > maximum {
            return Err(Error::Rejected(crate::RejectionReason::OperationRecord(
                crate::OperationRecordRejection::RecordByteCeiling,
            )));
        }
        self.take(n)
    }
    pub(super) fn optional_bytes(&mut self, maximum: usize) -> Result<Option<&'a [u8]>> {
        match self.u8()? {
            0 => Ok(None),
            1 => Ok(Some(self.bytes(maximum)?)),
            _ => Err(Error::Rejected(crate::RejectionReason::OperationRecord(
                crate::OperationRecordRejection::RecordOption,
            ))),
        }
    }
    pub(super) fn optional_u64(&mut self) -> Result<Option<u64>> {
        match self.u8()? {
            0 => Ok(None),
            1 => Ok(Some(self.u64()?)),
            _ => Err(Error::Rejected(crate::RejectionReason::OperationRecord(
                crate::OperationRecordRejection::RecordOption,
            ))),
        }
    }
    pub(super) fn finish(self) -> Result<()> {
        if self.position == self.bytes.len() {
            Ok(())
        } else {
            Err(Error::Rejected(crate::RejectionReason::OperationRecord(
                crate::OperationRecordRejection::RecordTrailingBytes,
            )))
        }
    }
}
pub(super) fn decode(bytes: &[u8], limits: Limits) -> Result<(Kind, Reader<'_>)> {
    decode_with(bytes, limits, None)
}
pub(super) fn decode_with<'a>(
    bytes: &'a [u8],
    limits: Limits,
    graph_observer: GraphObserver<'a>,
) -> Result<(Kind, Reader<'a>)> {
    limits.validate()?;
    if bytes.len() > limits.bytes {
        return Err(Error::Rejected(crate::RejectionReason::OperationRecord(
            crate::OperationRecordRejection::RecordByteCeiling,
        )));
    }
    let mut reader = Reader {
        bytes,
        position: 0,
        graph_observer,
    };
    if reader.take(8)? != MAGIC {
        return Err(Error::Rejected(crate::RejectionReason::OperationRecord(
            crate::OperationRecordRejection::RecordVersion,
        )));
    }
    let kind = Kind::from_wire(reader.u8()?)?;
    let payload = usize::try_from(reader.u64()?).map_err(|_| {
        Error::Rejected(crate::RejectionReason::OperationRecord(
            crate::OperationRecordRejection::RecordByteLength,
        ))
    })?;
    if payload != bytes.len() - HEADER {
        return Err(Error::Rejected(crate::RejectionReason::OperationRecord(
            crate::OperationRecordRejection::RecordPayloadLength,
        )));
    }
    Ok((kind, reader))
}
