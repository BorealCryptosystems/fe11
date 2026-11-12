// SPDX-License-Identifier: Apache-2.0
//! Aggregate admission for one fragment and, when needed, one AEAD message row.
use super::super::{
    storage_sum, AeadMessageOperation, Frame, GeneratedNonce, InitBinding, NativeParameters, Output,
};
use super::{Message, Need, Submission};
use crate::advanced::continuation::InputLayout;
use crate::symmetric::memory::{Buffer, ControlledReservation, Credit, UnboundBuffer};
use crate::{bounds, Error, ResourceAdmission, Result};
use fe11_sys::CK_ULONG;
use std::mem::size_of;

pub(super) fn vector_bytes<T>(values: &Vec<T>) -> Result<usize> {
    values
        .capacity()
        .checked_mul(size_of::<T>())
        .ok_or(Error::Rejected(crate::RejectionReason::AeadMessages(
            crate::AeadMessagesRejection::AeadTableSizeOverflow,
        )))
}
fn reserve<T>(count: usize) -> Result<Vec<T>> {
    let mut values = Vec::new();
    values.try_reserve_exact(count).map_err(|_| {
        Error::Rejected(crate::RejectionReason::AeadMessages(
            crate::AeadMessagesRejection::AeadTableAllocation,
        ))
    })?;
    Ok(values)
}

struct Tables {
    frames: Vec<Frame>,
    outputs: Vec<Output>,
}
impl Tables {
    fn requested(count: usize) -> Result<usize> {
        count
            .checked_mul(size_of::<Frame>() + size_of::<Output>())
            .ok_or(Error::Rejected(crate::RejectionReason::AeadMessages(
                crate::AeadMessagesRejection::AeadTableSizeOverflow,
            )))
    }
    fn allocate(count: usize) -> Result<Self> {
        Ok(Self {
            frames: reserve(count)?,
            outputs: reserve(count)?,
        })
    }
    fn allocated(&self) -> Result<usize> {
        storage_sum(&[vector_bytes(&self.frames)?, vector_bytes(&self.outputs)?])
    }
}

struct Row {
    aad: UnboundBuffer,
    output: UnboundBuffer,
    nonce: UnboundBuffer,
    tag: UnboundBuffer,
    expected_tag: Option<UnboundBuffer>,
    generated: Option<UnboundBuffer>,
}
impl Row {
    fn metadata(message: Message<'_>) -> Result<usize> {
        storage_sum(&[
            size_of::<NativeParameters>(),
            size_of::<CK_ULONG>(),
            message.origin.retained_bytes(),
        ])
    }
    fn requested(message: Message<'_>, generated: bool) -> Result<usize> {
        storage_sum(&[
            message.aad.len(),
            message.output_capacity,
            message.origin.iv().len(),
            message.origin.tag_bytes()?,
            message.expected_tag.map_or(0, <[u8]>::len),
            if generated {
                message.origin.iv().len()
            } else {
                0
            },
        ])
    }
    fn allocate(message: Message<'_>, generated: bool) -> Result<Self> {
        Ok(Self {
            aad: UnboundBuffer::allocate(message.aad.len())?,
            output: UnboundBuffer::allocate(message.output_capacity)?,
            nonce: UnboundBuffer::allocate(message.origin.iv().len())?,
            tag: UnboundBuffer::allocate(message.origin.tag_bytes()?)?,
            expected_tag: message
                .expected_tag
                .map(|tag| UnboundBuffer::allocate(tag.len()))
                .transpose()?,
            generated: generated
                .then(|| UnboundBuffer::allocate(message.origin.iv().len()))
                .transpose()?,
        })
    }
    fn allocated(&self) -> Result<usize> {
        storage_sum(&[
            self.aad.allocated(),
            self.output.allocated(),
            self.nonce.allocated(),
            self.tag.allocated(),
            self.expected_tag
                .as_ref()
                .map_or(0, UnboundBuffer::allocated),
            self.generated.as_ref().map_or(0, UnboundBuffer::allocated),
        ])
    }
    fn bind(self, message: Message<'_>, prepaid: &mut Credit) -> Result<(Frame, Output)> {
        let mut aad = self.aad.bind(prepaid)?;
        aad.as_mut().copy_from_slice(message.aad);
        let mut nonce = self.nonce.bind(prepaid)?;
        nonce.as_mut().copy_from_slice(message.origin.iv());
        let mut tag = self.tag.bind(prepaid)?;
        let expected_tag = self
            .expected_tag
            .map(|storage| -> Result<_> {
                let bytes = message.expected_tag.expect("validated AEAD input tag");
                let mut expected = storage.bind(prepaid)?;
                expected.as_mut().copy_from_slice(bytes);
                tag.as_mut().copy_from_slice(bytes);
                Ok(expected)
            })
            .transpose()?;
        let generated = self
            .generated
            .map(|storage| storage.bind(prepaid))
            .transpose()?;
        let params = Box::new(NativeParameters::new(
            message.origin,
            message.declared_length,
            nonce.as_mut().as_mut_ptr(),
            tag.as_mut().as_mut_ptr(),
        )?);
        let output = Output {
            disposition: crate::advanced::gcm::result::Disposition::Candidate,
            bytes: self.output.bind(prepaid)?,
            nonce,
            tag,
            tag_bits: message.origin.tag_bits(),
        };
        let frame = Frame {
            params,
            aad,
            inputs: Vec::new(),
            retirement: None,
            layout: InputLayout::from_owned_lengths(prepaid, Vec::new())?,
            length: Box::new(bounds::ck_length(message.output_capacity)?),
            expected: message.declared_length,
            used: 0,
            accepted_input: Some(0),
            origin: message.origin.clone(),
            observed_nonce: generated
                .map_or(GeneratedNonce::NotGenerated, GeneratedNonce::Awaiting),
            expected_tag,
        };
        Ok((frame, output))
    }
}

pub(super) struct Prepared {
    fragment: Option<Buffer>,
    last_tag: Option<Buffer>,
    row: Option<(Frame, Output)>,
    tables: Option<(Tables, Credit)>,
    metadata: Credit,
    pub(super) report: Option<crate::advanced::validation::PreparedReport>,
}
pub(super) struct Retired {
    _tag: Option<Buffer>,
    _tables: Option<Tables>,
    _metadata: Option<Credit>,
    _results: Option<Credit>,
}

impl Prepared {
    pub(super) fn prepare(
        budget: &std::sync::Arc<crate::symmetric::memory::Budget>,
        need: Need,
        submission: Submission<'_>,
        admission: &ResourceAdmission,
        mut before: impl FnMut() -> Result<()>,
    ) -> Result<Self> {
        let message = submission.message();
        let row_metadata = message.map(Row::metadata).transpose()?.unwrap_or(0);
        let mut required = storage_sum(&[
            submission.bytes().map_or(0, <[u8]>::len),
            submission.last_tag().map_or(0, <[u8]>::len),
            row_metadata,
            message
                .map(|message| Row::requested(message, need.generated_nonce))
                .transpose()?
                .unwrap_or(0),
            need.grow.map(Tables::requested).transpose()?.unwrap_or(0),
            need.report.map_or(0, |(_, bytes)| bytes),
        ])?;
        loop {
            let mut prepaid = match budget
                .reserve_controlled_retaining::<std::convert::Infallible>(
                    required,
                    crate::session::lifecycle_diagnostics::Store::allocation_bytes(),
                    admission,
                    || {
                        before()?;
                        Ok(None)
                    },
                    || Ok(None),
                )? {
                ControlledReservation::Acquired(credit) => credit,
                ControlledReservation::Redirect(never) => match never {},
            };
            let fragment = submission
                .bytes()
                .map(|bytes| UnboundBuffer::allocate(bytes.len()))
                .transpose()?;
            let last_tag = submission
                .last_tag()
                .map(|tag| UnboundBuffer::allocate(tag.len()))
                .transpose()?;
            let row = message
                .map(|message| Row::allocate(message, need.generated_nonce))
                .transpose()?;
            let tables = need.grow.map(Tables::allocate).transpose()?;
            let report = need
                .report
                .filter(|(_, bytes)| *bytes != 0)
                .map(|(maximum, _)| {
                    crate::advanced::validation::ReportStorage::allocate_growth(maximum)
                })
                .transpose()?;
            let metadata_bytes = storage_sum(&[
                row_metadata,
                tables
                    .as_ref()
                    .map(|tables| vector_bytes(&tables.frames))
                    .transpose()?
                    .unwrap_or(0),
            ])?;
            let actual = storage_sum(&[
                row_metadata,
                fragment.as_ref().map_or(0, UnboundBuffer::allocated),
                last_tag.as_ref().map_or(0, UnboundBuffer::allocated),
                row.as_ref().map(Row::allocated).transpose()?.unwrap_or(0),
                tables
                    .as_ref()
                    .map(Tables::allocated)
                    .transpose()?
                    .unwrap_or(0),
                report
                    .as_ref()
                    .map(crate::advanced::validation::ReportStorage::allocated_bytes)
                    .transpose()?
                    .unwrap_or(0),
            ])?;
            if actual > required {
                drop(fragment);
                drop(last_tag);
                drop(row);
                drop(tables);
                drop(report);
                drop(prepaid);
                required = actual;
                continue;
            }
            prepaid.release(required - actual);
            let fragment = fragment
                .map(|part| -> Result<_> {
                    let mut part = part.bind(&mut prepaid)?;
                    part.as_mut()
                        .copy_from_slice(submission.bytes().expect("prepared AEAD fragment"));
                    Ok(part)
                })
                .transpose()?;
            let last_tag = last_tag
                .map(|storage| -> Result<_> {
                    let mut tag = storage.bind(&mut prepaid)?;
                    tag.as_mut()
                        .copy_from_slice(submission.last_tag().expect("prepared final AEAD tag"));
                    Ok(tag)
                })
                .transpose()?;
            let row = row
                .map(|row| row.bind(message.expect("prepared AEAD row"), &mut prepaid))
                .transpose()?;
            let tables = tables
                .map(|tables| -> Result<_> {
                    let credit = prepaid.split(vector_bytes(&tables.outputs)?)?;
                    Ok((tables, credit))
                })
                .transpose()?;
            let report = report.map(|report| report.bind(&mut prepaid)).transpose()?;
            return Ok(Self {
                fragment,
                last_tag,
                row,
                tables,
                metadata: prepaid.split(metadata_bytes)?,
                report,
            });
        }
    }

    /// All sizes, report changes and current ownership were checked under this
    /// same possession. This transfer cannot allocate, wait or enter native code.
    pub(super) fn commit(
        mut self,
        body: &mut AeadMessageOperation,
        need: Need,
        submission: Submission<'_>,
    ) -> Retired {
        let outputs = body.outputs.as_mut().expect("checked AEAD outputs");
        let mut retired = Retired {
            _tag: None,
            _tables: None,
            _metadata: None,
            _results: None,
        };
        if let Some((mut tables, results)) = self.tables.take() {
            retired._metadata = Some(
                body._metadata
                    .split(need.old_metadata)
                    .expect("credited AEAD frame table"),
            );
            tables.frames.append(&mut body.frames);
            tables.outputs.append(&mut outputs.entries);
            std::mem::swap(&mut tables.frames, &mut body.frames);
            std::mem::swap(&mut tables.outputs, &mut outputs.entries);
            retired._tables = Some(tables);
            retired._results = Some(std::mem::replace(&mut outputs._credit, results));
        }
        body._metadata
            .merge(self.metadata)
            .expect("same AEAD budget");
        let index = if let Some((mut frame, output)) = self.row {
            if let InitBinding::Shared { nonce, tag, .. } = &mut body.init {
                frame
                    .params
                    .bind(nonce.as_mut().as_mut_ptr(), tag.as_mut().as_mut_ptr());
            }
            body.frames.push(frame);
            outputs.entries.push(output);
            need.rows
        } else {
            need.rows - 1
        };
        if let Some(tag) = self.last_tag {
            // Only a returned, idle message can reach this transition. Keep the
            // native tag address stable while supplying the caller's final tag.
            outputs.entries[index]
                .tag
                .as_mut()
                .copy_from_slice(tag.as_slice());
            if let InitBinding::Shared { tag: target, .. } = &mut body.init {
                target.as_mut().copy_from_slice(tag.as_slice());
            }
            retired._tag = body.frames[index].expected_tag.replace(tag);
        }
        body.input.as_mut().expect("checked AEAD stream").fragment = self.fragment;
        body.step = submission.step(index);
        retired
    }
}
