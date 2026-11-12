// SPDX-License-Identifier: Apache-2.0
//! One aggregate reservation for a message transition, before taking possession.
use super::{MacOperation, Need, Submission};
use crate::advanced::{continuation::InputLayout, validation};
use crate::symmetric::memory::{Buffer, ControlledReservation, Credit, UnboundBuffer};
use crate::{bounds, Error, ResourceAdmission, Result};
use fe11_sys::CK_ULONG;
use std::mem::size_of;

pub(super) fn sum(parts: &[usize]) -> Result<usize> {
    parts
        .iter()
        .try_fold(0usize, |n, part| n.checked_add(*part))
        .ok_or(Error::Rejected(crate::RejectionReason::SignatureMessages(
            crate::SignatureMessagesRejection::MessageInputStorageOverflow,
        )))
}
pub(super) fn vector_bytes<T>(values: &Vec<T>) -> Result<usize> {
    values
        .capacity()
        .checked_mul(size_of::<T>())
        .ok_or(Error::Rejected(crate::RejectionReason::SignatureMessages(
            crate::SignatureMessagesRejection::MessageVectorStorageOverflow,
        )))
}
fn reserve<T>(count: usize) -> Result<Vec<T>> {
    let mut values = Vec::new();
    values.try_reserve_exact(count).map_err(|_| {
        Error::Rejected(crate::RejectionReason::SignatureMessages(
            crate::SignatureMessagesRejection::MessageVectorAllocation,
        ))
    })?;
    Ok(values)
}

struct Tables {
    inputs: Vec<Vec<Buffer>>,
    layouts: Vec<InputLayout>,
    lengths: Vec<Box<CK_ULONG>>,
    outputs: Vec<Buffer>,
    rejections: Vec<Option<crate::NativeMessageRejection>>,
}
impl Tables {
    fn requested_bytes(capacity: usize) -> Result<usize> {
        capacity
            .checked_mul(
                size_of::<Vec<Buffer>>()
                    + size_of::<InputLayout>()
                    + size_of::<Box<CK_ULONG>>()
                    + size_of::<Buffer>()
                    + size_of::<Option<crate::NativeMessageRejection>>(),
            )
            .ok_or(Error::Rejected(crate::RejectionReason::SignatureMessages(
                crate::SignatureMessagesRejection::MessageVectorStorageOverflow,
            )))
    }
    fn allocate(capacity: usize) -> Result<Self> {
        Ok(Self {
            inputs: reserve(capacity)?,
            layouts: reserve(capacity)?,
            lengths: reserve(capacity)?,
            outputs: reserve(capacity)?,
            rejections: reserve(capacity)?,
        })
    }
    fn metadata_bytes(&self) -> Result<usize> {
        sum(&[
            vector_bytes(&self.inputs)?,
            vector_bytes(&self.layouts)?,
            vector_bytes(&self.lengths)?,
        ])
    }
    fn allocated_bytes(&self) -> Result<usize> {
        sum(&[
            self.metadata_bytes()?,
            vector_bytes(&self.outputs)?,
            vector_bytes(&self.rejections)?,
        ])
    }
}

pub(super) struct Prepared {
    fragment: Option<Buffer>,
    output: Option<Buffer>,
    row: Option<(InputLayout, Box<CK_ULONG>)>,
    tables: Option<(Tables, Credit)>,
    metadata: Credit,
    pub(super) report: Option<validation::PreparedReport>,
}

struct RetiredTables {
    _tables: Tables,
    _metadata: Credit,
    _results: Credit,
}
/// Empty old tables and replaced input are destroyed only after all guards.
pub(super) struct Retired {
    _tables: Option<RetiredTables>,
    _output: Option<Buffer>,
}

impl Prepared {
    pub(super) fn prepare(
        budget: &std::sync::Arc<crate::symmetric::memory::Budget>,
        need: Need,
        submission: Submission<'_>,
        admission: &ResourceAdmission,
        mut before: impl FnMut() -> Result<()>,
    ) -> Result<Self> {
        let new_row = submission.starts_message();
        let report_maximum = need
            .report
            .filter(|(_, bytes)| *bytes != 0)
            .map(|(maximum, _)| maximum);
        let mut required = sum(&[
            submission.bytes().map_or(0, <[u8]>::len),
            need.output.unwrap_or(0),
            usize::from(new_row) * size_of::<CK_ULONG>(),
            need.grow
                .map(Tables::requested_bytes)
                .transpose()?
                .unwrap_or(0),
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
            let output = need.output.map(UnboundBuffer::allocate).transpose()?;
            let tables = need.grow.map(Tables::allocate).transpose()?;
            let report = report_maximum
                .map(validation::ReportStorage::allocate_growth)
                .transpose()?;
            let length = if new_row {
                Some(Box::new(bounds::ck_length(need.output.unwrap_or(0))?))
            } else {
                None
            };
            let metadata_bytes = sum(&[
                usize::from(new_row) * size_of::<CK_ULONG>(),
                tables
                    .as_ref()
                    .map(Tables::metadata_bytes)
                    .transpose()?
                    .unwrap_or(0),
            ])?;
            let actual = sum(&[
                fragment.as_ref().map_or(0, UnboundBuffer::allocated),
                output.as_ref().map_or(0, UnboundBuffer::allocated),
                usize::from(new_row) * size_of::<CK_ULONG>(),
                tables
                    .as_ref()
                    .map(Tables::allocated_bytes)
                    .transpose()?
                    .unwrap_or(0),
                report
                    .as_ref()
                    .map(validation::ReportStorage::allocated_bytes)
                    .transpose()?
                    .unwrap_or(0),
            ])?;
            if actual > required {
                // Drop every provisional owner and credit before waiting again.
                drop(fragment);
                drop(output);
                drop(tables);
                drop(report);
                drop(length);
                drop(prepaid);
                required = actual;
                continue;
            }
            prepaid.release(required - actual);
            let fragment = fragment
                .map(|part| -> Result<_> {
                    let mut part = part.bind(&mut prepaid)?;
                    part.as_mut()
                        .copy_from_slice(submission.bytes().expect("prepared input"));
                    Ok(part)
                })
                .transpose()?;
            let output = output
                .map(|value| -> Result<_> {
                    let mut value = value.bind(&mut prepaid)?;
                    if let Some(expected) = submission.expected() {
                        value.as_mut().copy_from_slice(expected);
                    } else {
                        value.set_length(0)?;
                    }
                    Ok(value)
                })
                .transpose()?;
            let report = report.map(|value| value.bind(&mut prepaid)).transpose()?;
            let tables = tables
                .map(|value| -> Result<_> {
                    let results = prepaid.split(sum(&[
                        vector_bytes(&value.outputs)?,
                        vector_bytes(&value.rejections)?,
                    ])?)?;
                    Ok((value, results))
                })
                .transpose()?;
            let row = length
                .map(|length| -> Result<_> {
                    Ok((
                        InputLayout::from_owned_lengths(&mut prepaid, Vec::new())?,
                        length,
                    ))
                })
                .transpose()?;
            return Ok(Self {
                fragment,
                output,
                row,
                tables,
                metadata: prepaid.split(metadata_bytes)?,
                report,
            });
        }
    }

    /// Need was revalidated under the same possession immediately before this
    /// transition. All destination capacities are reserved; moving vectors or
    /// Boxes never moves the native buffers/cells they own. No native call here.
    pub(super) fn commit(
        mut self,
        body: &mut MacOperation,
        need: Need,
        submission: Submission<'_>,
    ) -> Retired {
        let signatures = body.signatures.as_mut().expect("checked message results");
        let old_tables = self.tables.take().map(|(mut tables, results)| {
            // The original metadata owns these exact vector capacities. Moving
            // their credit with the empty old vectors avoids a release under guard.
            let metadata = body
                ._metadata
                .split(need.old_metadata)
                .expect("existing message vector capacities are credited");
            tables.inputs.append(&mut body.inputs);
            tables.layouts.append(&mut body.layouts);
            tables.lengths.append(&mut body.lengths);
            tables.outputs.append(&mut signatures.bytes);
            tables.rejections.append(&mut signatures.rejections);
            std::mem::swap(&mut tables.inputs, &mut body.inputs);
            std::mem::swap(&mut tables.layouts, &mut body.layouts);
            std::mem::swap(&mut tables.lengths, &mut body.lengths);
            std::mem::swap(&mut tables.outputs, &mut signatures.bytes);
            std::mem::swap(&mut tables.rejections, &mut signatures.rejections);
            RetiredTables {
                _tables: tables,
                _metadata: metadata,
                _results: std::mem::replace(&mut signatures._metadata, results),
            }
        });
        // Same session budget, with both charges already included in its checked
        // total. The merge cannot fail without a broken internal ownership invariant.
        body._metadata
            .merge(self.metadata)
            .expect("message input credit belongs to this budget");
        let index = if let Some((layout, length)) = self.row {
            signatures.rejections.push(None);
            body.inputs.push(Vec::new());
            body.layouts.push(layout);
            body.lengths.push(length);
            signatures
                .bytes
                .push(self.output.take().expect("prepared new message output"));
            need.rows
        } else {
            need.rows - 1
        };
        let old_output = self.output.take().map(|output| {
            *body.lengths[index] = output.as_slice().len() as CK_ULONG;
            std::mem::replace(&mut signatures.bytes[index], output)
        });
        body.stream_fragment = self.fragment;
        body.step = submission.step(index);
        Retired {
            _tables: old_tables,
            _output: old_output,
        }
    }
}
