// SPDX-License-Identifier: Apache-2.0
//! Aggregate per-call allocation, followed by an allocation-free owner commit.
use super::{accounting, vector_bytes, Need, Submission};
use crate::advanced::{
    native_messages::{
        DataCall, Message, MessageOutput, NativeMessageOperation, Parameters, Phase,
        SignatureOutput,
    },
    validation,
};
use crate::mechanism_extension::{graph::GraphStorage, ExtensionParameters, OwnedGraph};
use crate::native::derivation::{InputBytes, InputBytesStorage};
use crate::symmetric::memory::{ControlledReservation, Credit, UnboundBuffer};
use crate::{bounds, ResourceAdmission, Result};
use fe11_sys::CK_ULONG;
use std::mem::size_of;

const NULL_PARAMETERS: ExtensionParameters<'static> = ExtensionParameters {
    blocks: &[],
    pointers: &[],
    root: None,
    outputs: &[],
};
fn sum(parts: &[usize]) -> Result<usize> {
    parts
        .iter()
        .try_fold(0usize, |total, part| total.checked_add(*part))
        .ok_or_else(accounting)
}
fn reserve<T>(capacity: usize) -> Result<Vec<T>> {
    let mut values = Vec::new();
    values
        .try_reserve_exact(capacity)
        .map_err(|_| accounting())?;
    Ok(values)
}

pub(super) struct Prepared {
    parameters: Option<Parameters>,
    input: Option<InputBytes>,
    signature: Option<InputBytes>,
    output: Option<SignatureOutput>,
    messages: Option<Vec<Message>>,
    parts: Option<Vec<Parameters>>,
    pub(super) report: Option<validation::PreparedReport>,
    parent_metadata: Credit,
    row_metadata: Credit,
}
struct RetiredVector<T> {
    _values: Vec<T>,
    _credit: Credit,
}
/// All retired vectors are empty, but keep their full allocated capacity and
/// charge together until the caller drops this value outside session possession.
pub(super) struct Retired {
    _messages: Option<RetiredVector<Message>>,
    _parts: Option<RetiredVector<Parameters>>,
}

impl Prepared {
    pub(super) fn prepare(
        budget: &std::sync::Arc<crate::symmetric::memory::Budget>,
        need: Need,
        submission: Submission<'_>,
        admission: &ResourceAdmission,
        mut before: impl FnMut() -> Result<()>,
    ) -> Result<Self> {
        let request = submission.parameters();
        let parameters = match submission {
            Submission::Begin(None) => None,
            _ => Some(request.map_or(NULL_PARAMETERS, |request| request.parameters)),
        };
        let output_capacity = submission.capacity();
        let output_bytes = output_capacity
            .map(|capacity| {
                crate::advanced::signature::output_storage_bytes(need.mechanism, capacity)
            })
            .transpose()?;
        let length_bytes = usize::from(output_capacity.is_some()) * size_of::<CK_ULONG>();
        let report_maximum = need
            .report
            .filter(|(_, bytes)| *bytes != 0)
            .map(|(maximum, _)| maximum);
        let inputs = submission
            .bytes()
            .map_or(0, <[u8]>::len)
            .checked_add(submission.signature().map_or(0, <[u8]>::len))
            .and_then(|bytes| bytes.checked_mul(2))
            .ok_or_else(accounting)?;
        let mut required = sum(&[
            parameters
                .as_ref()
                .map(OwnedGraph::allocation_bytes)
                .transpose()?
                .unwrap_or(0),
            inputs,
            output_bytes.unwrap_or(0),
            length_bytes,
            need.grow_messages
                .map(vector_bytes::<Message>)
                .transpose()?
                .unwrap_or(0),
            need.grow_parts
                .map(vector_bytes::<Parameters>)
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
            let graph = parameters
                .as_ref()
                .map(GraphStorage::allocate)
                .transpose()?;
            let input = submission
                .bytes()
                .map(|bytes| InputBytesStorage::allocate(bytes.len()))
                .transpose()?;
            let signature = submission
                .signature()
                .map(|bytes| InputBytesStorage::allocate(bytes.len()))
                .transpose()?;
            let output = output_bytes.map(UnboundBuffer::allocate).transpose()?;
            let messages = need.grow_messages.map(reserve::<Message>).transpose()?;
            let parts = need.grow_parts.map(reserve::<Parameters>).transpose()?;
            let report = report_maximum
                .map(validation::ReportStorage::allocate_growth)
                .transpose()?;
            let parent_bytes = messages
                .as_ref()
                .map(|values| vector_bytes::<Message>(values.capacity()))
                .transpose()?
                .unwrap_or(0);
            let row_bytes = sum(&[
                length_bytes,
                parts
                    .as_ref()
                    .map(|values| vector_bytes::<Parameters>(values.capacity()))
                    .transpose()?
                    .unwrap_or(0),
            ])?;
            let actual = sum(&[
                graph
                    .as_ref()
                    .map(GraphStorage::allocated_bytes)
                    .transpose()?
                    .unwrap_or(0),
                input
                    .as_ref()
                    .map(InputBytesStorage::allocated_bytes)
                    .transpose()?
                    .unwrap_or(0),
                signature
                    .as_ref()
                    .map(InputBytesStorage::allocated_bytes)
                    .transpose()?
                    .unwrap_or(0),
                output.as_ref().map_or(0, UnboundBuffer::allocated),
                report
                    .as_ref()
                    .map(validation::ReportStorage::allocated_bytes)
                    .transpose()?
                    .unwrap_or(0),
                parent_bytes,
                row_bytes,
            ])?;
            if actual > required {
                drop(graph);
                drop(input);
                drop(signature);
                drop(output);
                drop(messages);
                drop(parts);
                drop(report);
                drop(prepaid);
                required = actual;
                continue;
            }
            prepaid.release(required - actual);
            let parameters = graph
                .map(|graph| -> Result<_> {
                    Ok(Parameters {
                        graph: Box::new(graph.bind(&mut prepaid)?),
                        contract: request.map(|request| request.contract.clone()),
                    })
                })
                .transpose()?;
            let input = input
                .zip(submission.bytes())
                .map(|(storage, bytes)| storage.bind(bytes, &mut prepaid))
                .transpose()?;
            let signature = signature
                .zip(submission.signature())
                .map(|(storage, bytes)| storage.bind(bytes, &mut prepaid))
                .transpose()?;
            let output = output
                .zip(output_capacity)
                .map(|(storage, capacity)| -> Result<_> {
                    let mut bytes = storage.bind(&mut prepaid)?;
                    let offset =
                        crate::advanced::signature::output_offset(need.mechanism, &mut bytes)?;
                    Ok(SignatureOutput {
                        bytes,
                        offset,
                        capacity,
                        produced: None,
                        length: Box::new(bounds::ck_length(capacity)?),
                    })
                })
                .transpose()?;
            let report = report
                .map(|storage| storage.bind(&mut prepaid))
                .transpose()?;
            return Ok(Self {
                parameters,
                input,
                signature,
                output,
                messages,
                parts,
                report,
                parent_metadata: prepaid.split(parent_bytes)?,
                row_metadata: prepaid.split(row_bytes)?,
            });
        }
    }

    /// Plan/report/owner revisions must be rechecked under the same possession
    /// immediately before this transition. All appends fit prepared capacities;
    /// no native call, allocation or resource wait occurs here.
    pub(super) fn commit(
        mut self,
        body: &mut NativeMessageOperation,
        need: Need,
        submission: Submission<'_>,
    ) -> Retired {
        assert!(
            self.report.is_none(),
            "prepared observation report not committed"
        );
        let old_messages = self.messages.take().map(|mut messages| {
            let credit = body
                ._metadata
                .split(need.old_messages_bytes)
                .expect("existing message vector capacity is credited");
            messages.append(&mut body.messages);
            std::mem::swap(&mut messages, &mut body.messages);
            RetiredVector {
                _values: messages,
                _credit: credit,
            }
        });
        body._metadata
            .merge(self.parent_metadata)
            .expect("same message budget");
        let index = if need.new_message {
            body.messages.push(Message {
                rejection: None,
                begin: None,
                parts: Vec::new(),
                output: if need.verify {
                    MessageOutput::Verify { verdict: None }
                } else {
                    MessageOutput::Sign(None)
                },
                _metadata: self.row_metadata,
            });
            need.messages
        } else {
            let index = need.messages - 1;
            body.messages[index]
                ._metadata
                .merge(self.row_metadata)
                .expect("same message budget");
            index
        };
        let message = &mut body.messages[index];
        let old_parts = self.parts.take().map(|mut parts| {
            let credit = message
                ._metadata
                .split(need.old_parts_bytes)
                .expect("existing parameter vector capacity is credited");
            parts.append(&mut message.parts);
            std::mem::swap(&mut parts, &mut message.parts);
            RetiredVector {
                _values: parts,
                _credit: credit,
            }
        });
        if let Some(output) = self.output.take() {
            assert!(
                matches!(message.output, MessageOutput::Sign(None)),
                "terminal output not empty"
            );
            message.output = MessageOutput::Sign(Some(output));
        }
        match submission {
            Submission::Begin(_) => {
                message.begin = self.parameters.take();
                body.phase = Phase::Begin(index);
            }
            Submission::Data { kind, .. } => {
                message
                    .parts
                    .push(self.parameters.take().expect("prepared data parameters"));
                body.phase = Phase::Data(DataCall {
                    message: index,
                    part: need.parts,
                    kind,
                    bytes: self.input.take().expect("prepared data input"),
                    signature: self.signature.take(),
                });
            }
        }
        // Report storage is consumed by the enclosing observation commit first;
        // dropping an unconsumed report under possession would be a caller bug.
        Retired {
            _messages: old_messages,
            _parts: old_parts,
        }
    }
}
