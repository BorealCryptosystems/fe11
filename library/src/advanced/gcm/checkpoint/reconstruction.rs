// SPDX-License-Identifier: Apache-2.0
//! Rebuild stable AEAD storage under the enclosing aggregate reservation.
//! Native state and key possession are restored separately by the caller.
use super::super::{
    input, output, storage_sum, AeadMessageOperation, AeadOutcome, AeadStep, Frame, GeneratedNonce,
    InitBinding, InitReference, InitializationSeed, NativeParameters, Output, Outputs,
    PreparedAead,
};
use crate::advanced::record::aead_messages as wire;
use crate::advanced::{
    aead_parameters::CipherKind, continuation::InputLayout, record, NativeActivity,
};
use crate::symmetric::memory::{Buffer, Credit, UnboundBuffer};
use crate::{bounds, Error, Result};
use fe11_sys::{CK_ASYNC_DATA, CK_MECHANISM, CK_ULONG};
use std::mem::size_of;

fn invalid() -> Error {
    Error::Rejected(crate::RejectionReason::AeadMessages(
        crate::AeadMessagesRejection::AeadStreamReconstruction,
    ))
}
fn slots<T>(count: usize) -> Result<usize> {
    count.checked_mul(size_of::<T>()).ok_or_else(invalid)
}
fn reserve<T>(count: usize) -> Result<Vec<T>> {
    let mut values = Vec::new();
    values.try_reserve_exact(count).map_err(|_| invalid())?;
    Ok(values)
}

/// Shared sizing for a borrowed live projection and a parsed archive. No
/// allocation, immutable selection clone or reconstruction occurs here.
pub(super) fn allocation_from_rows<'a>(
    kind: CipherKind,
    decrypt: bool,
    header: wire::Header<'a>,
    count: usize,
    rows: impl Iterator<Item = Result<wire::Row<'a>>>,
) -> Result<usize> {
    let mut total = storage_sum(&[
        size_of::<AeadMessageOperation>(),
        crate::error::CleanupDiagnostic::allocation_bytes(),
        crate::error::CompletionStorage::allocation_bytes(),
        input::DIAGNOSTIC_BYTES,
        size_of::<CK_MECHANISM>(),
        size_of::<CK_ASYNC_DATA>(),
        slots::<Frame>(count)?,
        slots::<Output>(count)?,
        slots::<RowStorage>(count)?,
        header.fragment.map_or(0, <[u8]>::len),
    ])?;
    if let wire::Initial::Shared {
        nonce, tag, seed, ..
    } = header.initial
    {
        total = storage_sum(&[
            total,
            size_of::<NativeParameters>(),
            nonce.len(),
            tag.len(),
            seed.map(|seed| seed.selection.plan(kind).map(|s| s.retained_bytes()))
                .transpose()?
                .unwrap_or(0),
            seed.and_then(|seed| seed.expected_tag)
                .map_or(0, <[u8]>::len),
        ])?;
    }
    for row in rows {
        let row = row?;
        let selection = row.selection.plan(kind)?;
        total = storage_sum(&[
            total,
            size_of::<NativeParameters>(),
            size_of::<CK_ULONG>(),
            selection.retained_bytes(),
            row.aad.len(),
            row.nonce.len(),
            row.tag.len(),
            row.expected_tag.map_or(0, <[u8]>::len),
            row.capacity,
            if !decrypt && selection.generated() {
                row.nonce.len()
            } else {
                0
            },
        ])?;
    }
    Ok(total)
}
fn copy(storage: UnboundBuffer, bytes: &[u8], prepaid: &mut Credit) -> Result<Buffer> {
    let mut value = storage.bind(prepaid)?;
    if value.capacity() != bytes.len() {
        return Err(invalid());
    }
    value.as_mut().copy_from_slice(bytes);
    Ok(value)
}
fn copy_optional(
    storage: Option<UnboundBuffer>,
    bytes: Option<&[u8]>,
    prepaid: &mut Credit,
) -> Result<Option<Buffer>> {
    match (storage, bytes) {
        (Some(storage), Some(bytes)) => copy(storage, bytes, prepaid).map(Some),
        (None, None) => Ok(None),
        _ => Err(invalid()),
    }
}

#[derive(Clone, Copy)]
pub(in crate::advanced) struct RecordPlan<'a> {
    descriptor: record::Descriptor,
    record: wire::Record<'a>,
    kind: CipherKind,
    decrypt: bool,
}
struct RowStorage {
    aad: UnboundBuffer,
    nonce: UnboundBuffer,
    tag: UnboundBuffer,
    expected_tag: Option<UnboundBuffer>,
    generated: Option<UnboundBuffer>,
    output: UnboundBuffer,
}
struct SharedStorage {
    nonce: UnboundBuffer,
    tag: UnboundBuffer,
    expected_seed_tag: Option<UnboundBuffer>,
}
pub(in crate::advanced) struct Storage<'a> {
    plan: RecordPlan<'a>,
    rows: Vec<RowStorage>,
    frames: Vec<Frame>,
    outputs: Vec<Output>,
    shared: Option<SharedStorage>,
    fragment: Option<UnboundBuffer>,
    cleanup_diagnostic: crate::error::CleanupDiagnostic,
    return_diagnostic: crate::error::CompletionStorage,
    // Keep all vector/selection credits until partially bound owners leave.
    owner: Option<Credit>,
    results: Option<Credit>,
    temporary: Option<Credit>,
}

impl<'a> RecordPlan<'a> {
    /// Recipe already checked cross-section consistency. Apply the current
    /// caller's limits to the one retained input, not discarded stream history.
    pub(in crate::advanced) fn new(
        descriptor: record::Descriptor,
        record: wire::Record<'a>,
        ceilings: crate::CryptoLimits,
        pending: bool,
    ) -> Result<Self> {
        if pending {
            return Err(Error::Rejected(crate::RejectionReason::CheckpointFormat(
                crate::CheckpointFormatRejection::CallerFedAeadAsynchronousModeUnavailable,
            )));
        }
        if let Some(bytes) = record.header.fragment {
            crate::InputLimits {
                maximum_parts: ceilings.maximum_parts,
                maximum_total_bytes: ceilings.maximum_total_bytes,
            }
            .validate(ceilings, &[bytes])?;
        }
        Ok(Self {
            descriptor,
            record,
            kind: CipherKind::from_mechanism(descriptor.mechanism)?,
            decrypt: descriptor.family == record::Family::MessageDecrypt,
        })
    }

    fn owner_bytes(&self, frames: usize) -> Result<usize> {
        let mut total = storage_sum(&[
            size_of::<AeadMessageOperation>(),
            crate::error::CleanupDiagnostic::allocation_bytes(),
            crate::error::CompletionStorage::allocation_bytes(),
            input::DIAGNOSTIC_BYTES,
            size_of::<CK_MECHANISM>(),
            size_of::<CK_ASYNC_DATA>(),
            slots::<Frame>(frames)?,
        ])?;
        for row in self.record.iter() {
            total = storage_sum(&[
                total,
                size_of::<NativeParameters>(),
                size_of::<CK_ULONG>(),
                row?.selection.plan(self.kind)?.retained_bytes(),
            ])?;
        }
        Ok(total)
    }

    fn shared_metadata(&self) -> Result<usize> {
        match self.record.header.initial {
            wire::Initial::None => Ok(0),
            wire::Initial::Shared { seed, .. } => storage_sum(&[
                size_of::<NativeParameters>(),
                seed.map(|seed| seed.selection.plan(self.kind).map(|s| s.retained_bytes()))
                    .transpose()?
                    .unwrap_or(0),
            ]),
        }
    }

    pub(in crate::advanced) fn allocation_bytes(&self) -> Result<usize> {
        allocation_from_rows(
            self.kind,
            self.decrypt,
            self.record.header,
            self.record.len(),
            self.record.iter(),
        )
    }

    pub(in crate::advanced) fn allocate(&self) -> Result<Storage<'a>> {
        let mut rows = reserve(self.record.len())?;
        for row in self.record.iter() {
            let row = row?;
            rows.push(RowStorage {
                aad: UnboundBuffer::allocate(row.aad.len())?,
                nonce: UnboundBuffer::allocate(row.nonce.len())?,
                tag: UnboundBuffer::allocate(row.tag.len())?,
                expected_tag: row
                    .expected_tag
                    .map(|tag| UnboundBuffer::allocate(tag.len()))
                    .transpose()?,
                generated: (!self.decrypt && row.selection.plan(self.kind)?.generated())
                    .then(|| UnboundBuffer::allocate(row.nonce.len()))
                    .transpose()?,
                output: UnboundBuffer::allocate(row.capacity)?,
            });
        }
        let shared = match self.record.header.initial {
            wire::Initial::None => None,
            wire::Initial::Shared {
                nonce, tag, seed, ..
            } => Some(SharedStorage {
                nonce: UnboundBuffer::allocate(nonce.len())?,
                tag: UnboundBuffer::allocate(tag.len())?,
                expected_seed_tag: seed
                    .and_then(|seed| seed.expected_tag)
                    .map(|tag| UnboundBuffer::allocate(tag.len()))
                    .transpose()?,
            }),
        };
        Ok(Storage {
            plan: *self,
            rows,
            frames: reserve(self.record.len())?,
            outputs: reserve(self.record.len())?,
            shared,
            fragment: self
                .record
                .header
                .fragment
                .map(|bytes| UnboundBuffer::allocate(bytes.len()))
                .transpose()?,
            cleanup_diagnostic: crate::error::CleanupDiagnostic::prepare_sequence()?,
            return_diagnostic: crate::error::CompletionStorage::allocate()?,
            owner: None,
            results: None,
            temporary: None,
        })
    }
}

impl Storage<'_> {
    pub(in crate::advanced) fn allocated_bytes(&self) -> Result<usize> {
        let mut total = storage_sum(&[
            self.plan.owner_bytes(self.frames.capacity())?,
            slots::<Output>(self.outputs.capacity())?,
            slots::<RowStorage>(self.rows.capacity())?,
            self.plan.shared_metadata()?,
            self.fragment.as_ref().map_or(0, UnboundBuffer::allocated),
        ])?;
        if let Some(shared) = &self.shared {
            total = storage_sum(&[
                total,
                shared.nonce.allocated(),
                shared.tag.allocated(),
                shared
                    .expected_seed_tag
                    .as_ref()
                    .map_or(0, UnboundBuffer::allocated),
            ])?;
        }
        for row in &self.rows {
            total = storage_sum(&[
                total,
                row.aad.allocated(),
                row.nonce.allocated(),
                row.tag.allocated(),
                row.expected_tag
                    .as_ref()
                    .map_or(0, UnboundBuffer::allocated),
                row.generated.as_ref().map_or(0, UnboundBuffer::allocated),
                row.output.allocated(),
            ])?;
        }
        Ok(total)
    }

    pub(in crate::advanced) fn bind(mut self, prepaid: &mut Credit) -> Result<PreparedAead> {
        self.owner = Some(prepaid.split(self.plan.owner_bytes(self.frames.capacity())?)?);
        self.results = Some(prepaid.split(slots::<Output>(self.outputs.capacity())?)?);
        self.temporary = Some(prepaid.split(slots::<RowStorage>(self.rows.capacity())?)?);
        let active = self.plan.record.header.boundary.index();
        for (index, (storage, row)) in self.rows.drain(..).zip(self.plan.record.iter()).enumerate()
        {
            let row = row?;
            let origin = row.selection.plan(self.plan.kind)?.materialize()?;
            let mut nonce = copy(storage.nonce, row.nonce, prepaid)?;
            let mut tag = copy(storage.tag, row.tag, prepaid)?;
            let params = Box::new(NativeParameters::new(
                &origin,
                row.declared_length,
                nonce.as_mut().as_mut_ptr(),
                tag.as_mut().as_mut_ptr(),
            )?);
            let mut bytes = storage.output.bind(prepaid)?;
            crate::advanced::reconstruction::output(&mut bytes, row.output, active != Some(index))?;
            let observed_nonce = match storage.generated {
                None => GeneratedNonce::NotGenerated,
                Some(storage) => match row.observed_nonce {
                    Some(nonce) => GeneratedNonce::Observed(copy(storage, nonce, prepaid)?),
                    None => GeneratedNonce::Awaiting(storage.bind(prepaid)?),
                },
            };
            self.outputs.push(Output {
                disposition: row.disposition,
                bytes,
                nonce,
                tag,
                tag_bits: origin.tag_bits(),
            });
            self.frames.push(Frame {
                params,
                aad: copy(storage.aad, row.aad, prepaid)?,
                inputs: Vec::new(),
                retirement: None,
                layout: InputLayout::from_owned_lengths(prepaid, Vec::new())?,
                length: Box::new(bounds::ck_length(row.native_length)?),
                expected: row.declared_length,
                used: row.output.len(),
                accepted_input: row.accepted_input,
                origin,
                observed_nonce,
                expected_tag: copy_optional(storage.expected_tag, row.expected_tag, prepaid)?,
            });
        }
        // Free the temporary allocation before its credit can wake a waiter.
        drop(std::mem::take(&mut self.rows));
        drop(self.temporary.take());
        let mut init = match (self.shared.take(), self.plan.record.header.initial) {
            (None, wire::Initial::None) => InitBinding::WithoutParameters,
            (
                Some(storage),
                wire::Initial::Shared {
                    target,
                    seed,
                    nonce,
                    tag,
                },
            ) => {
                let metadata = prepaid.split(self.plan.shared_metadata()?)?;
                let mut nonce = copy(storage.nonce, nonce, prepaid)?;
                let mut tag = copy(storage.tag, tag, prepaid)?;
                let seed = match seed {
                    Some(seed) => Some(InitializationSeed {
                        origin: seed.selection.plan(self.plan.kind)?.materialize()?,
                        declared_length: seed.declared_length,
                        expected_tag: copy_optional(
                            storage.expected_seed_tag,
                            seed.expected_tag,
                            prepaid,
                        )?,
                    }),
                    None => {
                        if storage.expected_seed_tag.is_some() {
                            return Err(invalid());
                        }
                        None
                    }
                };
                let (origin, declared) = match target {
                    wire::Target::Seed => {
                        let seed = seed.as_ref().ok_or_else(invalid)?;
                        (&seed.origin, seed.declared_length)
                    }
                    wire::Target::Message(index) => {
                        let frame = self.frames.get(index).ok_or_else(invalid)?;
                        (&frame.origin, frame.expected)
                    }
                };
                let params = Box::new(NativeParameters::new(
                    origin,
                    declared,
                    nonce.as_mut().as_mut_ptr(),
                    tag.as_mut().as_mut_ptr(),
                )?);
                InitBinding::Shared {
                    params,
                    nonce,
                    tag,
                    seed,
                    prepared_message: match target {
                        wire::Target::Seed => InitReference::Seed,
                        wire::Target::Message(index) => InitReference::Message(index),
                    },
                    _metadata: metadata,
                }
            }
            _ => return Err(invalid()),
        };
        let mut mechanism = Box::new(CK_MECHANISM {
            mechanism: self.plan.kind.mechanism(),
            pParameter: std::ptr::null_mut(),
            ulParameterLen: 0,
        });
        if let InitBinding::Shared {
            params, nonce, tag, ..
        } = &mut init
        {
            mechanism.pParameter = params.pointer_mut();
            mechanism.ulParameterLen = params.size();
            for frame in &mut self.frames {
                frame
                    .params
                    .bind(nonce.as_mut().as_mut_ptr(), tag.as_mut().as_mut_ptr());
            }
        }
        let step = match self.plan.record.header.boundary {
            wire::Boundary::Ready => AeadStep::Ready,
            wire::Boundary::Begin(index) => AeadStep::Begin(index),
            wire::Boundary::Receive(index) => AeadStep::Receive(index),
            wire::Boundary::Data(call) => call_step(call),
            wire::Boundary::Capacity {
                call,
                required,
                previous,
                prepared,
            } => AeadStep::Output(output::Pending::from_record(
                call_step(call),
                crate::advanced::CipherBufferRequest {
                    function: call.function(self.plan.decrypt),
                    code: fe11_sys::CKR_BUFFER_TOO_SMALL as u64,
                    required,
                    previous_capacity: previous,
                },
                prepared,
            )?),
            wire::Boundary::Finish => AeadStep::Finish,
        };
        Ok(PreparedAead {
            input: Some(input::Input::restored(
                self.plan.descriptor.input,
                copy_optional(
                    self.fragment.take(),
                    self.plan.record.header.fragment,
                    prepaid,
                )?,
            )),
            kind: self.plan.kind,
            route: self.plan.record.header.route,
            decrypt: self.plan.decrypt,
            outcome: AeadOutcome::Nominal,
            step,
            activity: NativeActivity::Active,
            mechanism,
            outputs: Some(Outputs {
                entries: std::mem::take(&mut self.outputs),
                init: init.layout()?,
                _credit: self.results.take().ok_or_else(invalid)?,
            }),
            init,
            frames: std::mem::take(&mut self.frames),
            restart_at: 0,
            completion: Box::new(crate::native::output::async_data()),
            name: [0; 32],
            cleanup_diagnostic: Some(self.cleanup_diagnostic),
            return_diagnostic: Some(self.return_diagnostic),
            _metadata: self.owner.take().ok_or_else(invalid)?,
        })
    }
}

fn call_step(call: wire::Call) -> AeadStep {
    match call {
        wire::Call::Single(index) => AeadStep::Single(index),
        wire::Call::Update(index) => AeadStep::StreamUpdate(index),
        wire::Call::Last(index) => AeadStep::StreamLast(index),
    }
}
