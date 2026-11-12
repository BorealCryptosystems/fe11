// SPDX-License-Identifier: Apache-2.0
//! Borrowed message descriptions and retained outputs; never native pointers.
//! Decoding a stored output does not establish its authentication or provenance.
use super::{Limits, Reader, Writer};
use crate::advanced::MessageRoute;
use crate::{Error, Result};

#[derive(Clone, Copy, PartialEq, Eq)]
pub(in crate::advanced) enum NonceOrigin {
    None,
    Provided,
    Backend,
}
#[derive(Clone, Copy, PartialEq, Eq)]
pub(in crate::advanced) enum MessageState {
    Planned,
    Engaged,
    Finished,
}
#[derive(Clone, Copy)]
pub(in crate::advanced) struct Parameters<'a> {
    pub digest_output: Option<super::digest_output::DigestOutput>,
    pub cipher_extension: Option<super::cipher_extension::CipherExtension<'a>>,
    pub digest_extension: Option<super::digest_extension::DigestExtension<'a>>,
    pub signature: Option<super::signature::SignatureParameters<'a>>,
    pub message_init: Option<crate::MessageInitLayout>,
    pub counter_bits: Option<u64>,
    pub nonce: Option<&'a [u8]>,
    pub aad: Option<&'a [u8]>,
    pub digest_oid: Option<&'a [u8]>,
    pub tag_bits: u32,
    pub iv_generator: Option<u64>,
    pub iv_fixed_bits: Option<u64>,
    pub iv_initial: Option<&'a [u8]>,
    pub hash: Option<u64>,
    pub mgf: Option<u64>,
    pub salt: Option<u64>,
}
impl<'a> Parameters<'a> {
    pub(in crate::advanced) fn write(&self, w: &mut Writer<'_>) -> Result<()> {
        w.optional_bytes(self.nonce)?;
        w.optional_bytes(self.aad)?;
        w.u32(self.tag_bits)?;
        w.optional_u64(self.hash)?;
        w.optional_u64(self.mgf)?;
        w.optional_u64(self.salt)?;
        w.optional_u64(self.iv_generator)?;
        w.optional_u64(self.iv_fixed_bits)?;
        w.optional_bytes(self.iv_initial)?;
        w.u8(match self.message_init {
            None => 0,
            Some(crate::MessageInitLayout::InitWithoutParameters) => 1,
            Some(crate::MessageInitLayout::InitWithOwnedMessageParameters) => 2,
        })?;
        w.optional_u64(self.counter_bits)?;
        w.optional_bytes(self.digest_oid)?;
        match self.signature {
            None => w.u8(0),
            Some(parameters) => {
                w.u8(1)?;
                parameters.write(w)
            }
        }?;
        match self.digest_extension {
            None => w.u8(0),
            Some(parameters) => {
                w.u8(1)?;
                parameters.write(w)
            }
        }?;
        match self.cipher_extension {
            None => w.u8(0),
            Some(parameters) => {
                w.u8(1)?;
                parameters.write(w)
            }
        }?;
        match self.digest_output {
            None => w.u8(0),
            Some(output) => {
                w.u8(1)?;
                output.write(w)
            }
        }
    }
    pub(in crate::advanced) fn read(r: &mut Reader<'a>, limits: Limits) -> Result<Self> {
        Ok(Self {
            nonce: r.optional_bytes(limits.bytes)?,
            aad: r.optional_bytes(limits.bytes)?,
            tag_bits: r.u32()?,
            hash: r.optional_u64()?,
            mgf: r.optional_u64()?,
            salt: r.optional_u64()?,
            iv_generator: r.optional_u64()?,
            iv_fixed_bits: r.optional_u64()?,
            iv_initial: r.optional_bytes(limits.bytes)?,
            message_init: match r.u8()? {
                0 => None,
                1 => Some(crate::MessageInitLayout::InitWithoutParameters),
                2 => Some(crate::MessageInitLayout::InitWithOwnedMessageParameters),
                _ => {
                    return Err(Error::Rejected(crate::RejectionReason::MessageRecord(
                        crate::MessageRecordRejection::RecordMessageInitLayout,
                    )))
                }
            },
            counter_bits: r.optional_u64()?,
            digest_oid: r.optional_bytes(limits.bytes)?,
            signature: if r.boolean(crate::RejectionReason::MessageRecord(
                crate::MessageRecordRejection::SignatureRecordParameters,
            ))? {
                Some(super::signature::SignatureParameters::read(r, limits)?)
            } else {
                None
            },
            digest_extension: if r.boolean(crate::RejectionReason::MessageRecord(
                crate::MessageRecordRejection::DigestExtensionParameters,
            ))? {
                Some(super::digest_extension::DigestExtension::read(r, limits)?)
            } else {
                None
            },
            cipher_extension: if r.boolean(crate::RejectionReason::MessageRecord(
                crate::MessageRecordRejection::CipherExtensionParameters,
            ))? {
                Some(super::cipher_extension::CipherExtension::read(r, limits)?)
            } else {
                None
            },
            digest_output: if r.boolean(crate::RejectionReason::MessageRecord(
                crate::MessageRecordRejection::DigestOutputStorage,
            ))? {
                Some(super::digest_output::DigestOutput::read(r)?)
            } else {
                None
            },
        })
    }
}
#[derive(Clone, Copy)]
pub(in crate::advanced) enum Fragments<'a> {
    Slices(&'a [&'a [u8]]),
    Buffers(&'a [crate::symmetric::memory::Buffer]),
    Packed {
        bytes: &'a [u8],
        lengths: &'a [usize],
    },
    Encoded {
        bytes: &'a [u8],
        count: usize,
        maximum: usize,
    },
}
impl<'a> Fragments<'a> {
    pub(in crate::advanced) fn len(&self) -> usize {
        match self {
            Self::Slices(s) => s.len(),
            Self::Buffers(s) => s.len(),
            Self::Packed { lengths, .. } => lengths.len(),
            Self::Encoded { count, .. } => *count,
        }
    }
    pub(in crate::advanced) fn iter(self) -> FragmentIter<'a> {
        match self {
            Self::Slices(s) => FragmentIter::Slices(s.iter()),
            Self::Buffers(s) => FragmentIter::Buffers(s.iter()),
            Self::Packed { bytes, lengths } => FragmentIter::Packed {
                bytes,
                lengths: lengths.iter(),
                offset: 0,
            },
            Self::Encoded {
                bytes,
                count,
                maximum,
            } => FragmentIter::Encoded {
                reader: Reader {
                    graph_observer: None,
                    bytes,
                    position: 0,
                },
                remaining: count,
                maximum,
            },
        }
    }
    fn read(r: &mut Reader<'a>, limits: Limits) -> Result<Self> {
        let count = r.count(limits.fragments)?;
        let start = r.position;
        for _ in 0..count {
            r.bytes(limits.bytes)?;
        }
        Ok(Self::Encoded {
            bytes: &r.bytes[start..r.position],
            count,
            maximum: limits.bytes,
        })
    }
}
pub(in crate::advanced) enum FragmentIter<'a> {
    Slices(std::slice::Iter<'a, &'a [u8]>),
    Buffers(std::slice::Iter<'a, crate::symmetric::memory::Buffer>),
    Packed {
        bytes: &'a [u8],
        lengths: std::slice::Iter<'a, usize>,
        offset: usize,
    },
    Encoded {
        reader: Reader<'a>,
        remaining: usize,
        maximum: usize,
    },
}
impl<'a> Iterator for FragmentIter<'a> {
    type Item = Result<&'a [u8]>;
    fn next(&mut self) -> Option<Self::Item> {
        match self {
            Self::Slices(s) => s.next().map(|v| Ok(*v)),
            Self::Buffers(s) => s.next().map(|v| Ok(v.as_slice())),
            Self::Packed {
                bytes,
                lengths,
                offset,
            } => lengths.next().map(|length| {
                let end = offset.checked_add(*length).ok_or(Error::Rejected(
                    crate::RejectionReason::OperationOwnership(
                        crate::OperationOwnershipRejection::FragmentBoundaryOverflow,
                    ),
                ))?;
                let part = bytes.get(*offset..end).ok_or(Error::Rejected(
                    crate::RejectionReason::OperationOwnership(
                        crate::OperationOwnershipRejection::FragmentBoundaryRange,
                    ),
                ))?;
                *offset = end;
                Ok(part)
            }),
            Self::Encoded {
                reader,
                remaining,
                maximum,
            } => {
                if *remaining == 0 {
                    return None;
                }
                *remaining -= 1;
                let result = reader.bytes(*maximum);
                if result.is_err() {
                    *remaining = 0;
                }
                Some(result)
            }
        }
    }
}
#[derive(Clone, Copy)]
pub(in crate::advanced) struct Message<'a> {
    pub route: MessageRoute,
    pub params: Parameters<'a>,
    pub origin: NonceOrigin,
    pub state: MessageState,
    pub fragments: Fragments<'a>,
    pub next_fragment: usize,
    pub produced: usize,
    pub expected: usize,
    pub result: &'a [u8],
    pub tag_or_signature: Option<&'a [u8]>,
    pub residual_start: usize,
    pub residual_length: usize,
}
impl<'a> Message<'a> {
    pub(in crate::advanced) fn validate(&self, limits: Limits) -> Result<()> {
        if self.params.message_init.is_some() && self.origin == NonceOrigin::None {
            return Err(Error::Rejected(crate::RejectionReason::MessageRecord(
                crate::MessageRecordRejection::RecordInitLayoutWithoutAeadParameters,
            )));
        }
        if self.fragments.len() > limits.fragments
            || self.next_fragment > self.fragments.len()
            // An opaque cipher's required capacity is an observation, not a
            // retained allocation. Its archive stores only the produced bytes.
            || self.expected > limits.bytes && self.params.cipher_extension.is_none()
            || self.result.len() > limits.bytes
            || self.produced != self.result.len()
            || self.produced > self.expected
        {
            return Err(Error::Rejected(crate::RejectionReason::MessageRecord(
                crate::MessageRecordRejection::RecordMessageProgression,
            )));
        }
        if self
            .residual_start
            .checked_add(self.residual_length)
            .filter(|n| *n <= self.produced)
            .is_none()
        {
            return Err(Error::Rejected(crate::RejectionReason::MessageRecord(
                crate::MessageRecordRejection::RecordResidualRange,
            )));
        }
        match self.state {
            MessageState::Planned if self.next_fragment != 0 || self.produced != 0 => {
                return Err(Error::Rejected(crate::RejectionReason::MessageRecord(
                    crate::MessageRecordRejection::RecordPlannedMessageProgressed,
                )))
            }
            MessageState::Finished if self.next_fragment != self.fragments.len() => {
                return Err(Error::Rejected(crate::RejectionReason::MessageRecord(
                    crate::MessageRecordRejection::RecordFinishedMessageIncomplete,
                )))
            }
            _ => {}
        }
        match self.origin {
            NonceOrigin::None if self.params.nonce.is_some() => {
                return Err(Error::Rejected(crate::RejectionReason::MessageRecord(
                    crate::MessageRecordRejection::RecordNonceOrigin,
                )))
            }
            NonceOrigin::Provided if self.params.nonce.is_none() => {
                return Err(Error::Rejected(crate::RejectionReason::MessageRecord(
                    crate::MessageRecordRejection::RecordNonceOrigin,
                )))
            }
            NonceOrigin::Backend
                if self.state == MessageState::Finished && self.params.nonce.is_none() =>
            {
                return Err(Error::Rejected(crate::RejectionReason::MessageRecord(
                    crate::MessageRecordRejection::RecordCompletedNonceAbsent,
                )))
            }
            _ => {}
        }
        Ok(())
    }
    fn write(&self, w: &mut Writer<'_>, limits: Limits) -> Result<()> {
        self.validate(limits)?;
        w.u8(if self.route == MessageRoute::Single {
            1
        } else {
            2
        })?;
        self.params.write(w)?;
        w.u8(match self.origin {
            NonceOrigin::None => 0,
            NonceOrigin::Provided => 1,
            NonceOrigin::Backend => 2,
        })?;
        w.u8(match self.state {
            MessageState::Planned => 0,
            MessageState::Engaged => 1,
            MessageState::Finished => 2,
        })?;
        w.u32(u32::try_from(self.fragments.len()).map_err(|_| {
            Error::Rejected(crate::RejectionReason::MessageRecord(
                crate::MessageRecordRejection::RecordFragmentCount,
            ))
        })?)?;
        for fragment in self.fragments.iter() {
            w.bytes(fragment?)?;
        }
        w.u32(u32::try_from(self.next_fragment).map_err(|_| {
            Error::Rejected(crate::RejectionReason::MessageRecord(
                crate::MessageRecordRejection::RecordFragmentIndex,
            ))
        })?)?;
        w.u64(self.produced as u64)?;
        w.u64(self.expected as u64)?;
        w.bytes(self.result)?;
        w.optional_bytes(self.tag_or_signature)?;
        w.u64(self.residual_start as u64)?;
        w.u64(self.residual_length as u64)
    }
    fn read(r: &mut Reader<'a>, limits: Limits) -> Result<Self> {
        let route = match r.u8()? {
            1 => MessageRoute::Single,
            2 => MessageRoute::Multipart,
            _ => {
                return Err(Error::Rejected(crate::RejectionReason::MessageRecord(
                    crate::MessageRecordRejection::RecordMessageRoute,
                )))
            }
        };
        let params = Parameters::read(r, limits)?;
        let origin = match r.u8()? {
            0 => NonceOrigin::None,
            1 => NonceOrigin::Provided,
            2 => NonceOrigin::Backend,
            _ => {
                return Err(Error::Rejected(crate::RejectionReason::MessageRecord(
                    crate::MessageRecordRejection::RecordNonceOrigin,
                )))
            }
        };
        let state = match r.u8()? {
            0 => MessageState::Planned,
            1 => MessageState::Engaged,
            2 => MessageState::Finished,
            _ => {
                return Err(Error::Rejected(crate::RejectionReason::MessageRecord(
                    crate::MessageRecordRejection::RecordMessageState,
                )))
            }
        };
        let fragments = Fragments::read(r, limits)?;
        let next_fragment = r.count(limits.fragments)?;
        let size = |n: u64| {
            usize::try_from(n).map_err(|_| {
                Error::Rejected(crate::RejectionReason::MessageRecord(
                    crate::MessageRecordRejection::RecordSizeConversion,
                ))
            })
        };
        let produced = size(r.u64()?)?;
        let expected = size(r.u64()?)?;
        let result = r.bytes(limits.bytes)?;
        let tag_or_signature = r.optional_bytes(limits.bytes)?;
        let message = Self {
            route,
            params,
            origin,
            state,
            fragments,
            next_fragment,
            produced,
            expected,
            result,
            tag_or_signature,
            residual_start: size(r.u64()?)?,
            residual_length: size(r.u64()?)?,
        };
        message.validate(limits)?;
        Ok(message)
    }
}
fn ordered(previous: &mut MessageState, current: MessageState) -> Result<()> {
    // Finished prefix, at most one engaged message, then an unstarted suffix.
    let valid = match *previous {
        MessageState::Finished => true,
        MessageState::Engaged | MessageState::Planned => current == MessageState::Planned,
    };
    if !valid {
        return Err(Error::Rejected(crate::RejectionReason::MessageRecord(
            crate::MessageRecordRejection::RecordMessageOrder,
        )));
    }
    *previous = current;
    Ok(())
}
// A sequence has one chosen Init representation. The owned variant fixes
// its descriptor scalars; IV bytes and authentication tags remain per-message.
fn ordered_init<'a>(first: &mut Option<Parameters<'a>>, current: Parameters<'a>) -> Result<()> {
    use crate::MessageInitLayout;
    if let Some(initial) = first {
        let layout = initial
            .message_init
            .unwrap_or(MessageInitLayout::InitWithoutParameters);
        if layout
            != current
                .message_init
                .unwrap_or(MessageInitLayout::InitWithoutParameters)
        {
            return Err(Error::Rejected(crate::RejectionReason::MessageRecord(
                crate::MessageRecordRejection::RecordMixedMessageInitLayouts,
            )));
        }
        if layout == MessageInitLayout::InitWithOwnedMessageParameters
            && (initial.iv_initial.map(<[u8]>::len) != current.iv_initial.map(<[u8]>::len)
                || initial.iv_generator != current.iv_generator
                || initial.iv_fixed_bits != current.iv_fixed_bits
                || initial.tag_bits != current.tag_bits)
        {
            return Err(Error::Rejected(crate::RejectionReason::MessageRecord(
                crate::MessageRecordRejection::RecordChangedFixedInitScalars,
            )));
        }
    } else {
        *first = Some(current);
    }
    Ok(())
}
// A cursor factory over immutable caller-held bytes, not an owning allocation.
#[derive(Clone, Copy)]
pub(in crate::advanced) enum Messages<'a> {
    Typed(TypedMessages<'a>),
    Native(super::native_messages::Record<'a>),
    Aead(super::aead_messages::Record<'a>),
}

#[derive(Clone, Copy)]
pub(in crate::advanced) struct TypedMessages<'a> {
    aead_batch: Option<super::aead_batch::State<'a>>,
    stream: Option<super::MessageStream<'a>>,
    output: Option<super::MessageOutput>,
    bytes: &'a [u8],
    count: usize,
    limits: Limits,
}
impl<'a> Messages<'a> {
    pub(in crate::advanced) fn write(
        w: &mut Writer<'_>,
        messages: &[Message<'a>],
        limits: Limits,
    ) -> Result<()> {
        Self::write_generated(w, messages.len(), limits, |index| Ok(messages[index]))
    }
    /// Stream one borrowed message at a time; the callback is a local immutable
    /// view, never a consumer callback and never retained beyond this call.
    pub(in crate::advanced) fn write_generated(
        w: &mut Writer<'_>,
        count: usize,
        limits: Limits,
        message: impl FnMut(usize) -> Result<Message<'a>>,
    ) -> Result<()> {
        Self::write_generated_with_output(w, count, limits, None, message)
    }
    pub(in crate::advanced) fn write_generated_with_output(
        w: &mut Writer<'_>,
        count: usize,
        limits: Limits,
        output: Option<super::MessageOutput>,
        message: impl FnMut(usize) -> Result<Message<'a>>,
    ) -> Result<()> {
        Self::write_generated_with_state(w, count, limits, None, output, message)
    }
    pub(in crate::advanced) fn write_generated_with_state(
        w: &mut Writer<'_>,
        count: usize,
        limits: Limits,
        stream: Option<super::MessageStream<'a>>,
        output: Option<super::MessageOutput>,
        message: impl FnMut(usize) -> Result<Message<'a>>,
    ) -> Result<()> {
        Self::write_typed(w, count, limits, stream, output, message)
    }
    pub(in crate::advanced) fn write_generated_aead(
        w: &mut Writer<'_>,
        count: usize,
        limits: Limits,
        state: super::aead_batch::State<'_>,
        mut declared: impl FnMut(usize) -> Result<usize>,
        message: impl FnMut(usize) -> Result<Message<'a>>,
    ) -> Result<()> {
        if count == 0 || count > limits.messages {
            return Err(Error::Rejected(crate::RejectionReason::MessageRecord(
                crate::MessageRecordRejection::RecordMessageCount,
            )));
        }
        w.u8(8)?;
        state.write(w)?;
        w.u32(u32::try_from(count).map_err(|_| {
            Error::Rejected(crate::RejectionReason::MessageRecord(
                crate::MessageRecordRejection::RecordMessageWidth,
            ))
        })?)?;
        for index in 0..count {
            // A declared total can include data consumed by earlier calls.
            // Preserve its host width; it is not an individual C argument.
            let length = declared(index)?;
            w.u64(length as u64)?;
        }
        Self::write_rows(w, count, limits, None, message)
    }
    fn write_typed(
        w: &mut Writer<'_>,
        count: usize,
        limits: Limits,
        stream: Option<super::MessageStream<'a>>,
        output: Option<super::MessageOutput>,
        message: impl FnMut(usize) -> Result<Message<'a>>,
    ) -> Result<()> {
        if count == 0 && stream.is_none() || count > limits.messages {
            return Err(Error::Rejected(crate::RejectionReason::MessageRecord(
                crate::MessageRecordRejection::RecordMessageCount,
            )));
        }
        w.u8(if stream.is_some() { 6 } else { 0 })?;
        if let Some(stream) = stream {
            stream.write(w)?;
        }
        Self::write_rows(w, count, limits, output, message)
    }
    fn write_rows(
        w: &mut Writer<'_>,
        count: usize,
        limits: Limits,
        output: Option<super::MessageOutput>,
        mut message: impl FnMut(usize) -> Result<Message<'a>>,
    ) -> Result<()> {
        w.u8(u8::from(output.is_some()))?;
        if let Some(output) = output {
            output.write(w)?;
        }
        w.u32(u32::try_from(count).map_err(|_| {
            Error::Rejected(crate::RejectionReason::MessageRecord(
                crate::MessageRecordRejection::RecordMessageWidth,
            ))
        })?)?;
        let mut initial = None;
        let mut state = MessageState::Finished;
        let mut fragments = 0usize;
        for index in 0..count {
            let message = message(index)?;
            ordered_init(&mut initial, message.params)?;
            ordered(&mut state, message.state)?;
            fragments = fragments
                .checked_add(message.fragments.len())
                .filter(|n| *n <= limits.fragments)
                .ok_or(Error::Rejected(crate::RejectionReason::MessageRecord(
                    crate::MessageRecordRejection::RecordAggregateFragments,
                )))?;
            message.write(w, limits)?;
        }
        Ok(())
    }
    pub(in crate::advanced) fn read(r: &mut Reader<'a>, limits: Limits) -> Result<Self> {
        // Historical tags keep their exact meanings. Tag 6 adds typed-stream
        // refusals; 2/5 carry generic graphs, 3/4 caller-fed AEAD. Tag 7 adds
        // queued AEAD capacities, independent of input length, and a retained
        // insufficient-buffer call when present. Tag 8 additionally retains
        // declared input widths independently of consumed/retired input bytes.
        // Tag 9 preserves per-row accepted input with explicit availability.
        let mut aead_batch = None;
        let tag = r.u8()?;
        let stream = match tag {
            0 => None,
            7 | 8 => {
                aead_batch = Some(super::aead_batch::State::read(r, limits, tag == 8)?);
                None
            }
            1 => Some(super::MessageStream::read(r, limits, false)?),
            6 => Some(super::MessageStream::read(r, limits, true)?),
            2 => return super::native_messages::Record::read(r, limits, false).map(Self::Native),
            5 => return super::native_messages::Record::read(r, limits, true).map(Self::Native),
            3 => {
                return super::aead_messages::Record::read(r, limits, false, false).map(Self::Aead)
            }
            4 => return super::aead_messages::Record::read(r, limits, true, false).map(Self::Aead),
            9 => return super::aead_messages::Record::read(r, limits, true, true).map(Self::Aead),
            _ => {
                return Err(Error::Rejected(crate::RejectionReason::MessageRecord(
                    crate::MessageRecordRejection::MessageStreamParent,
                )))
            }
        };
        let output = if r.boolean(crate::RejectionReason::MessageRecord(
            crate::MessageRecordRejection::MessageOutputContinuation,
        ))? {
            Some(super::MessageOutput::read(r)?)
        } else {
            None
        };
        let count = r.count(limits.messages)?;
        if count == 0 && stream.is_none() {
            return Err(Error::Rejected(crate::RejectionReason::MessageRecord(
                crate::MessageRecordRejection::RecordMessageCount,
            )));
        }
        let start = r.position;
        let mut initial = None;
        let mut state = MessageState::Finished;
        let mut fragments = 0usize;
        for _ in 0..count {
            let message = Message::read(r, limits)?;
            ordered_init(&mut initial, message.params)?;
            ordered(&mut state, message.state)?;
            fragments = fragments
                .checked_add(message.fragments.len())
                .filter(|n| *n <= limits.fragments)
                .ok_or(Error::Rejected(crate::RejectionReason::MessageRecord(
                    crate::MessageRecordRejection::RecordAggregateFragments,
                )))?;
        }
        Ok(Self::Typed(TypedMessages {
            aead_batch,
            stream,
            output,
            bytes: &r.bytes[start..r.position],
            count,
            limits,
        }))
    }
    pub(in crate::advanced) fn aead_batch(&self) -> Option<super::aead_batch::State<'a>> {
        match self {
            Self::Typed(rows) => rows.aead_batch,
            Self::Native(_) | Self::Aead(_) => None,
        }
    }
    pub(in crate::advanced) fn aead_row_layout(
        &self,
        index: usize,
    ) -> Result<super::aead_batch::RowLayout> {
        self.aead_batch()
            .map(|state| state.row_layout(index))
            .transpose()
            .map(|layout| layout.unwrap_or_default())
    }
    pub(in crate::advanced) fn stream(&self) -> Option<super::MessageStream<'a>> {
        match self {
            Self::Typed(rows) => rows.stream,
            Self::Native(_) | Self::Aead(_) => None,
        }
    }
    pub(in crate::advanced) fn output(&self) -> Option<super::MessageOutput> {
        match self {
            Self::Typed(rows) => rows.output,
            Self::Native(_) | Self::Aead(_) => None,
        }
    }
    pub(in crate::advanced) fn native(&self) -> Option<super::native_messages::Record<'a>> {
        match self {
            Self::Native(rows) => Some(*rows),
            Self::Typed(_) | Self::Aead(_) => None,
        }
    }
    pub(in crate::advanced) fn aead(&self) -> Option<super::aead_messages::Record<'a>> {
        match self {
            Self::Aead(rows) => Some(*rows),
            Self::Typed(_) | Self::Native(_) => None,
        }
    }
    pub(in crate::advanced) fn require_typed(&self) -> Result<()> {
        match self {
            Self::Typed(_) => Ok(()),
            Self::Native(_) | Self::Aead(_) => {
                Err(Error::Rejected(crate::RejectionReason::MessageRecord(
                    crate::MessageRecordRejection::MessageRepresentationOnAnotherFamily,
                )))
            }
        }
    }
    pub(in crate::advanced) fn len(&self) -> usize {
        match self {
            Self::Typed(rows) => rows.count,
            Self::Native(rows) => rows.len(),
            Self::Aead(rows) => rows.len(),
        }
    }
    pub(in crate::advanced) fn iter(&self) -> MessageIter<'a> {
        match self {
            Self::Typed(rows) => MessageIter::Typed {
                reader: Reader {
                    graph_observer: None,
                    bytes: rows.bytes,
                    position: 0,
                },
                remaining: rows.count,
                limits: rows.limits,
            },
            // A mistaken typed consumer receives a concrete error, including
            // for a zero-row generic parent; it cannot silently skip the body.
            Self::Native(_) | Self::Aead(_) => MessageIter::WrongFamily,
        }
    }
}

pub(in crate::advanced) enum MessageIter<'a> {
    Typed {
        reader: Reader<'a>,
        remaining: usize,
        limits: Limits,
    },
    WrongFamily,
    Finished,
}
impl<'a> Iterator for MessageIter<'a> {
    type Item = Result<Message<'a>>;
    fn next(&mut self) -> Option<Self::Item> {
        match self {
            Self::Typed {
                reader,
                remaining,
                limits,
            } => {
                if *remaining == 0 {
                    return None;
                }
                *remaining -= 1;
                let result = Message::read(reader, *limits);
                if result.is_err() {
                    *remaining = 0;
                }
                Some(result)
            }
            Self::WrongFamily => {
                *self = Self::Finished;
                Some(Err(Error::Rejected(crate::RejectionReason::MessageRecord(
                    crate::MessageRecordRejection::GenericMessageBodyOnAnotherFamily,
                ))))
            }
            Self::Finished => None,
        }
    }
}
