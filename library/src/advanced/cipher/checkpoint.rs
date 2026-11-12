// SPDX-License-Identifier: Apache-2.0
//! Canonical block cipher continuation boundaries; restoration never replays native Init.

use super::{
    parameters, plain_parameters, record, restoration_keys, CipherBufferRequest, CipherLease,
    CipherOperation, CipherOutputPlan, Direction, KeyLease, MessageRoute, NativeActivity,
    OutputObserver, OutputStep, PreparedCipher, Selection, Stage, StateRestoreKeys,
};

use crate::symmetric::memory::{Budget, Credit};
use crate::{bounds, Error, Result, Session};
use fe11_sys::{CKK_AES, CKO_SECRET_KEY, CKR_BUFFER_TOO_SMALL, CKR_OK};
use record::{Descriptor, Family, KeyBindings, Limits, Message, MessageState, Messages};
use std::sync::Arc;

impl CipherOperation {
    /// A refused SetOperationState may already have armed the destination's
    /// writer. Preserve that authority only when returning the same identity.
    pub(in crate::advanced) fn retain_refused_binding(
        &mut self,
        keys: &restoration_keys::BoundKeys,
    ) {
        if let (CipherLease::WithKey(source), Some(destination)) = (&mut self.key, &keys.encryption)
        {
            source.retain_refused_binding(destination);
        }
    }
}

// Two independent wire fields share a byte: the low nibble describes
// the recorded key, the high nibble the output negotiation. Decode each into
// its own closed type; neither is a normative security profile or a default
// imposed on the caller's cryptographic operation.
#[derive(Clone, Copy, PartialEq, Eq)]
enum KeyProfile {
    Absent,
    NativeSecret,
    Aes128,
    Aes192,
    Aes256,
}
impl KeyProfile {
    fn read(value: u8) -> Result<Self> {
        match value {
            0 => Ok(Self::Absent),
            1 => Ok(Self::NativeSecret),
            2 => Ok(Self::Aes128),
            3 => Ok(Self::Aes192),
            4 => Ok(Self::Aes256),
            _ => Err(Error::Rejected(crate::RejectionReason::CipherContinuation(
                crate::CipherContinuationRejection::CipherRecordKeyProfile,
            ))),
        }
    }
    fn wire(self) -> u8 {
        match self {
            Self::Absent => 0,
            Self::NativeSecret => 1,
            Self::Aes128 => 2,
            Self::Aes192 => 3,
            Self::Aes256 => 4,
        }
    }
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum OutputProfile {
    Buffer,
    Query,
    SizeReported,
    TooSmall,
}
impl OutputProfile {
    fn storage(
        self,
        capacity: usize,
        produced: usize,
        terminal: bool,
    ) -> Result<super::OutputStorage> {
        let remaining = capacity.checked_sub(produced).ok_or(Error::Rejected(
            crate::RejectionReason::CipherContinuation(
                crate::CipherContinuationRejection::CipherRecordOutputBounds,
            ),
        ))?;
        let offered = if !terminal && matches!(self, Self::Buffer | Self::TooSmall) {
            Some(remaining)
        } else {
            // A query lends NULL; a finished sequence has no future offer.
            None
        };
        let storage = super::OutputStorage::Retained { capacity, offered };
        storage.validate(capacity)?;
        Ok(storage)
    }

    fn read(value: u8) -> Result<(Self, KeyProfile)> {
        // Preserve decoding order: an invalid key nibble is reported before
        // an invalid output nibble, including when both are malformed.
        let key = KeyProfile::read(value & 0x0f)?;
        let output = match value >> 4 {
            0 => Self::Buffer,
            1 => Self::Query,
            2 => Self::SizeReported,
            3 => Self::TooSmall,
            _ => {
                return Err(Error::Rejected(crate::RejectionReason::CipherContinuation(
                    crate::CipherContinuationRejection::CipherRecordOutputProfile,
                )))
            }
        };
        Ok((output, key))
    }
    fn wire(self, key: u8) -> Result<u8> {
        if !(0..=4).contains(&key) {
            return Err(Error::Rejected(crate::RejectionReason::CipherContinuation(
                crate::CipherContinuationRejection::CipherCheckpointKeyProfile,
            )));
        }
        let code = match self {
            Self::Buffer => 0,
            Self::Query => 1,
            Self::SizeReported => 2,
            Self::TooSmall => 3,
        };
        Ok((code << 4) | key)
    }
    fn waiting(self) -> bool {
        matches!(self, Self::SizeReported | Self::TooSmall)
    }
}
pub(in crate::advanced) fn key_profile(value: u8) -> Result<u8> {
    Ok(OutputProfile::read(value)?.1.wire())
}

impl Direction {
    fn family(self) -> Family {
        match self {
            Self::Encrypt => Family::CipherEncrypt,
            Self::Decrypt => Family::CipherDecrypt,
        }
    }
    fn from_family(family: Family) -> Result<Self> {
        match family {
            Family::CipherEncrypt => Ok(Self::Encrypt),
            Family::CipherDecrypt => Ok(Self::Decrypt),
            _ => Err(Error::Rejected(crate::RejectionReason::CipherContinuation(
                crate::CipherContinuationRejection::CipherRecordFamily,
            ))),
        }
    }
}

pub(in crate::advanced) fn validate(
    d: Descriptor,
    keys: &KeyBindings<'_>,
    messages: &Messages<'_>,
    validation: Option<&record::ValidationRecord<'_>>,
    limits: Limits,
    terminal: bool,
) -> Result<()> {
    let direction = Direction::from_family(d.family)?;
    let (profile, key_profile) = OutputProfile::read(d.profile)?;
    let key_matches = match (key_profile, keys.cipher) {
        (KeyProfile::Absent, None) => true,
        (
            KeyProfile::NativeSecret | KeyProfile::Aes128 | KeyProfile::Aes192 | KeyProfile::Aes256,
            Some(key),
        ) => {
            key.role == record::KeyRole::Cipher
                && (key_profile == KeyProfile::NativeSecret
                    || (key.class == Some(CKO_SECRET_KEY as u64)
                        && key.key_type == Some(CKK_AES as u64)
                        && plain_parameters::non_aead(d.mechanism)))
        }
        _ => false,
    };
    if keys.authentication.is_some()
        || !key_matches
        || d.active_flags != 0
        || d.validation_requested
        || d.carried_messages != 0
        || messages.len() != 1
        || d.size > limits.bytes
        || messages
            .iter()
            .next()
            .transpose()?
            .is_some_and(|m| m.params.cipher_extension.is_none())
            && parameters::is_aead(d.mechanism)
            && key_profile != KeyProfile::NativeSecret
    {
        return Err(Error::Rejected(crate::RejectionReason::CipherContinuation(
            crate::CipherContinuationRejection::CipherRecordDescriptor,
        )));
    }
    let m = messages.iter().next().ok_or(Error::Rejected(
        crate::RejectionReason::CipherContinuation(
            crate::CipherContinuationRejection::CipherRecordMessageAbsent,
        ),
    ))??;
    m.validate(limits)?;
    let p = &m.params;
    if p.digest_output.is_some()
        || p.digest_oid.is_some()
        || p.digest_extension.is_some()
        || p.signature.is_some()
    {
        return Err(Error::Rejected(crate::RejectionReason::CipherContinuation(
            crate::CipherContinuationRejection::DigestOidOnNonDigestOwner,
        )));
    }
    let generated_iv = matches!(
        d.cipher_options,
        Some(crate::symmetric::structured::CipherOptions::TokenIv { generated: true })
    );
    let expected_origin = if generated_iv {
        record::NonceOrigin::Backend
    } else {
        record::NonceOrigin::Provided
    };
    if (p.cipher_extension.is_none()
        && !plain_parameters::block_cipher(d.mechanism)
        && !parameters::is_aead(d.mechanism))
        || m.origin != expected_origin
        || p.message_init.is_some()
        || p.iv_generator.is_some()
        || p.iv_fixed_bits.is_some()
        || p.iv_initial.is_some()
        || p.hash.is_some()
        || p.mgf.is_some()
        || p.salt.is_some()
        || m.tag_or_signature.is_some()
        || m.residual_start != 0
        || m.residual_length != 0
        || p.cipher_extension.is_some()
            && (d.cipher_options.is_some()
                || p.counter_bits.is_some()
                || p.nonce != Some(&[][..])
                || p.aad.is_some()
                || p.tag_bits != 0)
    {
        return Err(Error::Rejected(crate::RejectionReason::CipherContinuation(
            crate::CipherContinuationRejection::CipherRecordParameters,
        )));
    }
    let selection = Selection::from_record(d, p)?.record_route(m.route)?;
    selection.validate_route(m.route)?;
    let mut input = 0usize;
    let mut consumed = 0usize;
    for (index, part) in m.fragments.iter().enumerate() {
        let length = part?.len();
        input = input.checked_add(length).ok_or(Error::Rejected(
            crate::RejectionReason::CipherContinuation(
                crate::CipherContinuationRejection::CipherRecordInputOverflow,
            ),
        ))?;
        if index < m.next_fragment {
            consumed = consumed.checked_add(length).ok_or(Error::Rejected(
                crate::RejectionReason::CipherContinuation(
                    crate::CipherContinuationRejection::CipherRecordOffsetOverflow,
                ),
            ))?;
        }
    }
    if m.next_fragment
        != if terminal || d.phase.name() == direction.final_call() {
            m.fragments.len()
        } else {
            0
        }
    {
        return Err(Error::Rejected(crate::RejectionReason::CipherContinuation(
            crate::CipherContinuationRejection::CipherCheckpointRetainsConsumedInput,
        )));
    }
    if d.input
        .progress
        .output_bytes
        .checked_sub(d.input.progress.delivered_bytes)
        != Some(m.produced as u128)
    {
        return Err(Error::Rejected(crate::RejectionReason::CipherContinuation(
            crate::CipherContinuationRejection::CipherRetainedOutputCounters,
        )));
    }
    if !d.input.incremental {
        consumed = usize::try_from(d.input.progress.input_bytes).map_err(|_| {
            Error::Rejected(crate::RejectionReason::CipherContinuation(
                crate::CipherContinuationRejection::CipherCompleteInputCounterWidth,
            ))
        })?;
        input = input.checked_add(consumed).ok_or(Error::Rejected(
            crate::RejectionReason::CipherContinuation(
                crate::CipherContinuationRejection::CipherCompleteInputSizeOverflow,
            ),
        ))?;
    }
    let (_minimum, maximum) = if d.input.incremental {
        (0, d.size)
    } else {
        selection.output_bounds(input, direction.decrypts())?
    };
    let produced_prefix_bound = match selection {
        Selection::Aead(p, _) if !direction.decrypts() => consumed
            .checked_add(p.tag_bits()?.div_ceil(8) as usize)
            .ok_or(Error::Rejected(crate::RejectionReason::CipherContinuation(
                crate::CipherContinuationRejection::AeadRetainedPrefixLengthOverflow,
            )))?,
        _ => consumed,
    };
    profile.storage(d.size, m.produced, terminal)?;
    if profile.waiting() {
        let required = m.expected.checked_sub(m.produced).ok_or(Error::Rejected(
            crate::RejectionReason::CipherContinuation(
                crate::CipherContinuationRejection::CipherRecordOutputBounds,
            ),
        ))?;
        bounds::ck_length(required)?;
    }
    if !d.input.incremental
        && !profile.waiting()
        && selection.validates_output_interval()
        && m.expected != maximum
        || m.produced != m.result.len()
        || m.produced > d.size
        || matches!(profile, OutputProfile::Query | OutputProfile::SizeReported)
            && d.size != m.produced
    {
        return Err(Error::Rejected(crate::RejectionReason::CipherContinuation(
            crate::CipherContinuationRejection::CipherRecordOutputBounds,
        )));
    }

    if d.input.incremental {
        if m.route != MessageRoute::Multipart
            || d.input
                .progress
                .output_bytes
                .checked_sub(d.input.progress.delivered_bytes)
                != Some(m.produced as u128)
            || d.input.progress.key_inputs != 0
            || d.input.retained_submission
                != (profile == OutputProfile::TooSmall && d.phase.name() == direction.update())
            || p.cipher_extension.is_none()
                && parameters::is_aead(d.mechanism)
                && direction.decrypts()
                && d.input.progress.delivered_bytes != 0
        {
            return Err(Error::Rejected(crate::RejectionReason::CipherContinuation(
                crate::CipherContinuationRejection::CipherStreamCheckpointProgression,
            )));
        }
    }
    let terminal_function = match m.route {
        MessageRoute::Single => direction.single(),
        MessageRoute::Multipart => direction.final_call(),
    };
    let steps = if m.route == MessageRoute::Single {
        1
    } else {
        m.fragments.len().max(1)
    };
    if terminal {
        if profile != OutputProfile::Buffer
            || m.state != MessageState::Finished
            || m.next_fragment != m.fragments.len()
            || d.phase.name() != terminal_function
            || d.input.is_open()
            || !selection.terminal_lengths(
                d.input.progress.input_bytes,
                d.input.progress.output_bytes,
                direction.decrypts(),
                d.cipher_options,
            )?
        {
            return Err(Error::Rejected(crate::RejectionReason::CipherContinuation(
                crate::CipherContinuationRejection::CipherTerminalProgression,
            )));
        }
    } else {
        if m.state != MessageState::Engaged {
            return Err(Error::Rejected(crate::RejectionReason::CipherContinuation(
                crate::CipherContinuationRejection::CipherRecordProgression,
            )));
        }
        match m.route {
            MessageRoute::Single
                if d.phase.name() == direction.single()
                    && m.next_fragment == 0
                    && m.produced == 0 => {}
            MessageRoute::Multipart
                if d.phase.name() == direction.update()
                    && m.next_fragment < steps
                    && (d.input.incremental
                        || p.cipher_extension.is_some()
                        || m.produced
                            <= if parameters::is_aead(d.mechanism) {
                                produced_prefix_bound.min(maximum)
                            } else {
                                consumed
                            }) => {}
            MessageRoute::Multipart
                if d.phase.name() == direction.final_call()
                    && m.next_fragment == m.fragments.len()
                    && (d.input.incremental
                        || p.cipher_extension.is_some()
                        || m.produced
                            <= if parameters::is_aead(d.mechanism) {
                                maximum
                            } else {
                                input
                            }) => {}
            _ => {
                return Err(Error::Rejected(crate::RejectionReason::CipherContinuation(
                    crate::CipherContinuationRejection::CipherRecordNextFunctionOrFragment,
                )))
            }
        }
    }
    if let Some(report) = validation {
        let mut observations = report.iter();
        let observed = observations.next().transpose()?;
        if report.maximum() != 1
            || observations.next().is_some()
            || if terminal {
                observed.map_or(true, |observation| {
                    observation.function != terminal_function || observation.message_index.is_some()
                })
            } else {
                observed.is_some()
            }
        {
            return Err(Error::Rejected(crate::RejectionReason::CipherContinuation(
                crate::CipherContinuationRejection::CipherRecordValidationCorrelation,
            )));
        }
    } else if terminal {
        return Err(Error::Rejected(crate::RejectionReason::CipherContinuation(
            crate::CipherContinuationRejection::CipherTerminalObservationAbsent,
        )));
    }
    Ok(())
}

impl CipherOperation {
    pub(super) fn capturable(&self) -> Result<()> {
        if self.pending()
            || matches!(self.stage, Stage::Init(_) | Stage::Failed)
            || self.observer == OutputObserver::Session
            || self.frame.output.is_none()
            || !self.frame.unchanged()
        {
            return Err(Error::Rejected(crate::RejectionReason::CipherContinuation(
                crate::CipherContinuationRejection::CipherContinuationUnavailable,
            )));
        }
        Ok(())
    }
    fn next_fragment(&self, logical_fragments: usize) -> usize {
        match self.stage {
            Stage::Done => logical_fragments,
            stage => match OutputStep::from_stage(stage) {
                Ok(OutputStep::Single) => 0,
                Ok(OutputStep::Update { index, .. }) => index,
                Ok(OutputStep::Final) => logical_fragments,
                Err(_) => 0,
            },
        }
    }
    fn output_profile(&self) -> Result<OutputProfile> {
        match self.stage {
            Stage::Query(_) => Ok(OutputProfile::Query),
            Stage::Waiting { request, .. } if request.code == CKR_OK as u64 => {
                Ok(OutputProfile::SizeReported)
            }
            Stage::Waiting { request, .. } if request.code == CKR_BUFFER_TOO_SMALL as u64 => {
                Ok(OutputProfile::TooSmall)
            }
            Stage::Waiting { .. } => {
                Err(Error::Rejected(crate::RejectionReason::CipherContinuation(
                    crate::CipherContinuationRejection::CipherSizeResultCode,
                )))
            }
            _ => Ok(OutputProfile::Buffer),
        }
    }
    pub(in crate::advanced) fn checkpoint_header(&self) -> Result<(Descriptor, KeyBindings<'_>)> {
        self.capturable()?;
        let phase = if self.complete() {
            if self.frame.route == MessageRoute::Single {
                self.frame.direction.single()
            } else {
                self.frame.direction.final_call()
            }
        } else {
            OutputStep::from_stage(self.stage)?.function(self.frame.direction)
        };
        Ok((
            Descriptor {
                input: self.input,
                family: self.frame.direction.family(),
                profile: self
                    .output_profile()?
                    .wire(self.key.checkpoint_profile()?)?,
                phase: record::Function::from_name(phase)?,
                mechanism: self.frame.parameters.kind() as u64,
                size: self.frame.output.as_ref().unwrap().capacity(),
                active_flags: 0,
                validation_requested: false,
                digest_bits: None,
                cipher_options: self.frame.parameters.options(),
                carried_messages: 0,
            },
            KeyBindings {
                cipher: self.key.checkpoint_key()?,
                authentication: None,
            },
        ))
    }
    pub(in crate::advanced) fn write_checkpoint_messages(
        &self,
        _budget: &Arc<Budget>,
        writer: &mut record::Writer<'_>,
        limits: Limits,
    ) -> Result<()> {
        self.capturable()?;
        let parts = self
            .frame
            .layout
            .fragments(&self.frame.inputs, self.frame.route)?;
        let output = self.frame.output.as_ref().unwrap();
        let message = Message {
            route: self.frame.route,
            params: record::Parameters {
                digest_output: None,
                cipher_extension: match &self.frame.parameters {
                    parameters::Frame::Extension(frame) => Some(frame.record()?),
                    _ => None,
                },
                digest_extension: None,
                signature: None,
                digest_oid: None,
                message_init: None,
                counter_bits: self.frame.parameters.counter_bits(),
                nonce: Some(self.frame.parameters.expected_iv_bytes()),
                aad: self.frame.parameters.aad(),
                tag_bits: u32::try_from(self.frame.parameters.tag_bits()).map_err(|_| {
                    Error::Rejected(crate::RejectionReason::CipherContinuation(
                        crate::CipherContinuationRejection::RecordTagWidth,
                    ))
                })?,
                iv_generator: None,
                iv_fixed_bits: None,
                iv_initial: None,
                hash: None,
                mgf: None,
                salt: None,
            },
            origin: if self.frame.parameters.generated_iv()?.is_some() {
                record::NonceOrigin::Backend
            } else {
                record::NonceOrigin::Provided
            },
            state: if self.complete() {
                MessageState::Finished
            } else {
                MessageState::Engaged
            },
            fragments: parts,
            next_fragment: self.next_fragment(parts.len()),
            produced: self.used,
            // The shared message codec requires expected >= produced. While
            // waiting, expected denotes the prospective total allocation; the
            // native call's required capacity is recovered by subtracting used.
            expected: match self.buffer_request() {
                Some(request) => self
                    .used
                    .checked_add(request.required)
                    .ok_or(Error::Rejected(crate::RejectionReason::CipherContinuation(
                        crate::CipherContinuationRejection::CipherCapturedRequiredCapacityOverflow,
                    )))?,
                None if self.input.incremental
                    || matches!(&self.frame.parameters, parameters::Frame::Extension(_)) =>
                {
                    output.capacity()
                }
                None => self.frame.maximum,
            },
            result: output.as_slice().get(..self.used).ok_or(Error::Rejected(
                crate::RejectionReason::CipherContinuation(
                    crate::CipherContinuationRejection::CipherRetainedOutputRange,
                ),
            ))?,
            tag_or_signature: None,
            residual_start: 0,
            residual_length: 0,
        };
        Messages::write(writer, &[message], limits)
    }

    pub(in crate::advanced) fn set_terminal(&mut self) {
        self.stage = Stage::Done;
        self.activity = NativeActivity::Inactive;
    }
    pub(in crate::advanced) fn restore_keys(
        &self,
        session: &Session,
        keys: StateRestoreKeys<'_>,
        permits: &mut [Option<crate::registry::ReadPermit>],
        bound: &mut restoration_keys::BoundKeys,
    ) -> Result<()> {
        if keys.authentication.is_some() {
            return Err(Error::Rejected(crate::RejectionReason::CipherContinuation(
                crate::CipherContinuationRejection::CipherHasNoAuthenticationKeyRole,
            )));
        }
        bound.extension =
            super::extension_binding::captured_contract(session, self, keys.extension)?;
        match (&self.key, keys.encryption) {
            (CipherLease::NoKey, None) => {}
            (CipherLease::WithKey(source), Some(key)) => {
                let lease = source.rebind_retained(
                    session,
                    key.reference,
                    self.frame.parameters.kind(),
                    permits,
                    &mut bound.encryption,
                )?;
                bound.native_encryption = match key.encoding {
                    crate::advanced::StateKeyEncoding::Supplied => lease.handle,
                    crate::advanced::StateKeyEncoding::Embedded => fe11_sys::CK_INVALID_HANDLE,
                };
                bound.encryption = Some(lease);
            }
            _ => {
                return Err(Error::Rejected(crate::RejectionReason::CipherContinuation(
                    crate::CipherContinuationRejection::CipherRestorationKeyPresenceMismatch,
                )))
            }
        }
        Ok(())
    }
    /// Preserve the displaced lease until the caller leaves restore possession.
    pub(in crate::advanced) fn bind_restored(
        &mut self,
        mut keys: restoration_keys::BoundKeys,
    ) -> restoration_keys::BoundKeys {
        if let parameters::Frame::Extension(frame) = &mut self.frame.parameters {
            frame
                .bind_contract(keys.extension.take().expect("validated cipher declaration"))
                .expect("validated cipher declaration identity");
        }
        match &mut self.key {
            CipherLease::NoKey => assert!(keys.encryption.is_none(), "validated cipher has no key"),
            CipherLease::WithKey(key) => {
                let replacement = keys.encryption.take().expect("validated cipher key");
                keys.encryption = Some(std::mem::replace(key, replacement));
            }
        }
        keys
    }
}

/// A pure archive recipe: cryptographic parameters and source fragments remain
/// borrowed until the whole destination graph is admitted.
pub(in crate::advanced) struct RecordPlan<'a> {
    descriptor: Descriptor,
    message: record::Message<'a>,
    direction: Direction,
    selection: Selection<'a>,
    profile: OutputProfile,
    key_profile: KeyProfile,
    request: super::snapshot::Request<'a>,
}
impl<'a> RecordPlan<'a> {
    pub(in crate::advanced) fn new(
        descriptor: Descriptor,
        messages: &record::Messages<'a>,
        ceilings: crate::CryptoLimits,
        pending: bool,
    ) -> Result<Self> {
        if pending {
            return Err(Error::Rejected(crate::RejectionReason::CipherContinuation(
                crate::CipherContinuationRejection::NativeCipherAsynchronousModeUnavailable,
            )));
        }
        let direction = Direction::from_family(descriptor.family)?;
        let message = messages.iter().next().ok_or(Error::Rejected(
            crate::RejectionReason::CipherContinuation(
                crate::CipherContinuationRejection::CipherRecordMessageAbsent,
            ),
        ))??;
        let selection =
            Selection::from_record(descriptor, &message.params)?.record_route(message.route)?;
        let limits = crate::InputLimits {
            maximum_parts: ceilings.maximum_parts,
            maximum_total_bytes: ceilings.maximum_total_bytes,
        };
        let input = match selection {
            Selection::Plain(_) | Selection::Extension(_) => limits.validate_lengths(
                ceilings,
                message.fragments.len(),
                message.fragments.iter().map(|part| part.map(<[u8]>::len)),
            )?,
            Selection::Aead(parameters, _) => crate::symmetric::input_size_lengths(
                ceilings,
                limits,
                message.fragments.len(),
                message.fragments.iter().map(|part| part.map(<[u8]>::len)),
                parameters.aad().len(),
                if direction.decrypts() {
                    parameters.tag_bits()?.div_ceil(8) as usize
                } else {
                    0
                },
            )?,
        };
        let (profile, key_profile) = OutputProfile::read(descriptor.profile)?;
        let request = super::snapshot::Request::for_record(
            direction,
            selection,
            &message,
            input,
            profile.storage(
                descriptor.size,
                message.produced,
                message.state == MessageState::Finished,
            )?,
            descriptor.input.incremental,
            descriptor.input.progress.input_bytes,
            match descriptor.cipher_options {
                Some(crate::symmetric::structured::CipherOptions::CcmDataLength { bytes }) => {
                    Some(bytes)
                }
                _ => None,
            },
        )?;
        Ok(Self {
            descriptor,
            message,
            direction,
            selection,
            profile,
            key_profile,
            request,
        })
    }
    pub(in crate::advanced) fn allocation_bytes(&self) -> usize {
        self.request.allocation_bytes()
    }
    pub(in crate::advanced) fn allocate(
        &self,
        prepaid: &mut Credit,
    ) -> Result<super::snapshot::Storage<'a>> {
        self.request
            .allocate_record(self.message.fragments, prepaid)
    }
    pub(in crate::advanced) fn bind(
        self,
        storage: super::snapshot::Storage<'a>,
        prepaid: &mut Credit,
    ) -> Result<PreparedCheckpoint> {
        let frame = storage
            .bind(prepaid)?
            .fill_record(self.selection, self.message.fragments)?;
        PreparedCheckpoint::finish(
            frame,
            self.direction,
            self.selection,
            self.profile,
            self.key_profile,
            &self.message,
            self.descriptor,
        )
    }
}

/// Fully rebuilt cipher storage without destination key possession.
pub(in crate::advanced) struct PreparedCheckpoint {
    input: crate::advanced::input::InputState,
    frame: PreparedCipher,
    key_profile: KeyProfile,
    stage: Stage,
    used: usize,
}
impl PreparedCheckpoint {
    fn finish(
        mut frame: PreparedCipher,
        direction: Direction,
        selection: Selection<'_>,
        profile: OutputProfile,
        key_profile: KeyProfile,
        m: &record::Message<'_>,
        d: Descriptor,
    ) -> Result<Self> {
        frame
            .parameters
            .restore_generated_iv(m.params.nonce.ok_or(Error::Rejected(
                crate::RejectionReason::CipherContinuation(
                    crate::CipherContinuationRejection::CipherRecordIvAbsent,
                ),
            ))?)?;
        if frame.parameters.options() != d.cipher_options {
            return Err(Error::Rejected(crate::RejectionReason::CipherContinuation(
                crate::CipherContinuationRejection::CipherParameterFramingChangedOnRestoration,
            )));
        }
        if frame.output.as_ref().unwrap().capacity() != d.size
            || m.result.len() != m.produced
            || m.produced > d.size
            || !d.input.incremental
                && !profile.waiting()
                && selection.validates_output_interval()
                && m.expected != frame.maximum
        {
            return Err(Error::Rejected(crate::RejectionReason::CipherContinuation(
                crate::CipherContinuationRejection::CipherDestinationOutputCapacity,
            )));
        }
        if d.input.incremental && m.fragments.len() == 0 {
            frame.inputs.clear();
        }
        let mut restored = Self {
            input: d.input,
            frame,
            key_profile,
            stage: Stage::Done,
            used: 0,
        };
        let step = match (m.route, d.phase.name()) {
            (MessageRoute::Single, name) if name == direction.single() => OutputStep::Single,
            (MessageRoute::Multipart, name) if name == direction.update() => {
                if m.next_fragment >= restored.frame.inputs.len() {
                    return Err(Error::Rejected(crate::RejectionReason::CipherContinuation(
                        crate::CipherContinuationRejection::CipherRestoredFragment,
                    )));
                }
                let offset = restored.frame.inputs[..m.next_fragment]
                    .iter()
                    .try_fold(0usize, |n, b| n.checked_add(b.as_slice().len()))
                    .ok_or(Error::Rejected(crate::RejectionReason::CipherContinuation(
                        crate::CipherContinuationRejection::CipherRestoredOffsetOverflow,
                    )))?;
                OutputStep::Update {
                    index: m.next_fragment,
                    offset,
                }
            }
            (MessageRoute::Multipart, name) if name == direction.final_call() => OutputStep::Final,
            _ => {
                return Err(Error::Rejected(crate::RejectionReason::CipherContinuation(
                    crate::CipherContinuationRejection::CipherRestoredFunction,
                )))
            }
        };
        restored.stage = match profile {
            OutputProfile::Buffer => step.stage(),
            OutputProfile::Query => Stage::Query(step),
            OutputProfile::SizeReported | OutputProfile::TooSmall => Stage::Waiting {
                step,
                request: CipherBufferRequest {
                    function: step.function(direction),
                    code: if profile == OutputProfile::SizeReported {
                        CKR_OK as u64
                    } else {
                        CKR_BUFFER_TOO_SMALL as u64
                    },
                    required: m.expected.checked_sub(m.produced).ok_or(Error::Rejected(
                        crate::RejectionReason::CipherContinuation(
                            crate::CipherContinuationRejection::CipherRestoredRequiredCapacity,
                        ),
                    ))?,
                    previous_capacity: if profile == OutputProfile::SizeReported {
                        0
                    } else {
                        d.size.checked_sub(m.produced).ok_or(Error::Rejected(
                            crate::RejectionReason::CipherContinuation(
                                crate::CipherContinuationRejection::CipherRestoredCapacityOffset,
                            ),
                        ))?
                    },
                },
            },
        };
        let output = restored.frame.output.as_mut().unwrap();
        output.as_mut()[..m.result.len()].copy_from_slice(m.result);
        if m.state == MessageState::Finished {
            output.set_length(m.produced)?;
        }
        restored.used = m.produced;
        Ok(restored)
    }

    pub(in crate::advanced) fn check_binding(
        &self,
        key: Option<&KeyLease>,
        declaration: Option<&crate::MechanismExtension>,
    ) -> Result<()> {
        match (&self.frame.parameters, declaration) {
            (parameters::Frame::Extension(frame), Some(contract)) => {
                frame.check_contract(contract)?
            }
            (parameters::Frame::Extension(_), None) | (_, Some(_)) => {
                return Err(Error::Rejected(
                    crate::RejectionReason::CipherContinuation(crate::CipherContinuationRejection::CipherReconstructedDeclarationAbsentOrUnexpected),
                ))
            }
            (_, None) => {}
        }
        CipherLease::check_record(key, self.key_profile.wire())
    }
    /// Move the checked frame and key without a subsequent refusal point.
    pub(in crate::advanced) fn bind_checked(
        mut self,
        key: Option<KeyLease>,
        declaration: Option<crate::MechanismExtension>,
    ) -> CipherOperation {
        match (&mut self.frame.parameters, declaration) {
            (parameters::Frame::Extension(frame), Some(contract)) => {
                frame.bind_checked_contract(contract);
            }
            (parameters::Frame::Extension(_), None) | (_, Some(_)) => {
                unreachable!("validated cipher destination declaration")
            }
            (_, None) => {}
        }
        let key = CipherLease::from_checked_record(key);
        let mut result = CipherOperation::new(key, self.frame, CipherOutputPlan::MechanismBound);
        result.input = self.input;
        result.stage = self.stage;
        result.used = self.used;
        result.activity = NativeActivity::Active;
        result
    }
}
