// SPDX-License-Identifier: Apache-2.0
//! Parent message state independent of the retained, possibly empty row set.
//!
//! These checks establish structural coherence only. Consumed input is absent;
//! its counters are not evidence that an imported native state is authentic.
use super::{
    Descriptor, Family, Function, KeyBindings, Limits, MessageState, Messages, NonceOrigin,
    Parameters, Reader, ValidationRecord, Writer,
};
use crate::advanced::MessageRoute;
use crate::{bounds, Error, Result};

#[derive(Clone, Copy, PartialEq, Eq)]
pub(in crate::advanced) enum StreamBoundary {
    Init,
    Ready,
    Begin,
    Receive,
    Single,
    Update,
    Last,
    Finish,
}

impl StreamBoundary {
    pub(in crate::advanced) fn function(self, verify: bool) -> &'static str {
        match (self, verify) {
            (Self::Init | Self::Ready, false) => "C_MessageSignInit",
            (Self::Init | Self::Ready, true) => "C_MessageVerifyInit",
            (Self::Begin | Self::Receive, false) => "C_SignMessageBegin",
            (Self::Begin | Self::Receive, true) => "C_VerifyMessageBegin",
            (Self::Single, false) => "C_SignMessage",
            (Self::Single, true) => "C_VerifyMessage",
            (Self::Update | Self::Last, false) => "C_SignMessageNext",
            (Self::Update | Self::Last, true) => "C_VerifyMessageNext",
            (Self::Finish, false) => "C_MessageSignFinal",
            (Self::Finish, true) => "C_MessageVerifyFinal",
        }
    }

    pub(in crate::advanced) fn has_message(self) -> bool {
        matches!(
            self,
            Self::Begin | Self::Receive | Self::Single | Self::Update | Self::Last
        )
    }

    pub(in crate::advanced) fn has_fragment(self) -> bool {
        matches!(self, Self::Single | Self::Update | Self::Last)
    }

    pub(in crate::advanced) fn terminal_message(self) -> bool {
        matches!(self, Self::Single | Self::Last)
    }

    fn wire(self) -> u8 {
        match self {
            Self::Init => 0,
            Self::Ready => 1,
            Self::Begin => 2,
            Self::Receive => 3,
            Self::Single => 4,
            Self::Update => 5,
            Self::Last => 6,
            Self::Finish => 7,
        }
    }

    fn read(reader: &mut Reader<'_>) -> Result<Self> {
        Ok(match reader.u8()? {
            0 => Self::Init,
            1 => Self::Ready,
            2 => Self::Begin,
            3 => Self::Receive,
            4 => Self::Single,
            5 => Self::Update,
            6 => Self::Last,
            7 => Self::Finish,
            _ => {
                return Err(Error::Rejected(crate::RejectionReason::MessageRecord(
                    crate::MessageRecordRejection::RecordMessageStreamBoundary,
                )))
            }
        })
    }
}

#[derive(Clone, Copy)]
pub(in crate::advanced) struct MessageStream<'a> {
    pub boundary: StreamBoundary,
    pub route: MessageRoute,
    pub invalid: bool,
    pub rejections: super::MessageRejections<'a>,
    // Init parameters exist before the first message and survive between rows.
    pub parameters: Parameters<'a>,
}

impl<'a> MessageStream<'a> {
    pub(super) fn write(self, writer: &mut Writer<'_>) -> Result<()> {
        writer.u8(self.boundary.wire())?;
        writer.u8(match self.route {
            MessageRoute::Single => 0,
            MessageRoute::Multipart => 1,
        })?;
        writer.u8(u8::from(self.invalid))?;
        self.parameters.write(writer)?;
        self.rejections.write(writer)
    }

    pub(super) fn read(reader: &mut Reader<'a>, limits: Limits, refusals: bool) -> Result<Self> {
        Ok(Self {
            boundary: StreamBoundary::read(reader)?,
            route: match reader.u8()? {
                0 => MessageRoute::Single,
                1 => MessageRoute::Multipart,
                _ => {
                    return Err(Error::Rejected(crate::RejectionReason::MessageRecord(
                        crate::MessageRecordRejection::RecordMessageStreamRoute,
                    )))
                }
            },
            invalid: reader.boolean(crate::RejectionReason::MessageRecord(
                crate::MessageRecordRejection::RecordMessageStreamInvalidResult,
            ))?,
            parameters: Parameters::read(reader, limits)?,
            rejections: if refusals {
                super::MessageRejections::read(reader, limits)?
            } else {
                super::MessageRejections::Legacy
            },
        })
    }

    pub(super) fn validate(
        self,
        descriptor: Descriptor,
        keys: &KeyBindings<'_>,
        messages: &Messages<'_>,
        report: Option<&ValidationRecord<'_>>,
        limits: Limits,
        detached: bool,
        terminal: Option<bool>,
    ) -> Result<()> {
        use StreamBoundary::*;
        let verify = descriptor.family == Family::MessageVerify;
        if !matches!(
            descriptor.family,
            Family::MessageSign | Family::MessageVerify
        ) || !descriptor.input.incremental
            || descriptor.carried_messages != 0
            || descriptor.cipher_options.is_some()
            || descriptor.digest_bits.is_some()
            || descriptor.phase != Function::from_name(self.boundary.function(verify))?
        {
            return Err(Error::Rejected(crate::RejectionReason::MessageRecord(
                crate::MessageRecordRejection::RecordMessageStreamAssociation,
            )));
        }
        descriptor.keys(keys, limits)?;
        descriptor.signature_parameters(&self.parameters)?;
        crate::advanced::messages::pss::record_selection(descriptor, messages)?;
        let route_valid = match self.route {
            MessageRoute::Single => matches!(self.boundary, Init | Ready | Single | Finish),
            MessageRoute::Multipart => !matches!(self.boundary, Single),
        };
        if !route_valid
            || self.boundary == Init && (!detached || messages.len() != 0)
            || detached && matches!(self.boundary, Ready | Receive)
            || terminal.is_some_and(|valid| self.boundary != Finish || valid == self.invalid)
            || descriptor.input.is_open() != (self.boundary != Finish)
            || self.invalid && !verify
        {
            return Err(Error::Rejected(crate::RejectionReason::MessageRecord(
                crate::MessageRecordRejection::RecordMessageStreamDisposition,
            )));
        }
        if let Some(output) = messages.output() {
            if !self.boundary.terminal_message() || terminal.is_some() {
                return Err(Error::Rejected(crate::RejectionReason::MessageRecord(
                    crate::MessageRecordRejection::RecordMessageStreamOutputPhase,
                )));
            }
            output.validate(descriptor, messages, detached)?;
        }
        let active = self.boundary.has_message();
        let completed = messages
            .len()
            .checked_sub(usize::from(active))
            .ok_or(Error::Rejected(crate::RejectionReason::MessageRecord(
                crate::MessageRecordRejection::RecordMessageStreamRowAbsent,
            )))?;
        let mut output_bytes = 0u128;
        let mut refused_begin = 0usize;
        let mut refused_rows = 0usize;
        let mut refusals = self.rejections.iter(messages.len())?;
        for (index, message) in messages.iter().enumerate() {
            let message = message?;
            let finished = index < completed;
            let rejection = refusals.next().ok_or(Error::Rejected(
                crate::RejectionReason::MessageRecord(
                    crate::MessageRecordRejection::MessageRefusalRowAbsent,
                ),
            ))??;
            if let Some(rejection) = rejection {
                let (begin, data) = match (verify, self.route) {
                    (false, MessageRoute::Single) => (None, "C_SignMessage"),
                    (true, MessageRoute::Single) => (None, "C_VerifyMessage"),
                    (false, MessageRoute::Multipart) => {
                        (Some("C_SignMessageBegin"), "C_SignMessageNext")
                    }
                    (true, MessageRoute::Multipart) => {
                        (Some("C_VerifyMessageBegin"), "C_VerifyMessageNext")
                    }
                };
                let code = fe11_sys::CK_RV::try_from(rejection.code).map_err(|_| {
                    Error::Rejected(crate::RejectionReason::MessageRecord(
                        crate::MessageRecordRejection::MessageRefusalCodeWidth,
                    ))
                })?;
                if !finished
                    || code == fe11_sys::CKR_OK
                    || (verify
                        && self.route == MessageRoute::Single
                        && matches!(
                            code,
                            fe11_sys::CKR_SIGNATURE_INVALID | fe11_sys::CKR_SIGNATURE_LEN_RANGE
                        ))
                    || (!verify
                        && self.route == MessageRoute::Single
                        && code == fe11_sys::CKR_BUFFER_TOO_SMALL)
                    || !crate::native_return::call_memory_returned(code)
                    || crate::native_return::native_context_scope(code)
                        != crate::native_return::FailureScope::None
                    || (Some(rejection.function) != begin && rejection.function != data)
                    || message.produced != 0
                    || !message.result.is_empty()
                {
                    return Err(Error::Rejected(crate::RejectionReason::MessageRecord(
                        crate::MessageRecordRejection::MessageRefusalDisposition,
                    )));
                }
                refused_rows = refused_rows.checked_add(1).ok_or(Error::Rejected(
                    crate::RejectionReason::MessageRecord(
                        crate::MessageRecordRejection::MessageRefusalCount,
                    ),
                ))?;
                if Some(rejection.function) == begin {
                    refused_begin = refused_begin.checked_add(1).ok_or(Error::Rejected(
                        crate::RejectionReason::MessageRecord(
                            crate::MessageRecordRejection::MessageRefusalCount,
                        ),
                    ))?;
                }
            }
            let state = if finished {
                MessageState::Finished
            } else if matches!(self.boundary, Single | Begin) {
                MessageState::Planned
            } else {
                MessageState::Engaged
            };
            descriptor.signature_parameters(&message.params)?;
            if message.params.hash != self.parameters.hash
                || message.params.mgf != self.parameters.mgf
                || message.params.salt != self.parameters.salt
                || message.params.tag_bits != self.parameters.tag_bits
                || message.route != self.route
                || message.origin != NonceOrigin::None
                || message.state != state
                || message.next_fragment != 0
                || message.fragments.len() != usize::from(!finished && self.boundary.has_fragment())
                || message.residual_start != 0
                || message.residual_length != 0
                || !finished && message.produced != 0
            {
                return Err(Error::Rejected(crate::RejectionReason::MessageRecord(
                    crate::MessageRecordRejection::RecordMessageStreamRow,
                )));
            }
            for part in message.fragments.iter() {
                bounds::ck_length(part?.len())?;
            }
            bounds::ck_length(message.expected)?;
            if verify {
                let needs_signature = !finished && self.boundary.terminal_message();
                if message.expected != 0
                    || message.produced != 0
                    || message.tag_or_signature.is_some() != needs_signature
                {
                    return Err(Error::Rejected(crate::RejectionReason::MessageRecord(
                        crate::MessageRecordRejection::RecordMessageStreamVerificationInput,
                    )));
                }
                if let Some(signature) = message.tag_or_signature {
                    bounds::ck_length(signature.len())?;
                }
            } else if (finished && message.tag_or_signature != Some(message.result))
                || (!finished && message.tag_or_signature.is_some())
            {
                return Err(Error::Rejected(crate::RejectionReason::MessageRecord(
                    crate::MessageRecordRejection::RecordMessageStreamSignatureResult,
                )));
            }
            output_bytes =
                output_bytes
                    .checked_add(message.produced as u128)
                    .ok_or(Error::Rejected(crate::RejectionReason::MessageRecord(
                        crate::MessageRecordRejection::RecordMessageStreamOutputCounter,
                    )))?;
        }
        let retained = detached && self.boundary.has_fragment() || messages.output().is_some();
        let progress = descriptor.input.progress;
        let completed_data = completed.checked_sub(refused_begin).ok_or(Error::Rejected(
            crate::RejectionReason::MessageRecord(
                crate::MessageRecordRejection::MessageRefusalCount,
            ),
        ))?;
        let minimum = u64::try_from(completed_data)
            .ok()
            .and_then(|n| n.checked_add(u64::from(retained)))
            .ok_or(Error::Rejected(crate::RejectionReason::MessageRecord(
                crate::MessageRecordRejection::RecordMessageStreamSubmissionWidth,
            )))?;
        if descriptor.input.retained_submission != retained
            || progress.key_inputs != 0
            || progress.delivered_bytes != 0
            || progress.output_bytes != output_bytes
            || progress.submissions < minimum
            || self.route == MessageRoute::Single && progress.submissions != minimum
            || progress.submissions == 0 && progress.input_bytes != 0
            || messages.len() == 0 && progress.submissions != 0
            || self.invalid && completed == refused_rows
            || self.route == MessageRoute::Single
                && completed == refused_rows
                && progress.input_bytes != 0
        {
            return Err(Error::Rejected(crate::RejectionReason::MessageRecord(
                crate::MessageRecordRejection::RecordMessageStreamProgress,
            )));
        }
        if let Some(report) = report {
            if messages.len().checked_add(1) != Some(report.maximum()) {
                return Err(Error::Rejected(crate::RejectionReason::MessageRecord(
                    crate::MessageRecordRejection::RecordMessageStreamReportCapacity,
                )));
            }
            let function = match self.route {
                MessageRoute::Single => Single,
                MessageRoute::Multipart => Last,
            }
            .function(verify);
            let mut observations = report.iter();
            let mut refusals = self.rejections.iter(messages.len())?;
            for index in 0..completed {
                if refusals
                    .next()
                    .ok_or(Error::Rejected(crate::RejectionReason::MessageRecord(
                        crate::MessageRecordRejection::MessageRefusalRowAbsent,
                    )))??
                    .is_some()
                {
                    continue;
                }
                let observation = observations.next().ok_or(Error::Rejected(
                    crate::RejectionReason::MessageRecord(
                        crate::MessageRecordRejection::RecordMessageStreamObservationAbsent,
                    ),
                ))??;
                if observation.function != function || observation.message_index != Some(index) {
                    return Err(Error::Rejected(crate::RejectionReason::MessageRecord(
                        crate::MessageRecordRejection::RecordMessageStreamObservationAssociation,
                    )));
                }
            }
            if observations.next().is_some() {
                return Err(Error::Rejected(crate::RejectionReason::MessageRecord(
                    crate::MessageRecordRejection::RecordMessageStreamUnexpectedObservation,
                )));
            }
        } else if terminal.is_some() {
            return Err(Error::Rejected(crate::RejectionReason::MessageRecord(
                crate::MessageRecordRejection::TerminalMessageStreamReportAbsent,
            )));
        }
        Ok(())
    }
}
