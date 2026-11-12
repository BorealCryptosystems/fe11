// SPDX-License-Identifier: Apache-2.0
//! Pointer-free signature parameters and exact retained-call negotiation.
use super::{Limits, Reader, Writer};
use crate::mechanism_extension::graph::{snapshot::SnapshotRecipe, OwnedGraph};
use crate::{Error, Result};

#[derive(Clone, Copy)]
pub(in crate::advanced) enum Graph<'a> {
    Live(&'a OwnedGraph),
    Encoded(&'a [u8]),
}
impl<'a> Graph<'a> {
    pub(in crate::advanced) fn write(self, writer: &mut Writer<'_>) -> Result<()> {
        match self {
            Self::Encoded(bytes) => {
                SnapshotRecipe::decode(bytes)?;
                writer.bytes(bytes)
            }
            Self::Live(graph) => writer.generated_bytes(graph.snapshot_bytes()?, |write| {
                graph.write_snapshot(&mut |bytes| write(bytes))
            }),
        }
    }
    pub(in crate::advanced) fn encoded(self) -> Result<&'a [u8]> {
        match self {
            Self::Encoded(bytes) => Ok(bytes),
            Self::Live(_) => Err(Error::Rejected(crate::RejectionReason::OperationRecord(
                crate::OperationRecordRejection::ReconstructionRequiresEncodedGraph,
            ))),
        }
    }
}

#[derive(Clone, Copy)]
pub(in crate::advanced) enum SignaturePhase {
    Ready,
    Update,
    Terminal,
    Waiting {
        code: u64,
        required: usize,
        previous_capacity: usize,
    },
}

#[derive(Clone, Copy)]
pub(in crate::advanced) struct SignatureParameters<'a> {
    pub graph: Graph<'a>,
    pub edition: (u8, u8),
    pub caller_asserted: bool,
    pub mutates_key: bool,
    pub phase: SignaturePhase,
    pub query: bool,
    pub output_capacity: Option<usize>,
    pub maximum_output: usize,
    pub returned_length: u64,
}

fn width(value: u64) -> Result<usize> {
    usize::try_from(value).map_err(|_| {
        Error::Rejected(crate::RejectionReason::OperationRecord(
            crate::OperationRecordRejection::SignatureRecordWidth,
        ))
    })
}
impl<'a> SignatureParameters<'a> {
    pub(in crate::advanced) fn write(self, writer: &mut Writer<'_>) -> Result<()> {
        self.graph.write(writer)?;
        writer.u8(self.edition.0)?;
        writer.u8(self.edition.1)?;
        writer.u8(u8::from(self.caller_asserted))?;
        writer.u8(u8::from(self.mutates_key))?;
        match self.phase {
            SignaturePhase::Ready => writer.u8(0)?,
            SignaturePhase::Update => writer.u8(1)?,
            SignaturePhase::Terminal => writer.u8(2)?,
            SignaturePhase::Waiting {
                code,
                required,
                previous_capacity,
            } => {
                writer.u8(3)?;
                writer.u64(code)?;
                writer.u64(required as u64)?;
                writer.u64(previous_capacity as u64)?;
            }
        }
        writer.u8(u8::from(self.query))?;
        writer.optional_u64(self.output_capacity.map(|n| n as u64))?;
        writer.u64(self.maximum_output as u64)?;
        writer.u64(self.returned_length)
    }
    pub(in crate::advanced) fn read(reader: &mut Reader<'a>, limits: Limits) -> Result<Self> {
        let bytes = reader.bytes(limits.bytes)?;
        reader.inspect_graph(bytes)?;
        let graph = Graph::Encoded(bytes);
        let edition = (reader.u8()?, reader.u8()?);
        let caller_asserted = reader.boolean(crate::RejectionReason::OperationRecord(
            crate::OperationRecordRejection::SignatureLayoutProvenance,
        ))?;
        let mutates_key = reader.boolean(crate::RejectionReason::OperationRecord(
            crate::OperationRecordRejection::SignatureKeyEffect,
        ))?;
        let phase = match reader.u8()? {
            0 => SignaturePhase::Ready,
            1 => SignaturePhase::Update,
            2 => SignaturePhase::Terminal,
            3 => SignaturePhase::Waiting {
                code: reader.u64()?,
                required: width(reader.u64()?)?,
                previous_capacity: width(reader.u64()?)?,
            },
            _ => {
                return Err(Error::Rejected(crate::RejectionReason::OperationRecord(
                    crate::OperationRecordRejection::SignatureRecordPhase,
                )))
            }
        };
        Ok(Self {
            graph,
            edition,
            caller_asserted,
            mutates_key,
            phase,
            query: reader.boolean(crate::RejectionReason::OperationRecord(
                crate::OperationRecordRejection::SignatureOutputQuery,
            ))?,
            output_capacity: reader.optional_u64()?.map(width).transpose()?,
            maximum_output: width(reader.u64()?)?,
            returned_length: reader.u64()?,
        })
    }
}

/// Validate representation and continuation position. Key suitability and
/// native save/restore support remain decisions of the PKCS#11 module.
pub(in crate::advanced) fn validate(
    descriptor: super::Descriptor,
    keys: &super::KeyBindings<'_>,
    messages: &super::Messages<'_>,
    validation: Option<&super::ValidationRecord<'_>>,
    limits: Limits,
) -> Result<()> {
    use crate::MessageRoute;
    use fe11_sys::{CKR_BUFFER_TOO_SMALL, CKR_OK};
    if descriptor.family != super::Family::Signature
        || !matches!(descriptor.profile, 1..=3)
        || descriptor.active_flags != 0
        || descriptor.validation_requested
        || descriptor.carried_messages != 0
        || descriptor.cipher_options.is_some()
        || descriptor.digest_bits.is_some()
        || messages.len() != 1
        || keys.cipher.is_some()
        || keys.authentication.is_none()
    {
        return Err(Error::Rejected(crate::RejectionReason::OperationRecord(
            crate::OperationRecordRejection::SignatureRecordSections,
        )));
    }
    // A captured signature is not terminal yet. Its optional collector owns
    // one future observation and therefore has no completed observation here.
    if let Some(report) = validation {
        if report.maximum() != 1 || report.iter().next().is_some() {
            return Err(Error::Rejected(crate::RejectionReason::OperationRecord(
                crate::OperationRecordRejection::SignatureContinuationObservation,
            )));
        }
    }
    let message =
        messages
            .iter()
            .next()
            .ok_or(Error::Rejected(crate::RejectionReason::Restoration(
                crate::RestorationRejection::SignatureMessageAbsent,
            )))??;
    message.validate(limits)?;
    let p = message.params.signature.ok_or(Error::Rejected(
        crate::RejectionReason::OperationRecord(
            crate::OperationRecordRejection::SignatureRecordParametersAbsent,
        ),
    ))?;
    let m = message.params;
    if m.digest_output.is_some()
        || m.cipher_extension.is_some()
        || m.digest_extension.is_some()
        || m.message_init.is_some()
        || m.counter_bits.is_some()
        || m.nonce.is_some()
        || m.aad.is_some()
        || m.digest_oid.is_some()
        || m.tag_bits != 0
        || m.iv_generator.is_some()
        || m.iv_fixed_bits.is_some()
        || m.iv_initial.is_some()
        || m.hash.is_some()
        || m.mgf.is_some()
        || m.salt.is_some()
        || message.origin != super::NonceOrigin::None
        || message.state != super::MessageState::Engaged
        || message.next_fragment != 0
        || message.produced != 0
        || !message.result.is_empty()
        || message.residual_start != 0
        || message.residual_length != 0
        || descriptor.input.progress.output_bytes != 0
        || descriptor.input.progress.delivered_bytes != 0
        || descriptor.input.progress.key_inputs != 0
        || descriptor.size != p.output_capacity.unwrap_or(0)
        || message.expected != p.output_capacity.unwrap_or(0)
        || p.output_capacity
            .is_some_and(|capacity| capacity > limits.bytes)
        || p.output_capacity
            .is_some_and(|capacity| capacity > p.maximum_output)
    {
        return Err(Error::Rejected(crate::RejectionReason::OperationRecord(
            crate::OperationRecordRejection::SignatureRecordRepresentation,
        )));
    }
    crate::bounds::ck_length(p.output_capacity.unwrap_or(0))?;
    fe11_sys::CK_ULONG::try_from(p.returned_length).map_err(|_| {
        Error::Rejected(crate::RejectionReason::OperationRecord(
            crate::OperationRecordRejection::SignatureReturnedLengthWidth,
        ))
    })?;
    fe11_sys::CK_MECHANISM_TYPE::try_from(descriptor.mechanism).map_err(|_| {
        Error::Rejected(crate::RejectionReason::OperationRecord(
            crate::OperationRecordRejection::SignatureMechanismWidth,
        ))
    })?;
    if descriptor.profile == 1 && message.tag_or_signature.is_some()
        || descriptor.profile == 3 && message.tag_or_signature.is_none()
        || descriptor.profile != 1 && (p.query || p.maximum_output != 0)
        || message.route == MessageRoute::Single
            && descriptor.input.is_open()
            && !matches!(p.phase, SignaturePhase::Ready)
    {
        return Err(Error::Rejected(crate::RejectionReason::OperationRecord(
            crate::OperationRecordRejection::SignatureRecordOperands,
        )));
    }
    // A monobloc call has either not been issued, or has one retained sizing
    // submission. No input is counted as accepted before its terminal success.
    // Replacing output storage must not erase that submission or count it twice.
    if message.route == MessageRoute::Single
        && (descriptor.input.progress.input_bytes != 0
            || descriptor.input.progress.submissions
                != u64::from(descriptor.input.retained_submission))
    {
        return Err(Error::Rejected(crate::RejectionReason::OperationRecord(
            crate::OperationRecordRejection::SingleSignatureSubmissionCounters,
        )));
    }
    let (update, terminal) = functions(descriptor.profile, message.route)?;
    let (function, fragments, retained) = match p.phase {
        SignaturePhase::Ready => {
            if message.route == MessageRoute::Single {
                if !descriptor.input.is_open()
                    || !descriptor.input.incremental
                    || descriptor.input.progress.submissions != 0
                    || descriptor.input.progress.input_bytes != 0
                {
                    return Err(Error::Rejected(crate::RejectionReason::OperationRecord(
                        crate::OperationRecordRejection::SingleSignatureReadyPhase,
                    )));
                }
                (terminal, 0, false)
            } else {
                (update, 0, false)
            }
        }
        SignaturePhase::Update => {
            if message.route != MessageRoute::Multipart {
                return Err(Error::Rejected(crate::RejectionReason::OperationRecord(
                    crate::OperationRecordRejection::SingleSignatureUpdatePhase,
                )));
            }
            (update, 1, false)
        }
        SignaturePhase::Terminal => {
            if descriptor.input.is_open() {
                return Err(Error::Rejected(crate::RejectionReason::OperationRecord(
                    crate::OperationRecordRejection::SignatureTerminalInputOpen,
                )));
            }
            let retained =
                message.route == MessageRoute::Single && descriptor.input.retained_submission;
            if retained && (descriptor.profile != 1 || p.query) {
                return Err(Error::Rejected(crate::RejectionReason::OperationRecord(
                    crate::OperationRecordRejection::SignatureTerminalSizingContinuation,
                )));
            }
            (
                terminal,
                usize::from(message.route == MessageRoute::Single),
                retained,
            )
        }
        SignaturePhase::Waiting {
            code,
            required,
            previous_capacity,
        } => {
            if descriptor.profile != 1
                || p.output_capacity.is_some()
                || descriptor.input.is_open()
                || p.returned_length != required as u64
                || previous_capacity > p.maximum_output
                || !(code == CKR_BUFFER_TOO_SMALL as u64 || code == CKR_OK as u64 && p.query)
                || p.query && previous_capacity != 0
            {
                return Err(Error::Rejected(crate::RejectionReason::OperationRecord(
                    crate::OperationRecordRejection::SignatureRetainedSizingResponse,
                )));
            }
            crate::bounds::ck_length(required)?;
            (
                terminal,
                usize::from(message.route == MessageRoute::Single),
                message.route == MessageRoute::Single,
            )
        }
    };
    if descriptor.phase.name() != function
        || message.fragments.len() != fragments
        || descriptor.input.retained_submission != retained
        || !matches!(p.phase, SignaturePhase::Waiting { .. }) && p.output_capacity.is_none()
        || p.query && p.output_capacity.is_some_and(|capacity| capacity != 0)
        || matches!(p.phase, SignaturePhase::Terminal)
            && descriptor.profile != 1
            && message.tag_or_signature.is_none()
    {
        return Err(Error::Rejected(crate::RejectionReason::OperationRecord(
            crate::OperationRecordRejection::SignatureContinuationPosition,
        )));
    }
    Ok(())
}

pub(in crate::advanced) fn functions(
    profile: u8,
    route: crate::MessageRoute,
) -> Result<(&'static str, &'static str)> {
    use crate::MessageRoute::{Multipart, Single};
    Ok(match (profile, route) {
        (1, Single) => ("C_SignUpdate", "C_Sign"),
        (1, Multipart) => ("C_SignUpdate", "C_SignFinal"),
        (2, Single) => ("C_VerifyUpdate", "C_Verify"),
        (2, Multipart) => ("C_VerifyUpdate", "C_VerifyFinal"),
        (3, Single) => ("C_VerifySignatureUpdate", "C_VerifySignature"),
        (3, Multipart) => ("C_VerifySignatureUpdate", "C_VerifySignatureFinal"),
        _ => {
            return Err(Error::Rejected(crate::RejectionReason::OperationRecord(
                crate::OperationRecordRejection::SignatureRecordKind,
            )))
        }
    })
}
