// SPDX-License-Identifier: Apache-2.0
//! Synthetic wire input validates parsing only, never native state provenance.
use super::{
    arguments::hex,
    outcome::{self, Failure},
    report::{Observation, Phase, PhaseResult, Producer, Report},
};
use fe11::*;
#[path = "record_mutations.rs"]
mod record_mutations;
use std::{
    fs::File,
    io::{self, Read, Write},
    path::Path,
};

struct Case {
    positive: Vec<u8>,
    negative: Vec<u8>,
    reason: RejectionReason,
    all_prefixes: bool,
}
impl Case {
    fn read(path: &Path) -> std::result::Result<Self, Failure> {
        let mut bytes = Vec::new();
        File::open(path)
            .map_err(|_| Failure::Input("record_fixture_open"))?
            .take(8193)
            .read_to_end(&mut bytes)
            .map_err(|_| Failure::Input("record_fixture_read"))?;
        if bytes.len() > 8192 {
            return Err(Failure::Input("record_fixture_size"));
        }
        let text =
            std::str::from_utf8(&bytes).map_err(|_| Failure::Input("record_fixture_encoding"))?;
        let fields: Vec<_> = text.split_terminator('\n').collect();
        if fields.len() != 4 {
            return Err(Failure::Input("record_fixture_fields"));
        }
        let reason = match fields[0] {
            "open_complete" => OperationOwnershipRejection::OpenCompleteInputStream.into(),
            "incremental" => OperationOwnershipRejection::StreamIncrementalRoute.into(),
            "retained" => OperationOwnershipRejection::StreamRetainedInput.into(),
            "closure" => OperationOwnershipRejection::StreamInputClosureEncoding.into(),
            "progress" => OperationOwnershipRejection::StreamProgressEncoding.into(),
            "internal_kind" => PersistenceRejection::UnsupportedAuthenticatedRecordKind.into(),
            "graph_version" => MechanismExtensionsRejection::GraphSnapshotAbiOrVersion.into(),
            "all_prefixes" => OperationRecordRejection::TruncatedRecord.into(),
            "MessageRecordRejection::RecordFinishedMessageIncomplete" => {
                MessageRecordRejection::RecordFinishedMessageIncomplete.into()
            }
            "CheckpointFormatRejection::RecordUnexpectedResidual" => {
                CheckpointFormatRejection::RecordUnexpectedResidual.into()
            }
            "CheckpointFormatRejection::RecordAeadOutput" => {
                CheckpointFormatRejection::RecordAeadOutput.into()
            }
            "DigestContinuationRejection::RecordDigestProfile" => {
                DigestContinuationRejection::RecordDigestProfile.into()
            }
            "DigestContinuationRejection::RecordNativeDigestMechanism" => {
                DigestContinuationRejection::RecordNativeDigestMechanism.into()
            }
            "DigestContinuationRejection::RecordDigestWidth" => {
                DigestContinuationRejection::RecordDigestWidth.into()
            }
            "CheckpointFormatRejection::RecordDigestParameters" => {
                CheckpointFormatRejection::RecordDigestParameters.into()
            }
            "CheckpointFormatRejection::RecordCarriedPrefix" => {
                CheckpointFormatRejection::RecordCarriedPrefix.into()
            }
            "CheckpointFormatRejection::RecordOperationFamily" => {
                CheckpointFormatRejection::RecordOperationFamily.into()
            }
            "CheckpointFormatRejection::DigestOutputOnAnotherFamily" => {
                CheckpointFormatRejection::DigestOutputOnAnotherFamily.into()
            }
            "CheckpointFormatRejection::RecordValidationRequest" => {
                CheckpointFormatRejection::RecordValidationRequest.into()
            }
            "MessageRecordRejection::CipherExtensionParameters" => {
                MessageRecordRejection::CipherExtensionParameters.into()
            }
            "MessageRecordRejection::DigestExtensionParameters" => {
                MessageRecordRejection::DigestExtensionParameters.into()
            }
            "MessageRecordRejection::DigestOutputStorage" => {
                MessageRecordRejection::DigestOutputStorage.into()
            }
            "MessageRecordRejection::MessageOutputContinuation" => {
                MessageRecordRejection::MessageOutputContinuation.into()
            }
            "MessageRecordRejection::MessageStreamParent" => {
                MessageRecordRejection::MessageStreamParent.into()
            }
            "MessageRecordRejection::RecordMessageCount" => {
                MessageRecordRejection::RecordMessageCount.into()
            }
            "MessageRecordRejection::RecordMessageInitLayout" => {
                MessageRecordRejection::RecordMessageInitLayout.into()
            }
            "MessageRecordRejection::RecordMessageProgression" => {
                MessageRecordRejection::RecordMessageProgression.into()
            }
            "MessageRecordRejection::RecordMessageRoute" => {
                MessageRecordRejection::RecordMessageRoute.into()
            }
            "MessageRecordRejection::RecordMessageState" => {
                MessageRecordRejection::RecordMessageState.into()
            }
            "MessageRecordRejection::RecordNonceOrigin" => {
                MessageRecordRejection::RecordNonceOrigin.into()
            }
            "MessageRecordRejection::RecordResidualRange" => {
                MessageRecordRejection::RecordResidualRange.into()
            }
            "MessageRecordRejection::SignatureRecordParameters" => {
                MessageRecordRejection::SignatureRecordParameters.into()
            }
            "OperationRecordRejection::RecordByteCeiling" => {
                OperationRecordRejection::RecordByteCeiling.into()
            }
            "OperationRecordRejection::RecordCipherOptionsTag" => {
                OperationRecordRejection::RecordCipherOptionsTag.into()
            }
            "OperationRecordRejection::RecordCount" => OperationRecordRejection::RecordCount.into(),
            "OperationRecordRejection::RecordKind" => OperationRecordRejection::RecordKind.into(),
            "OperationRecordRejection::RecordOption" => {
                OperationRecordRejection::RecordOption.into()
            }
            "OperationRecordRejection::RecordPayloadLength" => {
                OperationRecordRejection::RecordPayloadLength.into()
            }
            "OperationRecordRejection::RecordPhaseCode" => {
                OperationRecordRejection::RecordPhaseCode.into()
            }
            "OperationRecordRejection::RecordSessionState" => {
                OperationRecordRejection::RecordSessionState.into()
            }
            "OperationRecordRejection::RecordTrailingBytes" => {
                OperationRecordRejection::RecordTrailingBytes.into()
            }
            "OperationRecordRejection::RecordValidationMode" => {
                OperationRecordRejection::RecordValidationMode.into()
            }
            "OperationRecordRejection::RecordVersion" => {
                OperationRecordRejection::RecordVersion.into()
            }
            "OperationRecordRejection::TruncatedRecord" => {
                OperationRecordRejection::TruncatedRecord.into()
            }
            _ => return Err(Failure::Input("record_fixture_reason")),
        };
        let edits = fields[1].strip_prefix("edits:");
        let offset = if edits.is_some() {
            0
        } else {
            fields[1]
                .parse::<usize>()
                .map_err(|_| Failure::Input("record_fixture_offset"))?
        };
        let positive = hex(fields[2], 2048).map_err(Failure::Input)?;
        let negative = hex(fields[3], 2048).map_err(Failure::Input)?;
        // Numeric offsets retain the one-byte mutation contract. Explicit edits
        // allow one logical length relationship, including its envelope size;
        // each mode verifies the declared transformation before parsing.
        let all_prefixes = fields[0] == "all_prefixes";
        if let Some(specification) = edits {
            if all_prefixes || positive.len() < 17 {
                return Err(Failure::Input("record_mutation_mode"));
            }
            record_mutations::verify(specification, &positive, &negative)?;
        } else if all_prefixes {
            // The complete frame is retained twice as an explicit fixture
            // control. Prefixes are cut without rewriting its length field.
            if positive.len() < 17 || positive != negative || offset != positive.len() {
                return Err(Failure::Input("record_fixture_prefix_control"));
            }
        } else if positive.len() < 17
            || positive.len() != negative.len()
            || offset >= positive.len()
            || positive
                .iter()
                .zip(&negative)
                .enumerate()
                .any(|(i, (a, b))| (a != b) != (i == offset))
        {
            return Err(Failure::Input("record_fixture_single_mutation"));
        }
        Ok(Self {
            positive,
            negative,
            reason,
            all_prefixes,
        })
    }
}

pub fn execute<W: Write>(module: Module, path: &Path, mut report: Report<W>) -> io::Result<bool> {
    let mut parsed = None;
    let setup = (|| -> std::result::Result<Case, Failure> {
        let case = Case::read(path)?;
        let counts = module.call_counts()?;
        let positive = ParsedRecord::parse(
            &module,
            &case.positive,
            RecordLimits {
                bytes: case.positive.len(),
                messages: 1,
                fragments: 1,
            },
        )?;
        if positive.as_bytes() != case.positive || module.call_counts()? != counts {
            return Err(Failure::Oracle("record_structural_positive"));
        }
        parsed = Some(positive);
        Ok(case)
    })();
    let body = match &setup {
        Err(_) => Ok(()),
        Ok(case) => (|| -> std::result::Result<(), Failure> {
            let counts = module.call_counts()?;
            if case.all_prefixes {
                for end in 0..case.positive.len() {
                    // A partial 17-byte header cannot be decoded. With the
                    // complete header, its original payload length must reject
                    // every shorter payload before semantic parsing begins.
                    let reason = if end < 17 {
                        OperationRecordRejection::TruncatedRecord
                    } else {
                        OperationRecordRejection::RecordPayloadLength
                    };
                    match ParsedRecord::parse(
                        &module,
                        &case.positive[..end],
                        RecordLimits {
                            bytes: case.positive.len(),
                            messages: 1,
                            fragments: 1,
                        },
                    ) {
                        Err(Error::Rejected(actual)) if actual == reason.into() => (),
                        Err(error) => return Err(error.into()),
                        Ok(_) => return Err(Failure::Oracle("record_truncated_prefix_accepted")),
                    }
                    if module.call_counts()? != counts {
                        return Err(Failure::Oracle("record_prefix_dispatched"));
                    }
                }
            } else {
                match ParsedRecord::parse(
                    &module,
                    &case.negative,
                    RecordLimits {
                        bytes: case.negative.len(),
                        messages: 1,
                        fragments: 1,
                    },
                ) {
                    Err(Error::Rejected(reason)) if reason == case.reason => (),
                    Err(error) => return Err(error.into()),
                    Ok(_) => return Err(Failure::Oracle("record_semantic_negative_accepted")),
                }
            }
            if module.call_counts()? != counts
                || parsed
                    .as_ref()
                    .ok_or(Failure::Input("record_positive_owner"))?
                    .as_bytes()
                    != case.positive
            {
                return Err(Failure::Oracle(
                    "record_negative_changed_positive_or_dispatched",
                ));
            }
            Ok(())
        })(),
    };
    // These synthetic bytes must never be authenticated, imported or restored.
    // Dropping the parsed owner releases its charged buffer before module close.
    drop(parsed);
    let cleanup = module.close().map_err(Failure::from);
    if let Err(error) = &setup {
        outcome::record(&mut report, Phase::Setup, error)?;
    }
    if let Err(error) = &body {
        outcome::record(&mut report, Phase::Body, error)?;
    }
    if let Err(error) = &cleanup {
        outcome::record(&mut report, Phase::Cleanup, error)?;
    }
    if setup.is_ok() {
        report.observation(
            Phase::Body,
            "structural_positive_and_exact_semantic_refusal",
            Producer::Fe11Local,
            Observation::Boolean(body.is_ok()),
        )?;
    }
    if let Ok(case) = &setup {
        if case.all_prefixes && body.is_ok() {
            report.observation(
                Phase::Body,
                "truncated_prefixes_rejected",
                Producer::Fe11Local,
                Observation::Number(case.positive.len() as u64),
            )?;
        }
    }
    report.finish(
        if setup.is_ok() {
            PhaseResult::Passed
        } else {
            PhaseResult::Failed
        },
        if setup.is_err() {
            PhaseResult::NotExecuted
        } else if body.is_ok() {
            PhaseResult::Passed
        } else {
            PhaseResult::Failed
        },
        if cleanup.is_ok() {
            PhaseResult::Passed
        } else {
            PhaseResult::Failed
        },
    )
}
