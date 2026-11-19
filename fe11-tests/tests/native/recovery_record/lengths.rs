// SPDX-License-Identifier: Apache-2.0
//! Alter one length/progression field of a genuinely captured recovery record.
//! The altered bytes are parsed only; they are never authenticated or restored.
use super::*;

fn word(bytes: &[u8], offset: usize) -> std::result::Result<u64, Failure> {
    let end = offset
        .checked_add(8)
        .ok_or(Failure::Input("recovery_word_end"))?;
    let part = bytes
        .get(offset..end)
        .ok_or(Failure::Input("recovery_word_range"))?;
    Ok(u64::from_be_bytes(
        part.try_into()
            .map_err(|_| Failure::Input("recovery_word_width"))?,
    ))
}

impl Fixture {
    pub(super) fn length_guard(
        &self,
        module: &Module,
        case: &Case,
    ) -> std::result::Result<(), Failure> {
        require(self.old_closed, "length_guard_live_old_owner")?;
        let before = module.call_counts()?;
        let positive = ParsedRecord::parse(module, &self.bytes, LIMITS)?;
        require(
            positive.as_bytes() == self.bytes,
            "length_guard_positive_bytes",
        )?;
        // The fixture contains exactly one 32-byte fragment and no result,
        // tag, residual or validation. Verify this entire tail before using
        // its field offsets; a layout change cannot silently retarget a test.
        let start = self
            .bytes
            .len()
            .checked_sub(90)
            .ok_or(Failure::Input("recovery_tail_short"))?;
        let mut tail = Vec::new();
        tail.extend_from_slice(&1u32.to_be_bytes());
        tail.extend_from_slice(&32u64.to_be_bytes());
        tail.extend_from_slice(&case.ciphertext);
        tail.extend_from_slice(&0u32.to_be_bytes());
        tail.extend_from_slice(&0u64.to_be_bytes());
        tail.extend_from_slice(&16u64.to_be_bytes());
        tail.extend_from_slice(&0u64.to_be_bytes());
        tail.push(0);
        tail.extend_from_slice(&[0; 16]);
        tail.push(0);
        require(
            self.bytes.get(start..) == Some(tail.as_slice()),
            "recovery_tail_layout",
        )?;
        require(
            self.bytes.get(..8) == Some(b"BPKIOP09"),
            "recovery_header_version",
        )?;
        let payload = word(&self.bytes, 9)?;
        require(
            payload == (self.bytes.len() - 17) as u64,
            "recovery_payload_control",
        )?;
        let end = self.bytes.len();
        let (offset, width, value, reason): (usize, usize, u64, RejectionReason) =
            match case.action.as_str() {
                "length_payload_short" => (
                    9,
                    8,
                    payload - 1,
                    OperationRecordRejection::RecordPayloadLength.into(),
                ),
                "length_payload_long" => (
                    9,
                    8,
                    payload + 1,
                    OperationRecordRejection::RecordPayloadLength.into(),
                ),
                "length_consumed" => (
                    end - 46,
                    4,
                    1,
                    MessageRecordRejection::RecordPlannedMessageProgressed.into(),
                ),
                "length_produced" => (
                    end - 42,
                    8,
                    1,
                    MessageRecordRejection::RecordMessageProgression.into(),
                ),
                "length_capacity" => (
                    end - 34,
                    8,
                    0,
                    CheckpointFormatRejection::RecordDualCapacity.into(),
                ),
                "length_residual" => (
                    end - 9,
                    8,
                    1,
                    MessageRecordRejection::RecordResidualRange.into(),
                ),
                _ => return Err(Failure::Input("recovery_length_action")),
            };
        let mut negative = self.bytes.clone();
        let value = value.to_be_bytes();
        negative[offset..offset + width].copy_from_slice(&value[8 - width..]);
        require(
            negative.len() == self.bytes.len() && negative != self.bytes,
            "recovery_mutation_identity",
        )?;
        match ParsedRecord::parse(module, &negative, LIMITS) {
            Err(Error::Rejected(actual)) if actual == reason => (),
            Err(error) => return Err(error.into()),
            Ok(_) => return Err(Failure::Oracle("recovery_inconsistent_length_accepted")),
        }
        require(
            module.call_counts()? == before && positive.as_bytes() == self.bytes,
            "recovery_length_mutation_dispatched_or_changed_owner",
        )
    }
}
