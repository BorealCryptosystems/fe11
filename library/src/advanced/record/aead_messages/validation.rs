// SPDX-License-Identifier: Apache-2.0
//! Relationships required before rebuilding an AEAD continuation from bytes.
//! These checks establish a representation, never native authentication success.
use super::{invalid, Boundary, Call, Initial, Record, Row, Selection, Target};
use crate::advanced::aead_parameters::CipherKind;
use crate::advanced::gcm::result::Disposition;
use crate::advanced::record::{
    Descriptor, Family, Function, KeyBindings, Limits, ValidationRecord,
};
use crate::{MessageRoute, Result};

impl Selection<'_> {
    /// Decryption ignores generation fields: its whole nonce is input. For
    /// encryption only the declared fixed prefix may be compared before the
    /// generated nonce has been established by a successful native return.
    pub(in crate::advanced) fn validate_nonce(self, actual: &[u8], decrypt: bool) -> Result<()> {
        if actual.len() != self.nonce.len() {
            return Err(invalid());
        }
        if decrypt || self.generator == 0 {
            return if actual == self.nonce {
                Ok(())
            } else {
                Err(invalid())
            };
        }
        let bits = usize::try_from(self.fixed_bits).map_err(|_| invalid())?;
        if bits > actual.len().checked_mul(8).ok_or_else(invalid)? {
            return Err(invalid());
        }
        let whole = bits / 8;
        let part = bits % 8;
        if actual[..whole] != self.nonce[..whole]
            || part != 0 && (actual[whole] ^ self.nonce[whole]) & (0xffu8 << (8 - part)) != 0
        {
            return Err(invalid());
        }
        Ok(())
    }

    fn validate_tag(self, kind: CipherKind, tag: Option<&[u8]>, decrypt: bool) -> Result<()> {
        if let Some(tag) = tag {
            if !decrypt || tag.len() != self.plan(kind)?.tag_bytes()? {
                return Err(invalid());
            }
        }
        Ok(())
    }
}

impl Row<'_> {
    fn validate(
        self,
        kind: CipherKind,
        decrypt: bool,
        complete: bool,
        boundary: Boundary,
        route: MessageRoute,
    ) -> Result<()> {
        let selection = self.selection.plan(kind)?;
        selection.validate(self.aad.len(), self.declared_length, decrypt)?;
        self.selection.validate_nonce(self.nonce, decrypt)?;
        self.selection
            .validate_tag(kind, self.expected_tag, decrypt)?;
        if self.tag.len() != selection.tag_bytes()?
            || self.expected_tag.is_some_and(|tag| tag != self.tag)
        {
            return Err(invalid());
        }
        let rejected = match self.disposition {
            Disposition::Candidate => false,
            Disposition::Rejected {
                rejection,
                discarded_output,
            } => {
                let code = fe11_sys::CK_RV::try_from(rejection.code).map_err(|_| invalid())?;
                let compatible = match (decrypt, route, rejection.function) {
                    (false, MessageRoute::Single, "C_EncryptMessage")
                    | (true, MessageRoute::Single, "C_DecryptMessage")
                    | (
                        false,
                        MessageRoute::Multipart,
                        "C_EncryptMessageBegin" | "C_EncryptMessageNext",
                    )
                    | (
                        true,
                        MessageRoute::Multipart,
                        "C_DecryptMessageBegin" | "C_DecryptMessageNext",
                    ) => true,
                    _ => false,
                };
                if !complete
                    || !compatible
                    || matches!(code, fe11_sys::CKR_OK | fe11_sys::CKR_BUFFER_TOO_SMALL)
                    || !crate::native_return::call_memory_returned(code)
                    || crate::native_return::native_context_scope(code)
                        != crate::native_return::FailureScope::None
                    || !self.output.is_empty()
                    || self.capacity != 0
                    || self.native_length != 0
                    || (route == MessageRoute::Single || rejection.function.ends_with("Begin"))
                        && discarded_output != 0
                {
                    return Err(invalid());
                }
                true
            }
        };
        if complete
            && !rejected
            && (self
                .accepted_input
                .is_some_and(|accepted| accepted != self.output.len() as u128)
                || kind == CipherKind::Ccm && self.output.len() != self.declared_length)
        {
            return Err(invalid());
        }
        if self.accepted_input.is_some_and(|accepted| {
            let before_data = !complete
                && matches!(
                    boundary,
                    Boundary::Begin(_)
                        | Boundary::Data(Call::Single(_))
                        | Boundary::Capacity {
                            call: Call::Single(_),
                            ..
                        }
                );
            let refused_before_data = matches!(self.disposition,
                Disposition::Rejected { rejection, .. }
                if route == MessageRoute::Single || rejection.function.ends_with("Begin"));
            (before_data || refused_before_data) && accepted != 0
        }) {
            return Err(invalid());
        }
        let terminal =
            !complete && matches!(boundary.call(), Some(Call::Single(_) | Call::Last(_)));
        if !complete
            && matches!(
                boundary,
                Boundary::Begin(_)
                    | Boundary::Data(Call::Single(_))
                    | Boundary::Capacity {
                        call: Call::Single(_),
                        ..
                    }
            )
            && !self.output.is_empty()
        {
            // Begin has no output; Single has no earlier successful data call.
            return Err(invalid());
        }
        if decrypt
            && (!rejected && complete || terminal || route == MessageRoute::Single)
            && self.expected_tag.is_none()
        {
            return Err(invalid());
        }
        let generated = !decrypt && selection.generated();
        let begun = !complete
            && matches!(
                boundary,
                Boundary::Receive(_)
                    | Boundary::Data(Call::Update(_) | Call::Last(_))
                    | Boundary::Capacity {
                        call: Call::Update(_) | Call::Last(_),
                        ..
                    }
            );
        // A refused Next still follows an established Begin. A refused Begin
        // or Single does not establish a generated nonce by itself.
        let refused_after_begin = matches!(
            self.disposition,
            Disposition::Rejected { rejection, .. } if rejection.function.ends_with("Next")
        );
        if self
            .observed_nonce
            .is_some_and(|nonce| !generated || nonce != self.nonce)
            || generated
                && (!rejected && complete || begun || refused_after_begin)
                && self.observed_nonce.is_none()
        {
            return Err(invalid());
        }
        // Missing output retains the original buffer and native required size.
        // Prepared output retains the old request, but has a new native length.
        if !complete {
            if matches!(boundary, Boundary::Data(_)) {
                let remaining = self
                    .capacity
                    .checked_sub(self.output.len())
                    .ok_or_else(invalid)?;
                crate::bounds::ck_length(remaining)?;
            }
            if let Boundary::Capacity {
                required,
                previous,
                prepared,
                ..
            } = boundary
            {
                let remaining = self
                    .capacity
                    .checked_sub(self.output.len())
                    .ok_or_else(invalid)?;
                crate::bounds::ck_length(remaining)?;
                crate::bounds::ck_length(required)?;
                crate::bounds::ck_length(previous)?;
                if prepared && self.native_length != remaining
                    || !prepared && (self.native_length != required || previous != remaining)
                {
                    return Err(invalid());
                }
            }
        }
        Ok(())
    }
}

impl Record<'_> {
    pub(in crate::advanced) fn validate_sections(
        self,
        descriptor: Descriptor,
        keys: &KeyBindings<'_>,
        validation: Option<&ValidationRecord<'_>>,
        limits: Limits,
    ) -> Result<()> {
        let decrypt = match descriptor.family {
            Family::MessageEncrypt => false,
            Family::MessageDecrypt => true,
            _ => return Err(invalid()),
        };
        descriptor.keys(keys, limits)?;
        let kind = CipherKind::from_mechanism(descriptor.mechanism)?;
        let boundary = self.header.boundary;
        let active = boundary.index();
        if descriptor.size != 0
            || descriptor.active_flags != 0
            || descriptor.validation_requested
            || descriptor.carried_messages != 0
            || descriptor.cipher_options.is_some()
            || descriptor.digest_bits.is_some()
            || !descriptor.input.incremental
            || descriptor.input.progress.key_inputs != 0
            || descriptor.input.progress.delivered_bytes != 0
            || descriptor.phase != Function::from_name(boundary.function(decrypt))?
            || descriptor.input.is_open() == (boundary == Boundary::Finish)
            || descriptor.input.retained_submission != matches!(boundary, Boundary::Capacity { .. })
            || active.is_some_and(|index| index.checked_add(1) != Some(self.count))
            || self.header.fragment.is_some() != boundary.call().is_some()
        {
            return Err(invalid());
        }
        match (self.header.route, boundary) {
            (MessageRoute::Single, Boundary::Begin(_) | Boundary::Receive(_)) => {
                return Err(invalid())
            }
            (MessageRoute::Single, _)
                if boundary
                    .call()
                    .is_some_and(|call| !matches!(call, Call::Single(_))) =>
            {
                return Err(invalid())
            }
            (MessageRoute::Multipart, _) if matches!(boundary.call(), Some(Call::Single(_))) => {
                return Err(invalid())
            }
            _ => {}
        }
        let completed = self
            .count
            .checked_sub(usize::from(active.is_some()))
            .ok_or_else(invalid)?;
        let mut produced = 0u128;
        let mut accepted = 0u128;
        let mut all_known = true;
        let mut minimum_completed_calls = 0u64;
        let mut target_row = None;
        let fixed = match self.header.initial {
            Initial::None => None,
            Initial::Shared { target, seed, .. } => {
                if kind.stream() || seed.is_none() && target == Target::Seed {
                    return Err(invalid());
                }
                if let Some(seed) = seed {
                    seed.selection
                        .plan(kind)?
                        .validate(0, seed.declared_length, decrypt)?;
                    seed.selection
                        .validate_tag(kind, seed.expected_tag, decrypt)?;
                }
                // The target may still be the preceding message until a new
                // Begin/Single is actually issued. Never infer that issuing it
                // happened solely because a new row has been appended.
                let prepared_current = !matches!(
                    boundary,
                    Boundary::Begin(_) | Boundary::Data(Call::Single(_))
                );
                let expected = if prepared_current {
                    self.count.checked_sub(1)
                } else {
                    self.count.checked_sub(2)
                };
                if target != expected.map_or(Target::Seed, Target::Message) {
                    return Err(invalid());
                }
                seed.map(|seed| seed.selection)
            }
        };
        let mut fixed = fixed;
        for (index, row) in self.iter().enumerate() {
            let row = row?;
            row.validate(
                kind,
                decrypt,
                active != Some(index),
                boundary,
                self.header.route,
            )?;
            match row.accepted_input {
                Some(bytes) => accepted = accepted.checked_add(bytes).ok_or_else(invalid)?,
                None => all_known = false,
            }
            produced = produced
                .checked_add(row.output.len() as u128)
                .and_then(|total| total.checked_add(row.disposition.discarded_output() as u128))
                .ok_or_else(invalid)?;
            if index < completed
                && !matches!(row.disposition, Disposition::Rejected { rejection, .. } if rejection.function.ends_with("Begin"))
            {
                minimum_completed_calls =
                    minimum_completed_calls.checked_add(1).ok_or_else(invalid)?;
            }
            if matches!(self.header.initial, Initial::Shared { .. }) {
                if let Some(first) = fixed {
                    first
                        .plan(kind)?
                        .fixed_scalars(&row.selection.plan(kind)?)?;
                } else {
                    fixed = Some(row.selection);
                }
                if matches!(self.header.initial, Initial::Shared { target: Target::Message(i), .. } if i == index)
                {
                    target_row = Some(row);
                }
            }
        }
        if let Initial::Shared {
            target,
            seed,
            nonce,
            tag,
        } = self.header.initial
        {
            let (selection, expected, observed) = match target {
                Target::Seed => {
                    let seed = seed.ok_or_else(invalid)?;
                    (seed.selection, seed.expected_tag, None)
                }
                Target::Message(_) => {
                    let row = target_row.ok_or_else(invalid)?;
                    // Shared storage is copied back on every established return.
                    if nonce != row.nonce || tag != row.tag {
                        return Err(invalid());
                    }
                    (row.selection, row.expected_tag, row.observed_nonce)
                }
            };
            selection.validate_nonce(nonce, decrypt)?;
            if tag.len() != selection.plan(kind)?.tag_bytes()?
                || expected.is_some_and(|expected| expected != tag)
                || observed.is_some_and(|observed| observed != nonce)
            {
                return Err(invalid());
            }
        }
        if descriptor.input.progress.output_bytes != produced
            || accepted > descriptor.input.progress.input_bytes
            || all_known && accepted != descriptor.input.progress.input_bytes
        {
            return Err(invalid());
        }
        // Discarded input lengths cannot be reconstructed from an archive.
        // Check only the lower bound proven by completed messages and the
        // retained submission, without pretending to validate missing history.
        let minimum_calls = minimum_completed_calls
            .checked_add(u64::from(descriptor.input.retained_submission))
            .ok_or_else(invalid)?;
        if self.count == 0 && descriptor.input.progress.submissions != 0
            || descriptor.input.progress.submissions < minimum_calls
            || self.header.route == MessageRoute::Single
                && descriptor.input.progress.submissions != minimum_calls
            || descriptor.input.progress.submissions == 0
                && (descriptor.input.progress.input_bytes != 0 || produced != 0)
        {
            return Err(invalid());
        }
        if let Some(report) = validation {
            if self.count.checked_add(1) != Some(report.maximum()) {
                return Err(invalid());
            }
            let call = match self.header.route {
                MessageRoute::Single => Call::Single(0),
                MessageRoute::Multipart => Call::Last(0),
            };
            let mut observations = report.iter();
            for (index, row) in self.iter().take(completed).enumerate() {
                if matches!(row?.disposition, Disposition::Rejected { .. }) {
                    continue;
                }
                let observation = observations.next().ok_or_else(invalid)??;
                if observation.function != call.function(decrypt)
                    || observation.message_index != Some(index)
                {
                    return Err(invalid());
                }
            }
            if observations.next().is_some() {
                return Err(invalid());
            }
        }
        Ok(())
    }
}
