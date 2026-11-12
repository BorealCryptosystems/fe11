// SPDX-License-Identifier: Apache-2.0
//! Cross-section consistency for a generic continuation, before reconstruction.
//! Counters describe discarded history; they do not authenticate native state.
use super::{invalid, Boundary, DataKind, Output, Parameter, Record};
use crate::advanced::record::{Descriptor, Function, KeyBindings, ValidationRecord};
use crate::mechanism_extension::graph::{recipe::Recipe, snapshot::SnapshotRecipe};
use crate::{MessageRoute, Result};
use fe11_sys::{CKR_BUFFER_TOO_SMALL, CKR_OK, CKR_SIGNATURE_INVALID, CKR_SIGNATURE_LEN_RANGE};

impl Parameter<'_> {
    fn validate_declaration(self, mechanism: u64, writer: bool) -> Result<()> {
        if let Some(declaration) = self.declaration {
            if declaration.mechanism != mechanism || declaration.mutates_key && !writer {
                return Err(invalid());
            }
        } else {
            // None represents the actual null-parameter contract, not an
            // undeclared nonempty ABI whose addresses might later reach C.
            let graph = SnapshotRecipe::decode(self.graph.encoded()?)?;
            if graph.root().is_some()
                || graph.block_count() != 0
                || graph.pointer_count() != 0
                || graph.output_count() != 0
            {
                return Err(invalid());
            }
        }
        Ok(())
    }
}

impl Record<'_> {
    /// The enclosing family dispatcher selects the generic record first. This
    /// checks its payload/descriptor relationship, not destination references.
    pub(in crate::advanced) fn validate_sections(
        self,
        descriptor: Descriptor,
        keys: &KeyBindings<'_>,
        validation: Option<&ValidationRecord<'_>>,
    ) -> Result<()> {
        if !matches!(descriptor.profile, 1 | 2)
            || descriptor.size != 0
            || descriptor.active_flags != 0
            || descriptor.validation_requested
            || descriptor.carried_messages != 0
            || descriptor.cipher_options.is_some()
            || descriptor.digest_bits.is_some()
            || keys.cipher.is_some()
            || keys.authentication.is_none()
            || !descriptor.input.incremental
            || descriptor.input.progress.key_inputs != 0
            || descriptor.input.progress.delivered_bytes != 0
        {
            return Err(invalid());
        }
        let verify = descriptor.profile == 2;
        let boundary = self.header.boundary;
        if descriptor.phase != Function::from_name(boundary.function(verify))?
            || descriptor.input.is_open() == matches!(boundary, Boundary::Final)
            || self.header.invalid_seen && !verify
        {
            return Err(invalid());
        }
        let initial = self.header.initialization;
        if initial.declaration.is_none() {
            return Err(invalid());
        }
        initial.validate_declaration(descriptor.mechanism, self.header.writer)?;
        let call = boundary.call();
        let current = match boundary {
            Boundary::Ready | Boundary::Final => None,
            Boundary::Begin(index) | Boundary::Receive(index) => Some(index),
            Boundary::Data(call) | Boundary::Capacity { call, .. } => Some(call.message),
        };
        if current.is_some_and(|index| index.checked_add(1) != Some(self.count))
            || current.is_none() && descriptor.input.retained_submission
            || call.is_none() && descriptor.input.retained_submission
        {
            return Err(invalid());
        }
        match (self.header.route, boundary) {
            (MessageRoute::Single, Boundary::Begin(_) | Boundary::Receive(_)) => {
                return Err(invalid())
            }
            (MessageRoute::Single, _) if call.is_some_and(|call| call.kind != DataKind::Single) => {
                return Err(invalid())
            }
            (MessageRoute::Multipart, _)
                if call.is_some_and(|call| call.kind == DataKind::Single) =>
            {
                return Err(invalid())
            }
            _ => {}
        }
        if let Some(call) = call {
            if call.signature.is_some() != (verify && call.kind.terminal()) {
                return Err(invalid());
            }
        }
        if let Boundary::Capacity { call, code, .. } = boundary {
            if verify
                || !call.kind.terminal()
                || code != CKR_BUFFER_TOO_SMALL as u64
                || !descriptor.input.retained_submission
            {
                return Err(invalid());
            }
        }
        let mut parts = 0u64;
        let mut rejected = 0u64;
        let mut refused_data_calls = 0u64;
        let mut produced = 0u128;
        for (index, row) in self.iter().enumerate() {
            let row = row?;
            let active = current == Some(index);
            let count = row.parts.len();
            // Multipart Begin may use NULL/0 without an owned graph.
            // Single has no Begin call and therefore cannot carry one.
            if row.begin.is_some() && self.header.route == MessageRoute::Single
                || self.header.route == MessageRoute::Single && count != 1
                || !active && count == 0 && row.rejection.is_none()
            {
                return Err(invalid());
            }
            for parameter in row.begin.into_iter().map(Ok).chain(row.parts.iter()) {
                parameter?.validate_declaration(descriptor.mechanism, self.header.writer)?;
            }
            parts = parts
                .checked_add(u64::try_from(count).map_err(|_| invalid())?)
                .ok_or_else(invalid)?;
            if active {
                match boundary {
                    Boundary::Begin(_) if count != 0 => return Err(invalid()),
                    Boundary::Data(call) | Boundary::Capacity { call, .. }
                        if call.part.checked_add(1) != Some(count) =>
                    {
                        return Err(invalid())
                    }
                    _ => {}
                }
            }
            if let Some(rejection) = row.rejection {
                let (begin, single, next) = if verify {
                    (
                        "C_VerifyMessageBegin",
                        "C_VerifyMessage",
                        "C_VerifyMessageNext",
                    )
                } else {
                    ("C_SignMessageBegin", "C_SignMessage", "C_SignMessageNext")
                };
                let begin_refusal = self.header.route == MessageRoute::Multipart
                    && rejection.function == begin
                    && count == 0;
                let data_refusal = count != 0
                    && rejection.function
                        == match self.header.route {
                            MessageRoute::Single => single,
                            MessageRoute::Multipart => next,
                        };
                let code = fe11_sys::CK_RV::try_from(rejection.code).map_err(|_| invalid())?;
                if active
                    || !(begin_refusal || data_refusal)
                    || code == CKR_OK
                    || (verify
                        && self.header.route == MessageRoute::Single
                        && matches!(code, CKR_SIGNATURE_INVALID | CKR_SIGNATURE_LEN_RANGE))
                    || !crate::native_return::call_memory_returned(code)
                    || crate::native_return::native_context_scope(code)
                        != crate::native_return::FailureScope::None
                {
                    return Err(invalid());
                }
                match (verify, row.output) {
                    (true, Output::Verify(None)) => {}
                    (false, Output::Sign(None)) if self.header.route == MessageRoute::Multipart => {
                    }
                    (false, Output::Sign(Some(output)))
                        if data_refusal
                            && output.bytes.is_some()
                            && output.produced.is_none()
                            && code != CKR_BUFFER_TOO_SMALL => {}
                    _ => return Err(invalid()),
                }
                refused_data_calls = refused_data_calls
                    .checked_add(u64::from(data_refusal))
                    .ok_or_else(invalid)?;
                // Retained buffers and graphs preserve native addresses; none
                // of their bytes establishes an output or signature verdict.
                continue;
            }
            match (verify, row.output) {
                (true, Output::Verify(verdict)) => {
                    if active != verdict.is_none() {
                        return Err(invalid());
                    }
                    if let Some(code) = verdict {
                        if !matches!(code, n if n == CKR_OK as u64
                            || n == CKR_SIGNATURE_INVALID as u64 || n == CKR_SIGNATURE_LEN_RANGE as u64)
                        {
                            return Err(invalid());
                        }
                        if code != CKR_OK as u64 {
                            rejected = rejected.checked_add(1).ok_or_else(invalid)?;
                        }
                    }
                }
                (false, Output::Sign(output)) => {
                    let terminal_pending = active && call.is_some_and(|call| call.kind.terminal());
                    if output.is_some() != (!active || terminal_pending) {
                        return Err(invalid());
                    }
                    if let Some(output) = output {
                        if active != output.produced.is_none() {
                            return Err(invalid());
                        }
                        let missing = active
                            && matches!(
                                boundary,
                                Boundary::Capacity {
                                    prepared: false,
                                    ..
                                }
                            );
                        if missing != output.bytes.is_none() {
                            return Err(invalid());
                        }
                        if let Boundary::Capacity {
                            previous_capacity,
                            prepared: false,
                            ..
                        } = boundary
                        {
                            if active && output.capacity != previous_capacity {
                                return Err(invalid());
                            }
                        }
                        if let Some(length) = output.produced {
                            produced = produced.checked_add(length as u128).ok_or_else(invalid)?;
                        }
                        // Keep the current native length independently of the
                        // last established produced extent. Later native calls
                        // may still touch that retained cell before Final.
                    }
                }
                _ => return Err(invalid()),
            }
        }
        if self.header.invalid_seen != (rejected != 0)
            || descriptor.input.progress.output_bytes != produced
        {
            return Err(invalid());
        }
        let unissued = u64::from(call.is_some() && !descriptor.input.retained_submission);
        if parts.checked_sub(unissued) != Some(descriptor.input.progress.submissions) {
            return Err(invalid());
        }
        let accepted_calls = parts
            .checked_sub(u64::from(call.is_some()))
            .and_then(|n| n.checked_sub(rejected))
            .and_then(|n| n.checked_sub(refused_data_calls))
            .ok_or_else(invalid)?;
        if accepted_calls == 0 && descriptor.input.progress.input_bytes != 0 {
            return Err(invalid());
        }
        if let Some(report) = validation {
            if self.count.checked_add(1) != Some(report.maximum()) {
                return Err(invalid());
            }
            // Native observations follow every completed message, including a
            // retained invalid-signature verdict, but not operational errors.
            // They report module flags, not a signature
            // verdict. An active row and parent Final have no observation yet:
            // capture cannot cross a queued or pending observation.
            let completed = self
                .count
                .checked_sub(usize::from(current.is_some()))
                .ok_or_else(invalid)?;
            let function = match (verify, self.header.route) {
                (false, MessageRoute::Single) => "C_SignMessage",
                (true, MessageRoute::Single) => "C_VerifyMessage",
                (false, MessageRoute::Multipart) => "C_SignMessageNext",
                (true, MessageRoute::Multipart) => "C_VerifyMessageNext",
            };
            let mut observations = report.iter();
            for (index, row) in self.iter().take(completed).enumerate() {
                if row?.rejection.is_some() {
                    continue;
                }
                let observation = observations.next().ok_or_else(invalid)??;
                if observation.function != function || observation.message_index != Some(index) {
                    return Err(invalid());
                }
            }
            if observations.next().is_some() {
                return Err(invalid());
            }
        }
        // With consumed input intentionally absent, its byte total cannot be
        // recomputed. Do not invent lengths, quotas or proof of native success.
        Ok(())
    }
}
