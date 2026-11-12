// SPDX-License-Identifier: Apache-2.0
//! Check AEAD key bindings, parameter witnesses and returned frame boundaries.
//! A valid representation is separate from native authentication success.

use super::*;

pub(in crate::advanced) fn check_message_key(
    s: &State,
    key: MessageKey<'_>,
    kind: CipherKind,
    decrypt: bool,
    route: MessageRoute,
) -> Result<()> {
    match key {
        MessageKey::Aes(key)
            if !kind.stream()
                && matches!(
                    key.algorithm,
                    SymmetricAlgorithm::Aes128
                        | SymmetricAlgorithm::Aes192
                        | SymmetricAlgorithm::Aes256
                ) => {}
        MessageKey::Native(_) => {}
        _ => {
            return Err(Error::Rejected(crate::RejectionReason::AeadMessages(
                crate::AeadMessagesRejection::AeadMessageKeyReferenceSelection,
            )))
        }
    }
    let f = s
        .native
        .messages
        .ok_or(Error::Rejected(crate::RejectionReason::AeadMessages(
            crate::AeadMessagesRejection::MessageInterfaceUnavailable,
        )))?;
    let available = if decrypt {
        f.decrypt_init.is_some()
            && f.decrypt_finish.is_some()
            && match route {
                MessageRoute::Single => f.decrypt_message.is_some(),
                MessageRoute::Multipart => f.decrypt_begin.is_some() && f.decrypt_next.is_some(),
            }
    } else {
        f.encrypt_init.is_some()
            && f.encrypt_finish.is_some()
            && match route {
                MessageRoute::Single => f.encrypt_message.is_some(),
                MessageRoute::Multipart => f.encrypt_begin.is_some() && f.encrypt_next.is_some(),
            }
    };
    if !available {
        return Err(Error::Rejected(crate::RejectionReason::AeadMessages(
            crate::AeadMessagesRejection::AeadMessageMessageFunctionsUnavailable,
        )));
    }
    Ok(())
}

pub(super) fn message_key(
    session: &Session,
    s: &State,
    key: MessageKey<'_>,
    kind: CipherKind,
    decrypt: bool,
    route: MessageRoute,
    permits: &mut [Option<crate::registry::ReadPermit>],
) -> Result<KeyLease> {
    check_message_key(s, key, kind, decrypt, route)?;
    match key {
        MessageKey::Aes(key) => KeyLease::new(session, key, permits),
        MessageKey::Native(key) => {
            KeyLease::for_native_cipher(session, key, kind.mechanism(), permits)
        }
    }
}

impl AeadMessageOperation {
    // Only the transfer control calls this after C_AsyncGetID OK: the module
    // has released its access to the original native allocations, not completed.
    pub(in crate::advanced) fn detached_native_release(&mut self) {
        self.activity = NativeActivity::Active;
    }

    pub(super) fn validate_parameters(&mut self, i: usize) -> Result<()> {
        self.validate_returned_parameters(i, true)
    }

    /// Check only after the common protocol has established memory return.
    /// A refused call does not establish a new generated nonce or output extent;
    /// an already observed nonce and immutable input fields remain witnesses.
    pub(super) fn inspect_returned_boundary(&mut self, rv: CK_RV) -> Result<()> {
        self.validate_binding()?;
        if self.step == AeadStep::Init {
            if let InitBinding::Shared { nonce, tag, .. } = &self.init {
                let (origin, _, expected_tag) = self.init.reference(&self.frames)?;
                let input_nonce = if self.decrypt {
                    nonce.as_slice() == origin.iv()
                } else {
                    origin.fixed_bits_unchanged(nonce.as_slice())
                        && (origin.generated() || nonce.as_slice() == origin.iv())
                };
                if !input_nonce
                    || expected_tag.is_some_and(|expected| tag.as_slice() != expected.as_slice())
                {
                    return Err(Error::Rejected(crate::RejectionReason::AeadMessages(
                        crate::AeadMessagesRejection::AeadMessageInitInputBytesMutation,
                    )));
                }
            }
        }
        let parameters = if let AeadStep::Begin(index) = self.step {
            Some(index)
        } else {
            self.output_index()
        };
        if let Some(index) = parameters {
            self.validate_returned_parameters(index, rv == CKR_OK)?;
        }
        if rv == CKR_OK {
            // Declared Init outputs belong to the parent, not an individual
            // message. Only successful Final defines their mutable lengths.
            if self.step == AeadStep::Finish {
                if let InitBinding::Declared(initialization) = &self.init {
                    initialization.validate_output_bounds()?;
                }
            }
            if let Some(index) = self.output_index() {
                let frame = &self.frames[index];
                let output = &self.outputs.as_ref().expect("retained AEAD output").entries[index];
                bounds::final_length(*frame.length, output.bytes.capacity() - frame.used)?;
            }
        }
        Ok(())
    }

    pub(super) fn validate_frame(
        frame: &mut Frame,
        nonce: &Buffer,
        tag: &Buffer,
        completed: bool,
        decrypt: bool,
    ) -> Result<()> {
        if !frame.params.unchanged(
            &frame.origin,
            frame.expected,
            nonce.as_slice().as_ptr().cast_mut(),
            tag.as_slice().as_ptr().cast_mut(),
        )? {
            return Err(Error::Rejected(crate::RejectionReason::AeadMessages(
                crate::AeadMessagesRejection::AeadNativeParameterIdentity,
            )));
        }
        if frame
            .expected_tag
            .as_ref()
            .is_some_and(|expected| tag.as_slice() != expected.as_slice())
        {
            return Err(Error::Rejected(crate::RejectionReason::AeadMessages(
                crate::AeadMessagesRejection::AeadMessageNativeTagMutation,
            )));
        }
        if decrypt {
            // The decrypt IV is an input even when the ignored generator is
            // nonzero. Do not derive a slice bound from ignored fixed bits.
            if nonce.as_slice() != frame.origin.iv() {
                return Err(Error::Rejected(crate::RejectionReason::AeadMessages(
                    crate::AeadMessagesRejection::AeadMessageDecryptNonceMutation,
                )));
            }
        } else {
            if !frame.origin.fixed_bits_unchanged(nonce.as_slice()) {
                return Err(Error::Rejected(crate::RejectionReason::AeadMessages(
                    crate::AeadMessagesRejection::AeadMessageGeneratedFixedBitsMutation,
                )));
            }
            if frame.origin.generated() {
                // A capacity refusal does not establish a newly generated IV.
                // An IV established by an earlier part must still be unchanged.
                if completed || matches!(frame.observed_nonce, GeneratedNonce::Observed(_)) {
                    observe_generated_nonce(&mut frame.observed_nonce, nonce.as_slice())?;
                }
            } else if nonce.as_slice() != frame.origin.iv() {
                return Err(Error::Rejected(crate::RejectionReason::AeadMessages(
                    crate::AeadMessagesRejection::AeadMessageProvidedNonceMutation,
                )));
            }
        }
        Ok(())
    }

    pub(in crate::advanced) fn validation_point(
        &self,
    ) -> Result<Option<crate::advanced::validation::Point>> {
        let index = if self.last() {
            self.output_index()
        } else {
            None
        };
        if self.nominal() && (index.is_some() || self.step == AeadStep::Finish) {
            Ok(Some(crate::advanced::validation::Point {
                function: self.function()?,
                message_index: index,
            }))
        } else {
            Ok(None)
        }
    }
}
