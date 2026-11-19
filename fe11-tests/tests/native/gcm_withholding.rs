// SPDX-License-Identifier: Apache-2.0
//! A synchronous session withholds GCM plaintext until authenticated completion.
use super::{
    arguments::hex, object_owner::Owner, outcome::Failure, report::Report,
    single_key_case::SingleKeyCase,
};
use fe11::*;
use std::{
    fs::File,
    io::{Read, Write},
    path::Path,
};

pub struct Vector {
    ciphertext: Vec<u8>,
    plaintext: Vec<u8>,
}
impl SingleKeyCase for Vector {
    const ASSERTION: &'static str = "gcm_plaintext_withheld_until_authentication";
    const PRODUCER: super::report::Producer = super::report::Producer::TestOracle;
    fn read(path: &Path) -> std::result::Result<Self, Failure> {
        let mut data = Vec::new();
        File::open(path)
            .map_err(|_| Failure::Input("fixture_open"))?
            .take(129)
            .read_to_end(&mut data)
            .map_err(|_| Failure::Input("fixture_read"))?;
        if data.len() > 128 {
            return Err(Failure::Input("fixture_size"));
        }
        let text = std::str::from_utf8(&data).map_err(|_| Failure::Input("fixture_encoding"))?;
        let f: Vec<_> = text.split_terminator('\n').collect();
        if f.len() != 2 {
            return Err(Failure::Input("gcm_withholding_fields"));
        }
        let v = Self {
            ciphertext: hex(f[0], 32).map_err(Failure::Input)?,
            plaintext: hex(f[1], 16).map_err(Failure::Input)?,
        };
        if !matches!(v.plaintext.len(), 0 | 16)
            || v.ciphertext.len() != v.plaintext.len() + 16
            || v.plaintext.iter().any(|byte| *byte != 0)
        {
            return Err(Failure::Input("gcm_withholding_dimensions"));
        }
        Ok(v)
    }
    fn advanced(&self) -> bool {
        false
    }
    fn import(&self, owner: &Owner) -> std::result::Result<NativeObjectRef, Failure> {
        Ok(owner.import_secret_usages(
            &[0u8; 16],
            fe11_sys::CKK_AES,
            [
                (StandardAttribute::ENCRYPT, false),
                (StandardAttribute::DECRYPT, true),
            ],
        )?)
    }
    fn check<W: Write>(
        &self,
        owner: &Owner,
        key: &NativeObjectRef,
        _report: &mut Report<W>,
    ) -> std::result::Result<(), Failure> {
        let Owner::Session(session) = owner else {
            return Err(Failure::Input("gcm_synchronous_owner"));
        };
        let mut ticket = session.begin_decrypt_classic_aead_stream(
            key,
            ClassicAeadParameters::Gcm {
                iv: &[0u8; 12],
                aad: &[],
                tag_bits: 128,
            },
            None,
            CipherOutputPlan::Buffer {
                capacity: if self.plaintext.is_empty() {
                    self.ciphertext.len()
                } else {
                    self.plaintext.len()
                },
            },
        )?;
        match session.take_cipher_stream_output(&mut ticket) {
            Err(Error::Busy(BusyReason::CipherContinuation(
                CipherContinuationBusy::AeadPlaintextAwaitsSuccessfulFinal,
            ))) => (),
            Err(error) => return Err(error.into()),
            Ok(_) => return Err(Failure::Oracle("unauthenticated_plaintext_exposed")),
        }
        let (status, progress) = ticket.cipher_progress()?;
        if status != StreamInputStatus::Open
            || progress.submissions != 0
            || progress.input_bytes != 0
            || progress.output_bytes != 0
            || progress.delivered_bytes != 0
        {
            return Err(Failure::Oracle("gcm_refused_take_preserves_owner"));
        }
        let progress = session.cipher_update(
            &mut ticket,
            &self.ciphertext,
            InputLimits {
                maximum_parts: 1,
                maximum_total_bytes: self.ciphertext.len(),
            },
        )?;
        match progress {
            OperationProgress::Ready if self.plaintext.is_empty() => (),
            OperationProgress::CipherBufferRequired(request)
                if !self.plaintext.is_empty()
                    && request.function == "C_DecryptUpdate"
                    && request.code == fe11_sys::CKR_BUFFER_TOO_SMALL as u64
                    && request.previous_capacity == 16
                    && request.required == 32 =>
            {
                ()
            }
            _ => return Err(Failure::Oracle("gcm_exact_update_capacity_request")),
        }
        // The initial capacity belongs to the withholding boundary. Resizing
        // resumes the retained input; submitting the ciphertext again would
        // duplicate it and would test a different operation.
        if !self.plaintext.is_empty() {
            session.resize_cipher_output(&ticket, 32)?;
            if !matches!(session.poll_cipher(&mut ticket)?, OperationProgress::Ready) {
                return Err(Failure::Oracle("gcm_resumed_update_input_boundary"));
            }
        } else {
            // Even a tag-only input has not authenticated before Final. An
            // empty successful plaintext owner must not be published early.
            match session.take_cipher_stream_output(&mut ticket) {
                Err(Error::Busy(BusyReason::CipherContinuation(
                    CipherContinuationBusy::AeadPlaintextAwaitsSuccessfulFinal,
                ))) => (),
                Err(error) => return Err(error.into()),
                Ok(_) => return Err(Failure::Oracle("empty_plaintext_published_before_final")),
            }
        }
        let (_, progress) = ticket.cipher_progress()?;
        if progress.submissions != 1
            || progress.input_bytes != self.ciphertext.len() as u128
            || progress.output_bytes != 0
            || progress.delivered_bytes != 0
        {
            return Err(Failure::Oracle("gcm_retained_input_not_duplicated"));
        }
        match session.finish_cipher_stream(&mut ticket)? {
            OperationProgress::ClassicAeadDecrypted(value)
                if value.as_bytes() == self.plaintext =>
            {
                Ok(())
            }
            _ => Err(Failure::Oracle("gcm_authenticated_plaintext")),
        }
    }
}
