// SPDX-License-Identifier: Apache-2.0
//! Joint admission for classical signing/verification frames and their buffers.
use super::{SignatureMechanism, SignatureParameters};
use crate::{
    bounds, native::frame::SessionFrame, symmetric::memory::Credit, Error, Result, SecretBytes,
};
use fe11_sys::{CK_MECHANISM_TYPE, CK_ULONG};
use std::mem::size_of;

fn accounting() -> Error {
    Error::Rejected(crate::RejectionReason::ClassicalSignatures(
        crate::ClassicalSignaturesRejection::ClassicalSignatureStorageAccounting,
    ))
}

/// Complete data owner shared by the synchronous signature sequences. The
/// frame credit is last so neither buffers nor descriptors outlive its charge.
pub(in crate::crypto) struct Call {
    pub(in crate::crypto) mechanism: SignatureMechanism,
    pub(in crate::crypto) input: SecretBytes,
    pub(in crate::crypto) signature: SecretBytes,
    pub(in crate::crypto) length: CK_ULONG,
    _credit: Credit,
}
impl Call {
    pub(in crate::crypto) fn input_unchanged(&self, expected: &[u8]) -> bool {
        self.input.as_slice().get(..expected.len()) == Some(expected)
            && self.input.as_slice()[expected.len()..]
                .iter()
                .all(|byte| *byte == 0)
    }
}

/// Sizes are derived from the requested route, never from a policy ceiling.
pub(in crate::crypto) struct Plan {
    input: usize,
    signature: usize,
}
pub(in crate::crypto) struct Storage {
    input: SecretBytes,
    signature: SecretBytes,
    diagnostic: crate::error::PreparedCompletionCell,
    credit: Credit,
}
impl Plan {
    pub(in crate::crypto) fn new(input: usize, signature: usize) -> Result<Self> {
        bounds::ck_length(input)?;
        bounds::ck_length(signature)?;
        Ok(Self { input, signature })
    }

    /// The outer reservation may also prepare a digest and context login.
    /// On capacity growth, discard all of them before waiting again. Splitting
    /// this into independent reservations could wait for one's own credits.
    pub(in crate::crypto) fn prepare<T>(
        &self,
        overhead: usize,
        mut reserve: impl FnMut(usize) -> Result<(T, Credit)>,
    ) -> Result<((T, Storage), Credit)> {
        let fixed = size_of::<Call>()
            .checked_add(SessionFrame::<'_, Call>::allocation_bytes())
            .ok_or_else(accounting)?;
        let mut required = fixed
            .checked_add(self.input)
            .and_then(|n| n.checked_add(self.signature))
            .and_then(|n| n.checked_add(overhead))
            .and_then(|n| n.checked_add(crate::error::CompletionStorage::allocation_bytes()))
            .ok_or_else(accounting)?;
        loop {
            // Tuple field order also protects early `?` exits: the nested
            // owner is destroyed before its residual reservation is released.
            let mut candidate = reserve(required)?;
            let input = SecretBytes::new(self.input)?;
            let signature = SecretBytes::new(self.signature)?;
            let actual = fixed
                .checked_add(input.allocated_bytes())
                .and_then(|n| n.checked_add(signature.allocated_bytes()))
                .and_then(|n| n.checked_add(overhead))
                .and_then(|n| n.checked_add(crate::error::CompletionStorage::allocation_bytes()))
                .ok_or_else(accounting)?;
            if actual > required {
                drop(input);
                drop(signature);
                drop(candidate);
                required = actual;
                continue;
            }
            candidate.1.release(required - actual);
            let input = input.bind_prepaid_payload(&mut candidate.1)?;
            // The existing output header charge moves with the signature when
            // it is published. Native errors retain the same owner in the frame.
            let signature = signature.bind_prepaid(&mut candidate.1)?;
            let diagnostic = crate::error::PreparedCompletionCell::prepare(&mut candidate.1)?;
            let credit = candidate.1.split(
                fixed
                    .checked_sub(size_of::<SecretBytes>())
                    .ok_or_else(accounting)?,
            )?;
            return Ok((
                (
                    candidate.0,
                    Storage {
                        input,
                        signature,
                        diagnostic,
                        credit,
                    },
                ),
                candidate.1,
            ));
        }
    }
}
impl Storage {
    /// No allocation/admission here: called after acquisition of session guards.
    pub(in crate::crypto) fn bind(
        self,
        kind: CK_MECHANISM_TYPE,
        parameters: SignatureParameters<'_>,
        input: usize,
        signature: usize,
    ) -> Result<(Call, crate::error::PreparedCompletionCell)> {
        if input > self.input.len() || signature != self.signature.len() {
            return Err(Error::Rejected(
                crate::RejectionReason::ClassicalSignatures(
                    crate::ClassicalSignaturesRejection::ClassicalSignaturePreparationDiffers,
                ),
            ));
        }
        Ok((
            Call {
                mechanism: SignatureMechanism::new(kind, parameters)?,
                input: self.input,
                signature: self.signature,
                length: bounds::ck_length(signature)?,
                _credit: self.credit,
            },
            self.diagnostic,
        ))
    }
}
