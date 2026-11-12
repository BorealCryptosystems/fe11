// SPDX-License-Identifier: Apache-2.0
//! Joint OAEP storage admission, including witnesses and published plaintext.
use super::{OaepCall, OaepParams, SecretPlaintext, SecretScratch};
use crate::{
    native::frame::SessionFrame, session::AdmissionProgress, symmetric::memory::Credit, Error,
    Result, Session,
};
use std::mem::size_of;

fn accounting() -> Error {
    Error::Rejected(crate::RejectionReason::KeyTransport(
        crate::KeyTransportRejection::OaepStorageAccounting,
    ))
}
fn sum(values: &[usize]) -> Result<usize> {
    values
        .iter()
        .try_fold(0usize, |sum, n| sum.checked_add(*n).ok_or_else(accounting))
}
fn bytes(length: usize) -> Result<Vec<u8>> {
    crate::bounds::ck_length(length)?;
    let mut value = Vec::new();
    value.try_reserve_exact(length).map_err(|_| {
        Error::Rejected(crate::RejectionReason::KeyTransport(
            crate::KeyTransportRejection::RsaCiphertextAllocation,
        ))
    })?;
    value.resize(length, 0);
    Ok(value)
}
fn bind_plaintext(mut value: SecretPlaintext, prepaid: &mut Credit) -> Result<SecretPlaintext> {
    value.credit = Some(prepaid.split(sum(&[
        size_of::<SecretPlaintext>(),
        value.bytes.capacity(),
    ])?)?);
    Ok(value)
}

pub(super) struct Encryption {
    pub label: Vec<u8>,
    pub output: Vec<u8>,
    pub witness: SecretPlaintext,
    pub diagnostic: crate::error::PreparedCompletionCell,
    pub credit: Credit,
}
impl Encryption {
    pub(super) fn prepare(
        session: &Session,
        params: OaepParams<'_>,
        input: &SecretPlaintext,
        capacity: usize,
        overhead: usize,
        progress: &AdmissionProgress,
        epoch: u64,
    ) -> Result<(Self, Credit)> {
        type Call = OaepCall<SecretPlaintext, Vec<u8>>;
        let previous = input.credit.as_ref().filter(|credit| {
            credit
                .budget()
                .same_account(&session.inner.symmetric_budget)
        });
        let fixed = sum(&[
            size_of::<Call>(),
            SessionFrame::<'_, Call>::allocation_bytes(),
        ])?
        .checked_sub(if previous.is_some() {
            size_of::<SecretPlaintext>()
        } else {
            0
        })
        .ok_or_else(accounting)?;
        let transferred = if previous.is_some() {
            0
        } else {
            input.bytes.capacity()
        };
        let mut required = sum(&[
            fixed,
            transferred,
            params.label.len(),
            capacity,
            size_of::<SecretPlaintext>(),
            input.len(),
            overhead,
            crate::error::CompletionStorage::allocation_bytes(),
        ])?;
        loop {
            if let Some(previous) = previous {
                previous.check_additional_capacity(required)?;
            }
            let mut prepaid =
                crate::advanced::reserve_preparation_at_epoch(session, required, progress, epoch)?;
            let label = params.checked_label()?;
            let output = bytes(capacity)?;
            let mut witness = SecretPlaintext::new(input.len())?;
            witness.as_mut_slice().copy_from_slice(input.as_slice());
            let native = sum(&[fixed, transferred, label.capacity(), output.capacity()])?;
            let actual = sum(&[
                native,
                size_of::<SecretPlaintext>(),
                witness.bytes.capacity(),
                overhead,
                crate::error::CompletionStorage::allocation_bytes(),
            ])?;
            if actual > required {
                drop(witness);
                drop(output);
                drop(label);
                drop(prepaid);
                required = actual;
                continue;
            }
            prepaid.release(required - actual);
            let witness = bind_plaintext(witness, &mut prepaid)?;
            let diagnostic = crate::error::PreparedCompletionCell::prepare(&mut prepaid)?;
            let credit = prepaid.split(native)?;
            return Ok((
                Self {
                    label,
                    output,
                    witness,
                    diagnostic,
                    credit,
                },
                prepaid,
            ));
        }
    }
}

pub(super) struct Decryption {
    pub label: Vec<u8>,
    pub input: Vec<u8>,
    pub scratch: SecretScratch,
    pub plaintext: SecretPlaintext,
    pub diagnostic: crate::error::PreparedCompletionCell,
    pub credit: Credit,
}
impl Decryption {
    pub(super) fn prepare(
        session: &Session,
        params: OaepParams<'_>,
        input: &[u8],
        capacity: usize,
        overhead: usize,
        progress: &AdmissionProgress,
        epoch: u64,
    ) -> Result<(Self, Credit)> {
        type Call = OaepCall<Vec<u8>, SecretScratch>;
        let fixed = sum(&[
            size_of::<Call>(),
            SessionFrame::<'_, Call>::allocation_bytes(),
        ])?;
        let mut required = sum(&[
            fixed,
            params.label.len(),
            input.len(),
            capacity,
            size_of::<SecretPlaintext>(),
            capacity,
            overhead,
            crate::error::CompletionStorage::allocation_bytes(),
        ])?;
        loop {
            let mut prepaid =
                crate::advanced::reserve_preparation_at_epoch(session, required, progress, epoch)?;
            let label = params.checked_label()?;
            let mut owned_input = bytes(input.len())?;
            owned_input.copy_from_slice(input);
            let scratch = SecretScratch(SecretPlaintext::new(capacity)?);
            let plaintext = SecretPlaintext::new(capacity)?;
            let native = sum(&[
                fixed,
                label.capacity(),
                owned_input.capacity(),
                scratch.0.bytes.capacity(),
            ])?;
            let actual = sum(&[
                native,
                size_of::<SecretPlaintext>(),
                plaintext.bytes.capacity(),
                overhead,
                crate::error::CompletionStorage::allocation_bytes(),
            ])?;
            if actual > required {
                drop(plaintext);
                drop(scratch);
                drop(owned_input);
                drop(label);
                drop(prepaid);
                required = actual;
                continue;
            }
            prepaid.release(required - actual);
            let plaintext = bind_plaintext(plaintext, &mut prepaid)?;
            let diagnostic = crate::error::PreparedCompletionCell::prepare(&mut prepaid)?;
            let credit = prepaid.split(native)?;
            return Ok((
                Self {
                    label,
                    input: owned_input,
                    scratch,
                    plaintext,
                    diagnostic,
                    credit,
                },
                prepaid,
            ));
        }
    }
}
