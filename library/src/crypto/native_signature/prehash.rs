// SPDX-License-Identifier: Apache-2.0
//! Optional software digest and encoding, admitted with the final native frame.
use crate::{
    crypto::{software, HashAlgorithm, PreparedDigest},
    symmetric::memory::Credit,
    Error, Result, SecretBytes,
};
use std::mem::size_of;

fn accounting() -> Error {
    Error::Rejected(crate::RejectionReason::ClassicalSignatures(
        crate::ClassicalSignaturesRejection::ClassicalPrehashStorageAccounting,
    ))
}

pub(in crate::crypto) struct Plan {
    pub(in crate::crypto) software: Option<HashAlgorithm>,
    pub(in crate::crypto) encoded_length: Option<usize>,
}
pub(in crate::crypto) struct Storage {
    pub(in crate::crypto) software: Option<PreparedDigest>,
    pub(in crate::crypto) encoded: Option<SecretBytes>,
}
impl Plan {
    pub(in crate::crypto) fn prepare<T>(
        &self,
        parts: &[&[u8]],
        overhead: usize,
        mut reserve: impl FnMut(usize) -> Result<(T, Credit)>,
    ) -> Result<((T, Storage), Credit)> {
        let working = self.software.map_or(0, software::working_bytes);
        let software_bytes = self
            .software
            .map_or(0, |hash| hash.output_length() + size_of::<SecretBytes>());
        let encoded_bytes = self
            .encoded_length
            .map(|n| {
                n.checked_add(size_of::<SecretBytes>())
                    .ok_or_else(accounting)
            })
            .transpose()?
            .unwrap_or(0);
        let mut required = overhead
            .checked_add(working)
            .and_then(|n| n.checked_add(software_bytes))
            .and_then(|n| n.checked_add(encoded_bytes))
            .ok_or_else(accounting)?;
        loop {
            // Keep the nested owner ahead of residual credit on every error
            // path, including failure while allocating the encoding or digest.
            let mut candidate = reserve(required)?;
            let encoded = self.encoded_length.map(SecretBytes::new).transpose()?;
            // CPU work is done before session guards. Every hash allocation is
            // covered by this candidate's peak reservation, including overlap
            // of state, hash output and the separately owned digest result.
            let digest = self
                .software
                .map(|hash| software::hash_owned(hash, parts))
                .transpose()?;
            let mut actual = overhead.checked_add(working).ok_or_else(accounting)?;
            for bytes in [digest.as_ref(), encoded.as_ref()].into_iter().flatten() {
                actual = actual
                    .checked_add(bytes.allocated_bytes())
                    .and_then(|n| n.checked_add(size_of::<SecretBytes>()))
                    .ok_or_else(accounting)?;
            }
            if actual > required {
                drop(encoded);
                drop(digest);
                drop(candidate);
                required = actual;
                continue;
            }
            // The hash state/output temporaries have been wiped and freed by
            // `hash`; retain only the result and encoding allocation credits.
            candidate.1.release(required - actual + working);
            let software = digest
                .map(|d| -> Result<PreparedDigest> {
                    Ok(PreparedDigest::from_owned(
                        self.software.expect("prepared software digest"),
                        d.bind_prepaid(&mut candidate.1)?,
                    ))
                })
                .transpose()?;
            let encoded = encoded
                .map(|b| b.bind_prepaid(&mut candidate.1))
                .transpose()?;
            return Ok(((candidate.0, Storage { software, encoded }), candidate.1));
        }
    }
}
