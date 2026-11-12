// SPDX-License-Identifier: Apache-2.0
//! Prepaid storage for a synchronous digest, including its retained result.
use super::{NativeDigestCall, NativeHash};
use crate::{
    bounds, native::frame::SessionFrame, session::AdmissionProgress, symmetric::memory::Credit,
    Error, Result, SecretBytes, Session,
};
use fe11_sys::{CK_MECHANISM, CK_MECHANISM_TYPE};
use std::mem::size_of;

fn accounting() -> Error {
    Error::Rejected(crate::RejectionReason::ClassicalSignatures(
        crate::ClassicalSignaturesRejection::NativeDigestStorageAccounting,
    ))
}

/// Immutable sizes only: no session access, storage or native dispatch.
pub(super) struct Plan {
    mechanism: CK_MECHANISM_TYPE,
    input_capacity: usize,
    output_capacity: usize,
}

/// Capacity staging is discarded in full before an admission retry. Its fields
/// are never exposed to native code until binding and stable frame installation.
struct Storage {
    input: SecretBytes,
    output: SecretBytes,
}

/// The diagnostic never enters the retained native call frame.
pub(super) struct Prepared {
    pub(super) call: NativeDigestCall,
    pub(super) diagnostic: crate::error::PreparedCompletionCell,
}

impl Plan {
    pub(super) fn new(algorithm: &NativeHash, parts: &[&[u8]], multipart: bool) -> Result<Self> {
        if !multipart && parts.len() != 1 {
            return Err(Error::Rejected(
                crate::RejectionReason::ClassicalSignatures(
                    crate::ClassicalSignaturesRejection::SinglePartDigestRequiresOneInput,
                ),
            ));
        }
        let mut input_capacity = 0;
        for part in parts {
            bounds::ck_length(part.len())?;
            input_capacity = input_capacity.max(part.len());
        }
        let output_capacity = algorithm.output_length();
        bounds::ck_length(output_capacity)?;
        Ok(Self {
            mechanism: algorithm.mechanism(),
            input_capacity,
            output_capacity,
        })
    }

    fn fixed_bytes() -> Result<usize> {
        // NativeFrame owns one allocation for CallData and another for its
        // SessionFrame. Their inline SecretBytes headers are already included.
        size_of::<NativeDigestCall>()
            .checked_add(SessionFrame::<'_, NativeDigestCall>::allocation_bytes())
            .ok_or_else(accounting)
    }

    pub(super) fn prepare(
        &self,
        session: &Session,
        overhead: usize,
        progress: &AdmissionProgress,
        epoch: u64,
    ) -> Result<(Prepared, Credit)> {
        let fixed = Self::fixed_bytes()?;
        let mut required = fixed
            .checked_add(self.input_capacity)
            .and_then(|bytes| bytes.checked_add(self.output_capacity))
            .and_then(|bytes| bytes.checked_add(overhead))
            .and_then(|bytes| {
                bytes.checked_add(crate::error::CompletionStorage::allocation_bytes())
            })
            .ok_or_else(accounting)?;
        loop {
            let mut prepaid =
                crate::advanced::reserve_preparation_at_epoch(session, required, progress, epoch)?;
            let storage = Storage {
                input: SecretBytes::new(self.input_capacity)?,
                output: SecretBytes::new(self.output_capacity)?,
            };
            let actual = fixed
                .checked_add(storage.input.allocated_bytes())
                .and_then(|bytes| bytes.checked_add(storage.output.allocated_bytes()))
                .and_then(|bytes| bytes.checked_add(overhead))
                .and_then(|bytes| {
                    bytes.checked_add(crate::error::CompletionStorage::allocation_bytes())
                })
                .ok_or_else(accounting)?;
            if actual > required {
                // No guards are held. Release the complete candidate and its
                // reservation before waiting for the allocator's actual size.
                drop(storage);
                drop(prepaid);
                required = actual;
                continue;
            }
            prepaid.release(required - actual);
            let input = storage.input.bind_prepaid_payload(&mut prepaid)?;
            // Move the output header's existing charge, rather than charge it
            // twice. The output's credit follows it into PreparedDigest.
            let output = storage.output.bind_prepaid(&mut prepaid)?;
            let frame_bytes = fixed
                .checked_sub(size_of::<SecretBytes>())
                .ok_or_else(accounting)?;
            let call = NativeDigestCall {
                mechanism: CK_MECHANISM {
                    mechanism: self.mechanism,
                    pParameter: std::ptr::null_mut(),
                    ulParameterLen: 0,
                },
                input,
                output,
                length: bounds::ck_length(self.output_capacity)?,
                _credit: prepaid.split(frame_bytes)?,
            };
            let diagnostic = crate::error::PreparedCompletionCell::prepare(&mut prepaid)?;
            // Only the caller's permission/authentication overhead remains.
            return Ok((Prepared { call, diagnostic }, prepaid));
        }
    }
}

impl Session {
    /// Prehash, verification storage and key permissions share one reservation.
    /// A completed prehash can never be stranded waiting for its final frame.
    pub(super) fn prepare_verification_read_access(
        &self,
        key: &crate::ManagedObjectRef,
        algorithm: Option<NativeHash>,
        parts: &[&[u8]],
        multipart: bool,
        input_length: usize,
        signature_length: usize,
        software: Option<super::HashAlgorithm>,
        encoded_length: Option<usize>,
        retained_digest: Option<&super::PreparedDigest>,
    ) -> Result<(
        Option<Prepared>,
        super::native_signature::storage::Storage,
        super::native_signature::prehash::Storage,
        crate::session::SessionAccess<'_>,
    )> {
        let plan = algorithm
            .as_ref()
            .map(|algorithm| Plan::new(algorithm, parts, multipart))
            .transpose()?;
        let signature_plan =
            super::native_signature::storage::Plan::new(input_length, signature_length)?;
        let prehash_plan = super::native_signature::prehash::Plan {
            software,
            encoded_length,
        };
        let epoch = self.snapshot.authentication_stamp();
        let progress = match retained_digest {
            Some(digest) => AdmissionProgress::default()
                .retaining(digest.retained_bytes(&self.inner.symmetric_budget)?)?,
            None => AdmissionProgress::default(),
        };
        let (((prepared, prehash_storage), signature_storage), access) = self
            .prepare_with_roles_prepaid_at_epoch(
                [(Some(key), crate::session::activity::AccessMode::Read)],
                false,
                epoch,
                &progress,
                |overhead| {
                    signature_plan.prepare(overhead, |bytes| {
                        prehash_plan.prepare(parts, bytes, |bytes| match &plan {
                            Some(plan) => plan
                                .prepare(self, bytes, &progress, epoch)
                                .map(|(call, credit)| (Some(call), credit)),
                            None => crate::advanced::reserve_preparation_at_epoch(
                                self, bytes, &progress, epoch,
                            )
                            .map(|credit| (None, credit)),
                        })
                    })
                },
            )?;
        Ok((prepared, signature_storage, prehash_storage, access))
    }
}
