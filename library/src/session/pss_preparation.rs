// SPDX-License-Identifier: Apache-2.0
//! Prepaid native storage for the public Digest32/PSS adapters.
use super::{AdmissionProgress, PssCall, Session};
use crate::{native::frame::SessionFrame, symmetric::memory::Credit, Error, Result};
use std::mem::size_of;

/// Keep diagnostics outside the native frame until the public return boundary.
#[derive(Default)]
pub(super) struct SigningDiagnostics {
    pub(super) sequence: Option<crate::error::PreparedCompletionCell>,
    pub(super) authentication: Option<super::ContextDiagnostics>,
}

pub(super) struct Storage {
    pub(super) signature: Vec<u8>,
    pub(super) diagnostic: crate::error::PreparedCompletionCell,
    pub(super) credit: Credit,
}
impl Storage {
    pub(super) fn prepare(
        session: &Session,
        length: usize,
        overhead: usize,
        progress: &AdmissionProgress,
        epoch: u64,
    ) -> Result<(Self, Credit)> {
        crate::bounds::ck_length(length)?;
        let fixed = size_of::<PssCall>()
            .checked_add(SessionFrame::<'_, PssCall>::allocation_bytes())
            .ok_or(Error::Rejected(crate::RejectionReason::SessionLifecycle(
                crate::SessionLifecycleRejection::PssStorageAccounting,
            )))?;
        let mut required = fixed
            .checked_add(length)
            .and_then(|n| n.checked_add(overhead))
            .and_then(|n| n.checked_add(crate::error::CompletionStorage::allocation_bytes()))
            .ok_or(Error::Rejected(crate::RejectionReason::SessionLifecycle(
                crate::SessionLifecycleRejection::PssStorageAccounting,
            )))?;
        loop {
            let mut prepaid =
                crate::advanced::reserve_preparation_at_epoch(session, required, progress, epoch)?;
            let mut signature = Vec::new();
            signature.try_reserve_exact(length).map_err(|_| {
                Error::Rejected(crate::RejectionReason::SessionLifecycle(
                    crate::SessionLifecycleRejection::RsaSignatureAllocation,
                ))
            })?;
            signature.resize(length, 0);
            let actual = fixed
                .checked_add(signature.capacity())
                .ok_or(Error::Rejected(crate::RejectionReason::SessionLifecycle(
                    crate::SessionLifecycleRejection::PssStorageAccounting,
                )))?;
            let total = actual
                .checked_add(overhead)
                .and_then(|n| n.checked_add(crate::error::CompletionStorage::allocation_bytes()))
                .ok_or(Error::Rejected(crate::RejectionReason::SessionLifecycle(
                    crate::SessionLifecycleRejection::PssStorageAccounting,
                )))?;
            if total > required {
                drop(signature);
                drop(prepaid);
                required = total;
                continue;
            }
            prepaid.release(required - total);
            let diagnostic = crate::error::PreparedCompletionCell::prepare(&mut prepaid)?;
            let credit = prepaid.split(actual)?;
            return Ok((
                Self {
                    signature,
                    diagnostic,
                    credit,
                },
                prepaid,
            ));
        }
    }
}
