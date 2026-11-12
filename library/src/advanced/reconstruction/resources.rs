// SPDX-License-Identifier: Apache-2.0
//! One unpublished storage graph for an import or native reattachment.
use super::{PreparedContinuation, Recipe};
use crate::advanced::{
    asynchronous::{JoinPlan, JoinedCall},
    preparation,
};
use crate::{
    session::AdmissionProgress,
    symmetric::memory::{Buffer, Credit, UnboundBuffer},
    Error, Result, Session,
};

/// The containing operation defines its fixed owners. Independent native state
/// and Join output allocations are admitted with the continuation, never after it.
pub(in crate::advanced) struct Resources {
    pub(in crate::advanced) continuation: PreparedContinuation,
    pub(in crate::advanced) native: Option<Buffer>,
    pub(in crate::advanced) joined: Option<JoinedCall>,
    pub(in crate::advanced) metadata: Credit,
    pub(in crate::advanced) key_storage: crate::advanced::key_storage::Ready,
}

impl Resources {
    pub(in crate::advanced) fn prepare(
        session: &Session,
        progress: &AdmissionProgress,
        recipe: Recipe<'_>,
        native_capacity: Option<usize>,
        join: Option<JoinPlan>,
        fixed_bytes: usize,
    ) -> Result<Self> {
        Self::prepare_aggregate(
            session,
            progress,
            recipe,
            native_capacity,
            join,
            fixed_bytes,
            crate::advanced::key_storage::Plan::default(),
            None,
        )
    }
    pub(in crate::advanced) fn prepare_at_epoch(
        session: &Session,
        progress: &AdmissionProgress,
        recipe: Recipe<'_>,
        native_capacity: Option<usize>,
        join: Option<JoinPlan>,
        fixed_bytes: usize,
        authentication: u64,
    ) -> Result<Self> {
        Self::prepare_with_key_storage(
            session,
            progress,
            recipe,
            native_capacity,
            join,
            fixed_bytes,
            crate::advanced::key_storage::Plan::default(),
            authentication,
        )
    }

    pub(in crate::advanced) fn prepare_with_key_storage(
        session: &Session,
        progress: &AdmissionProgress,
        recipe: Recipe<'_>,
        native_capacity: Option<usize>,
        join: Option<JoinPlan>,
        fixed_bytes: usize,
        key_plan: crate::advanced::key_storage::Plan,
        authentication: u64,
    ) -> Result<Self> {
        Self::prepare_aggregate(
            session,
            progress,
            recipe,
            native_capacity,
            join,
            fixed_bytes,
            key_plan,
            Some(authentication),
        )
    }

    fn prepare_aggregate(
        session: &Session,
        progress: &AdmissionProgress,
        recipe: Recipe<'_>,
        native_capacity: Option<usize>,
        join: Option<JoinPlan>,
        fixed_bytes: usize,
        key_plan: crate::advanced::key_storage::Plan,
        authentication: Option<u64>,
    ) -> Result<Self> {
        let mut required = total(&[
            key_plan.allocation_bytes()?,
            recipe.allocation_bytes()?,
            native_capacity.unwrap_or(0),
            join.as_ref()
                .map(JoinPlan::allocation_bytes)
                .transpose()?
                .unwrap_or(0),
            fixed_bytes,
        ])?;
        loop {
            // Imports and native reattachments keep their entry epoch through
            // every retry, including actual-capacity growth and maintenance.
            // Ordinary fresh recovery retains its existing admission contract.
            let mut credit = match authentication {
                Some(epoch) => {
                    preparation::reserve_new_at_epoch(session, required, progress, epoch)?
                }
                None => preparation::reserve_new_with_progress(session, required, progress)?,
            };
            let key_storage = key_plan.allocate()?;
            let continuation = recipe.allocate(&mut credit)?;
            let native = native_capacity.map(UnboundBuffer::allocate).transpose()?;
            let joined = join.map(JoinPlan::allocate).transpose()?;
            let actual = total(&[
                key_storage.allocated_bytes()?,
                continuation.allocated_bytes()?,
                native.as_ref().map_or(0, UnboundBuffer::allocated),
                joined
                    .as_ref()
                    .map(|storage| storage.allocated_bytes())
                    .transpose()?
                    .unwrap_or(0),
                fixed_bytes,
            ])?;
            if actual > required {
                // Every unpublished owner and split selection credit is dropped
                // before another admission can wait. No native call is replayed.
                drop(key_storage);
                drop(joined);
                drop(native);
                drop(continuation);
                drop(credit);
                required = actual;
                continue;
            }
            credit.release(required - actual);
            return Ok(Self {
                continuation: recipe.bind(continuation, &mut credit)?,
                native: native
                    .map(|storage| storage.bind(&mut credit))
                    .transpose()?,
                joined: joined
                    .map(|storage| storage.bind(&mut credit))
                    .transpose()?,
                key_storage: key_storage.bind(&mut credit)?,
                metadata: credit,
            });
        }
    }
}

pub(in crate::advanced) fn total(parts: &[usize]) -> Result<usize> {
    parts
        .iter()
        .try_fold(0usize, |total, bytes| total.checked_add(*bytes))
        .ok_or(Error::Rejected(crate::RejectionReason::Restoration(
            crate::RestorationRejection::TransferStorageAccounting,
        )))
}
