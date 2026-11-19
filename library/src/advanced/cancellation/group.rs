// SPDX-License-Identifier: Apache-2.0
//! One scalar cancellation call addresses the session. Its return applies to
//! each requested category while unrelated continuations retain their rights.
use super::*;
use crate::advanced::ledger::{ClosedOperation, OperationCell};
use std::sync::Arc;

#[derive(Default)]
pub(super) struct CancelGroup {
    peers: [Option<Arc<OperationCell>>; 5],
    pub(super) pending_parent: bool,
}

impl CancelGroup {
    pub(super) fn select(
        state: &State,
        uid: u64,
        flags: Option<CK_FLAGS>,
    ) -> Result<(Self, Arc<OperationCell>)> {
        let mut peers = state.operations.live_cells(uid)?;
        let grouped = peers.iter().flatten().nth(1).is_some();
        let mut selected = None;
        let mut pending_parent = false;
        for (index, cell) in peers.iter().enumerate() {
            let Some(cell) = cell else { continue };
            let operation = cell.lock().map_err(|_| Error::Poisoned)?;
            match flags {
                Some(mask) => {
                    // GetOperationState describes the whole session, including
                    // a sibling outside this cancellation mask. Preserve a
                    // cooperative transfer and any outstanding native loan.
                    if grouped
                        && (operation.state.is_some()
                            || operation.transfer.is_some()
                            || operation.joined.is_some())
                    {
                        return Err(Error::Busy(crate::BusyReason::OperationOwnership(
                            crate::OperationOwnershipBusy::OperationStateControl,
                        )));
                    }
                    if operation.cancel.is_submitted() {
                        return Err(Error::Busy(crate::BusyReason::Cancellation(
                            crate::CancellationBusy::CancellationPending,
                        )));
                    }
                    if operation.rejoin().is_some()
                        || operation.detachment().is_some()
                        || operation.restore_owner().is_some()
                    {
                        let reason = if operation.rejoin().is_some() {
                            crate::CancellationBusy::OperationRejoinControl
                        } else if operation.detachment().is_some() {
                            crate::CancellationBusy::OperationDetachmentControl
                        } else {
                            crate::CancellationBusy::StateRestorationActive
                        };
                        return Err(Error::Busy(crate::BusyReason::Cancellation(reason)));
                    }
                    pending_parent |= operation.execution_incomplete();
                    if operation.active_categories() & mask != 0 {
                        selected.get_or_insert(index);
                    }
                }
                None if operation.cancel.is_submitted() => {
                    selected = Some(index);
                }
                None => {}
            }
        }
        let index = selected.unwrap_or(0);
        let cell = peers[index].take().ok_or(Error::Rejected(
            crate::RejectionReason::OperationOwnership(
                crate::OperationOwnershipRejection::OperationAbsent,
            ),
        ))?;
        Ok((
            Self {
                peers,
                pending_parent,
            },
            cell,
        ))
    }

    pub(super) fn claim(
        &self,
        state: &State,
        entry: &SessionEntry,
        id: u64,
        mask: CK_FLAGS,
    ) -> Result<()> {
        if self.peers.iter().all(Option::is_none) {
            return state.operations.claim_progress(entry, id);
        }
        for peer in self.peers.iter().flatten() {
            let peer = peer.lock().map_err(|_| Error::Poisoned)?;
            if peer.active_categories() & mask != 0 {
                entry.advanced_progress.claim(peer.id)?;
            }
        }
        entry.advanced_progress.claim(id)?;
        state.operations.notify_claim(entry);
        Ok(())
    }

    pub(super) fn complete(
        &self,
        state: &State,
        entry: &SessionEntry,
        primary: &mut Operation,
        rv: CK_RV,
        returned: bool,
        source: CancellationReturnSource,
        retired: &mut Option<ClosedOperation>,
        retired_peers: &mut [Option<ClosedOperation>; 5],
    ) -> Result<CancellationProgress> {
        let flags = primary.cancel.as_mut().ok_or(Error::Poisoned)?.flags;
        let mut remaining = 0;
        let mut failure = None;
        for (peer, retired) in self.peers.iter().flatten().zip(retired_peers) {
            let mut peer = peer.lock().map_err(|_| Error::Poisoned)?;
            let active = peer.active_categories();
            if active & flags == 0 {
                remaining |= active;
                continue;
            }
            peer.cancel.submit(flags);
            peer.cancel
                .as_mut()
                .expect("installed scalar cancellation")
                .record_return(rv, source);
            match finish_and_retire(state, entry, &mut peer, rv, returned, retired) {
                Ok(CancellationProgress::Complete { remaining: mask }) => remaining |= mask.0,
                Ok(CancellationProgress::Pending) => {
                    unreachable!("completion requires a terminal return")
                }
                Err(error) => {
                    failure.get_or_insert(error);
                }
            }
        }
        let result = finish_and_retire(state, entry, primary, rv, returned, retired)?;
        if let Some(error) = failure {
            return Err(error);
        }
        match result {
            CancellationProgress::Complete { remaining: mask } => {
                Ok(CancellationProgress::Complete {
                    remaining: CancellationFlags(remaining | mask.0),
                })
            }
            progress => Ok(progress),
        }
    }
}
