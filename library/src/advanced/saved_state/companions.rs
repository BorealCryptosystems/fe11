// SPDX-License-Identifier: Apache-2.0
//! Capture local plans at one session boundary. Only the selected operation
//! drives GetOperationState: the provider returns one opaque session image.
use super::*;
use crate::advanced::capture_preparation::{self, PreparedCapture};
use crate::symmetric::memory::{RetainedBytes, RetainedStorage};

pub(in crate::advanced) struct SavedCompanion {
    pub(in crate::advanced) stamp: Option<progress::Stamp>,
    pub(in crate::advanced) continuation: Continuation,
    pub(in crate::advanced) credit: Credit,
}

impl RetainedStorage for SavedCompanion {
    fn retain_credits(&self, retained: &mut RetainedBytes) -> Result<()> {
        self.continuation.retain_credits(retained)?;
        self.credit.retain_credits(retained)
    }
}

fn changed() -> Error {
    Error::Rejected(crate::RejectionReason::OperationOwnership(
        crate::OperationOwnershipRejection::StaleOperationTicket,
    ))
}

impl CaptureOwner {
    pub(super) fn check_members(&self, entry: &SessionEntry, selected: u64) -> Result<()> {
        let members = entry.advanced_progress.snapshot()?;
        if members.iter().flatten().count() != 1 + self.companions.len()
            || !entry.advanced_progress.contains(selected)
            || self.companions.iter().any(|peer| {
                peer.stamp
                    .map_or(true, |stamp| entry.advanced_progress.changed(stamp))
            })
        {
            return Err(changed());
        }
        Ok(())
    }
}

pub(super) fn prepare<'a>(
    session: &'a Session,
    selected: &OperationTicket,
    maximum: usize,
    diagnostics: &mut Option<progress::FailureDiagnostics>,
) -> Result<PreparedCapture<'a>> {
    let members = {
        let _access = session.advanced_access()?;
        session.entry.advanced_progress.snapshot()?
    };
    let mut primary = capture_preparation::prepare(session, selected, maximum, diagnostics)?;
    let peers = members.iter().flatten().filter(|s| s.ticket != selected.id);
    primary
        .owner
        .companions
        .try_reserve_exact(peers.clone().count())
        .map_err(|_| {
            Error::Rejected(crate::RejectionReason::OperationOwnership(
                crate::OperationOwnershipRejection::OperationRegistryAllocation,
            ))
        })?;
    for &stamp in peers {
        let peer = OperationTicket {
            restored_companions: Vec::new(),
            owner: session.inner.clone(),
            uid: session.uid,
            id: stamp.ticket,
            validation_report: None,
            state_provenance: None,
        };
        let mut copy = capture_preparation::prepare(session, &peer, maximum, diagnostics)?;
        let _access = session.advanced_access()?;
        if copy.waiter.changed() || session.entry.advanced_progress.changed(stamp) {
            return Err(changed());
        }
        copy.waiter.succeed()?;
        if copy.owner.provenance == StateProvenance::Imported {
            primary.owner.provenance = StateProvenance::Imported;
        }
        primary.owner.companions.push(SavedCompanion {
            stamp: Some(stamp),
            continuation: copy.owner.continuation,
            credit: copy.owner._credit,
        });
    }
    Ok(primary)
}
