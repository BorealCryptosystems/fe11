// SPDX-License-Identifier: Apache-2.0
//! Represent session-credit records and their recovery identities.
//! Quota arithmetic and phase checks preserve exact tickets through handle loss.

use super::*;

impl Counts {
    pub(super) fn combine(self, other: Self) -> Result<Self> {
        Ok(Self {
            total: self.total.checked_add(other.total).ok_or(Error::Rejected(
                crate::RejectionReason::SessionAccounting(
                    crate::SessionAccountingRejection::SessionCountOverflow,
                ),
            ))?,
            read_write: self
                .read_write
                .checked_add(other.read_write)
                .ok_or(Error::Rejected(crate::RejectionReason::SessionAccounting(
                    crate::SessionAccountingRejection::SessionCountOverflow,
                )))?,
        })
    }

    pub(super) fn within(self, limit: SessionLimit) -> Result<()> {
        if self.total > limit.total || self.read_write > limit.read_write {
            Err(Error::Rejected(crate::RejectionReason::SessionAccounting(
                crate::SessionAccountingRejection::SessionLimit,
            )))
        } else {
            Ok(())
        }
    }

    pub(super) fn acquire(self, rw: bool, limit: SessionLimit) -> Result<Self> {
        let total = self.total.checked_add(1).ok_or(Error::Rejected(
            crate::RejectionReason::SessionAccounting(
                crate::SessionAccountingRejection::SessionCountOverflow,
            ),
        ))?;
        let read_write = self
            .read_write
            .checked_add(usize::from(rw))
            .ok_or(Error::Rejected(crate::RejectionReason::SessionAccounting(
                crate::SessionAccountingRejection::SessionCountOverflow,
            )))?;
        if total > limit.total || read_write > limit.read_write {
            return Err(Error::Rejected(crate::RejectionReason::SessionAccounting(
                crate::SessionAccountingRejection::SessionLimit,
            )));
        }
        Ok(Self { total, read_write })
    }

    pub(super) fn release(self, rw: bool) -> Result<Self> {
        Ok(Self {
            total: self.total.checked_sub(1).ok_or(Error::Rejected(
                crate::RejectionReason::SessionAccounting(
                    crate::SessionAccountingRejection::SessionCountInvariant,
                ),
            ))?,
            read_write: self
                .read_write
                .checked_sub(usize::from(rw))
                .ok_or(Error::Rejected(crate::RejectionReason::SessionAccounting(
                    crate::SessionAccountingRejection::SessionCountInvariant,
                )))?,
        })
    }
}

impl Record {
    pub(super) fn identity(&self) -> &RecordIdentity {
        match self {
            Self::Live { identity, .. }
            | Self::RetainedWithoutHandle { identity, .. }
            | Self::RetainedReturned { identity, .. } => identity,
        }
    }

    pub(super) fn identity_mut(&mut self) -> &mut RecordIdentity {
        match self {
            Self::Live { identity, .. }
            | Self::RetainedWithoutHandle { identity, .. }
            | Self::RetainedReturned { identity, .. } => identity,
        }
    }

    pub(super) fn closing(&self, ticket: u64) -> bool {
        match self {
            Self::Live {
                phase: Phase::Closing,
                identity,
                ..
            } => ticket != 0 && identity.proof.ticket.load(Ordering::Acquire) == ticket,
            Self::RetainedWithoutHandle {
                recovery: RetentionRecovery::Closing { ticket: own },
                ..
            }
            | Self::RetainedReturned {
                recovery: RetentionRecovery::Closing { ticket: own },
                ..
            } => ticket != 0 && *own == ticket,
            _ => false,
        }
    }

    pub(super) fn recovery_active(&self) -> bool {
        self.recovering(self.identity().proof.ticket.load(Ordering::Acquire))
            && !matches!(self.identity().close,
                CloseAttempt::Collective { completion, .. } if completion.return_known())
    }

    pub(super) fn entry(&self) -> Option<&Arc<crate::module::SessionEntry>> {
        match self {
            Self::Live { entry, .. } => entry.as_ref(),
            Self::RetainedWithoutHandle { entry, .. } | Self::RetainedReturned { entry, .. } => {
                Some(entry)
            }
        }
    }

    pub(super) fn phase(&self) -> Option<Phase> {
        match self {
            Self::Live { phase, .. } => Some(*phase),
            Self::RetainedWithoutHandle { .. } | Self::RetainedReturned { .. } => None,
        }
    }

    pub(super) fn live_native(&self) -> bool {
        matches!(self, Self::Live { phase, .. } if *phase != Phase::Reserved)
    }

    pub(super) fn native_present(&self) -> bool {
        self.live_native() || matches!(self, Self::RetainedReturned { .. })
    }

    pub(super) fn change_phase(&mut self, next: Phase) {
        // Callers validate Live first or deliberately leave a retention alone.
        if let Self::Live { phase, .. } = self {
            *phase = next;
        }
    }

    pub(super) fn recovering(&self, ticket: u64) -> bool {
        match self {
            Self::Live {
                phase: Phase::Recovering,
                identity,
                ..
            } => identity.proof.ticket.load(Ordering::Acquire) == ticket,
            Self::RetainedWithoutHandle {
                recovery: RetentionRecovery::Recovering { ticket: own },
                ..
            }
            | Self::RetainedReturned {
                recovery: RetentionRecovery::Recovering { ticket: own },
                ..
            } => *own == ticket,
            _ => false,
        }
    }
}
