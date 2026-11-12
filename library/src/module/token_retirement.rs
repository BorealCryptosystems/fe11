// SPDX-License-Identifier: Apache-2.0
//! Admission withdrawal does not establish completion of native work.

use super::*;

pub(super) enum Retirement {
    Current,
    AdmissionWithdrawn { foreign_epoch: u64 },
    Complete,
}

impl TokenSnapshot {
    /// Ordinary admission is narrower than the native identity still held by
    /// an existing owner. Withdrawal alone must not prohibit its explicit close.
    pub(crate) fn admission_available(&self) -> bool {
        self.valid.load(Ordering::Acquire) && !self.admission_withdrawn.load(Ordering::Acquire)
    }

    /// Called under the registry lock for the exact discovery observation.
    /// Existing foreign progress keeps its epoch until the slot writer can
    /// establish successor readiness. No memory or callback owner is released.
    pub(crate) fn withdraw_admission(&self, foreign_epoch: u64) {
        {
            let mut retirement = self.retirement.lock().unwrap_or_else(|e| e.into_inner());
            if matches!(*retirement, Retirement::Current) {
                *retirement = Retirement::AdmissionWithdrawn { foreign_epoch };
                self.admission_withdrawn.store(true, Ordering::Release);
            }
        }
        self.notify_retirement();
    }

    pub(crate) fn invalidate(&self) {
        {
            // No fallible work or application code inside this short lock.
            // Recovering its metadata after poison still only withdraws rights.
            let mut retirement = self.retirement.lock().unwrap_or_else(|e| e.into_inner());
            let epoch = match *retirement {
                Retirement::Current => Some(self.domain.foreign_epoch.load(Ordering::Acquire)),
                Retirement::AdmissionWithdrawn { foreign_epoch } => Some(foreign_epoch),
                Retirement::Complete => None,
            };
            self.valid.store(false, Ordering::Release);
            if let Some(epoch) = epoch {
                // Compare-and-retire cannot advance a newer foreign epoch.
                self.domain.retire_foreign_epoch(epoch);
            }
            *retirement = Retirement::Complete;
        }
        self.notify_retirement();
    }

    fn notify_retirement(&self) {
        // Wait predicates do not acquire the registry or retirement mutex.
        self.domain.activity.notify();
        self.domain.transition.notify();
        self.notify_admission();
    }
}
