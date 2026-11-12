// SPDX-License-Identifier: Apache-2.0
//! Session-lifetime diagnostic storage, prepaid before native opening.
use crate::{
    error::{CompletionDiagnostic, CompletionStorage},
    module::SessionEntry,
    symmetric::memory::{Budget, ControlledReservation, Credit},
    Error, ResourceAdmission, Result,
};
use std::sync::{
    atomic::{AtomicBool, Ordering},
    Arc, Mutex,
};

#[derive(Default)]
struct Slots {
    primary: Option<CompletionStorage>,
    secondary: Option<CompletionStorage>,
}

/// The inline bookkeeping and both heap leaves belong to the session entry.
/// This is not a module-wide floor: unrelated sessions may release their stores.
pub(crate) struct Store {
    slots: Mutex<Slots>,
    loaned: AtomicBool,
    // Last: destroy any retained leaves before releasing their byte charge.
    credit: Credit,
}

impl Store {
    pub(crate) fn allocation_bytes() -> usize {
        std::mem::size_of::<Self>() + 2 * CompletionStorage::allocation_bytes()
    }

    /// This session's storage cannot be released by a peer while its operation
    /// waits. Count it in intrinsic demand, without reserving its credit twice.
    pub(crate) fn including(additional: usize) -> Result<usize> {
        additional
            .checked_add(Self::allocation_bytes())
            .ok_or(Error::Rejected(crate::RejectionReason::SessionLifecycle(
                crate::SessionLifecycleRejection::SessionLifecycleStorageAccounting,
            )))
    }

    pub(crate) fn from_prepaid(prepaid: &mut Credit) -> Result<Self> {
        let credit = prepaid.split(Self::allocation_bytes())?;
        Ok(Self {
            slots: Mutex::new(Slots {
                primary: Some(CompletionStorage::allocate()?),
                secondary: Some(CompletionStorage::allocate()?),
            }),
            loaned: AtomicBool::new(false),
            credit,
        })
    }

    /// Borrow only outside native/session possession. Refill a leaf only after
    /// the preceding public invocation transferred its error to its caller.
    pub(crate) fn loan(entry: &Arc<SessionEntry>, admission: &ResourceAdmission) -> Result<Loan> {
        Self::loan_checked(entry, admission, &|| Ok(()))
    }

    /// New native maintenance admissions can be withdrawn while waiting for
    /// this store. Local repair callers keep the unrestricted loan above.
    pub(crate) fn loan_checked(
        entry: &Arc<SessionEntry>,
        admission: &ResourceAdmission,
        validate: &dyn Fn() -> Result<()>,
    ) -> Result<Loan> {
        let store = &entry.lifecycle_diagnostics;
        // A peer can return this loan independently. Preserve the caller's
        // WaitUntil policy without a new lock, timeout or global serialization.
        // No native possession is held while waiting on the existing budget Wake.
        let claim = store
            .credit
            .budget()
            .admission_wake()
            .acquire(admission, || {
                use crate::admission_wait::Attempt;
                validate()?;
                Ok(
                    match store.loaned.compare_exchange(
                        false,
                        true,
                        Ordering::Acquire,
                        Ordering::Relaxed,
                    ) {
                        Ok(false) => Attempt::Acquired(LoanClaim {
                            entry: entry.clone(),
                        }),
                        _ => Attempt::Occupied(crate::BusyReason::SessionLifecycle(
                            crate::SessionLifecycleBusy::SessionLifecycleDiagnostic,
                        )),
                    },
                )
            })?;
        validate()?;
        let mut loan = Loan {
            slots: Slots::default(),
            claim,
        };
        loan.slots = std::mem::take(&mut *store.slots.lock().unwrap_or_else(|p| p.into_inner()));
        if loan.slots.primary.is_none() {
            loan.slots.primary = Some(CompletionStorage::allocate()?);
        }
        if loan.slots.secondary.is_none() {
            loan.slots.secondary = Some(CompletionStorage::allocate()?);
        }
        validate()?;
        Ok(loan)
    }
}

/// Keep this at the public boundary. Returning from an internal helper does not
/// permit a second call to reuse the same charge while its first error is live.
pub(crate) struct Loan {
    slots: Slots,
    // Last: release the claim only after returning or dropping the leaves.
    claim: LoanClaim,
}

/// Acquisition itself owns its rollback, including Wake's final cancellation
/// or deadline check. No leaf is extracted until this claim leaves Wake.
struct LoanClaim {
    entry: Arc<SessionEntry>,
}
impl Drop for LoanClaim {
    fn drop(&mut self) {
        let store = &self.entry.lifecycle_diagnostics;
        store.loaned.store(false, Ordering::Release);
        store.credit.budget().admission_wake().notify();
    }
}

impl Loan {
    pub(crate) fn completion(&mut self, function: &'static str) -> Result<CompletionDiagnostic> {
        self.slots
            .primary
            .take()
            .map(|storage| storage.bind(function))
            .ok_or(Error::Rejected(crate::RejectionReason::SessionLifecycle(
                crate::SessionLifecycleRejection::LifecycleDiagnosticAlreadyConsumed,
            )))
    }

    pub(crate) fn completions(
        &mut self,
        function: &'static str,
    ) -> Result<(CompletionDiagnostic, CompletionDiagnostic)> {
        let primary = self.completion(function)?;
        let secondary = self.slots.secondary.take().ok_or(Error::Rejected(
            crate::RejectionReason::SessionLifecycle(
                crate::SessionLifecycleRejection::LifecycleSecondaryDiagnosticAlreadyConsumed,
            ),
        ))?;
        Ok((primary, secondary.bind(function)))
    }

    pub(crate) fn owns(&self, entry: &Arc<SessionEntry>) -> bool {
        Arc::ptr_eq(&self.claim.entry, entry)
    }
}
impl Drop for Loan {
    fn drop(&mut self) {
        let store = &self.claim.entry.lifecycle_diagnostics;
        let mut slots = store.slots.lock().unwrap_or_else(|p| p.into_inner());
        *slots = std::mem::take(&mut self.slots);
        // This guard leaves before the last claim field notifies waiters.
    }
}

/// Collective recovery uses a captured session's prepaid storage. Only an
/// empty recovery batch admits a new leaf: it has no captured session buffers
/// whose release depends on the pending C_CloseAllSessions. The caller drops
/// its population/close owners before this preparation and revalidates after it.
pub(crate) enum RecoveryDiagnostic {
    Session(Loan),
    Empty(crate::error::PreparedCompletion),
}
impl RecoveryDiagnostic {
    pub(crate) fn matches(&self, entry: Option<&Arc<SessionEntry>>) -> bool {
        match (self, entry) {
            (Self::Session(loan), Some(entry)) => loan.owns(entry),
            (Self::Empty(_), None) => true,
            _ => false,
        }
    }

    pub(crate) fn prepare(
        entry: Option<&Arc<SessionEntry>>,
        budget: &Arc<Budget>,
        admission: &ResourceAdmission,
        mut before: impl FnMut() -> Result<()>,
    ) -> Result<Self> {
        if let Some(entry) = entry {
            return Store::loan(entry, admission).map(Self::Session);
        }
        let mut credit = match budget.reserve_controlled::<std::convert::Infallible>(
            crate::error::PreparedCompletion::allocation_bytes(),
            admission,
            || {
                before()?;
                Ok(None)
            },
            || Ok(None),
        )? {
            ControlledReservation::Acquired(credit) => credit,
            ControlledReservation::Redirect(never) => match never {},
        };
        crate::error::PreparedCompletion::prepare("C_CloseAllSessions", &mut credit)
            .map(Self::Empty)
    }

    pub(crate) fn take(&mut self) -> Result<CompletionDiagnostic> {
        match self {
            Self::Session(loan) => loan.completion("C_CloseAllSessions"),
            Self::Empty(prepared) => prepared.take(),
        }
    }
}
