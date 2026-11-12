// SPDX-License-Identifier: Apache-2.0
//! Ordinary-admission leases and their immutable, independently visible identity.
use crate::atomic_update::AtomicUpdate;
use crate::{
    module::{SessionEntry, SlotDomain},
    session::LeaseAdmission,
    symmetric::memory::Credit,
    Error, Result, TokenIdentity,
};
use std::sync::{
    atomic::{AtomicU64, AtomicU8, Ordering},
    Arc, Weak,
};

#[repr(u8)]
#[derive(Clone, Copy, PartialEq, Eq)]
enum LeaseClass {
    Unclassified,
    Stranded,
    Retired,
    Released,
}

enum Binding {
    Unbound,
    Bound {
        uid: u64,
        domain: Weak<SlotDomain>,
        token: TokenIdentity,
        generation: u64,
        entry: Weak<SessionEntry>,
    },
}

/// Shared by the ledger and its live lease; it never owns an Operation, Inner,
/// snapshot or session. Reading this identity requires no Operation mutex.
pub(super) struct Identity {
    binding: Binding,
    class: AtomicU8,
    proof_ticket: AtomicU64,
    _credit: Credit,
}
impl Identity {
    // The borrowed proof can only be constructed after close_entry owns this
    // session's gate and its slot writer. It excludes lease destruction and
    // replacement without locking the (possibly poisoned) Operation body.
    pub(super) fn classify(&self, proof: &crate::session::CloseOwnership<'_>) -> Result<()> {
        let entry = proof.entry();
        let domain = &entry.snapshot.domain;
        let ticket = entry.advanced_operation.load(Ordering::Acquire);
        if !self.matches(entry)
            || ticket == 0
            || domain.advanced_count_invalid.load(Ordering::Acquire)
        {
            return Err(Error::Rejected(crate::RejectionReason::ModuleLifecycle(
                crate::ModuleLifecycleRejection::RecoveryOwnerMismatch,
            )));
        }
        match self.class.load(Ordering::Acquire) {
            value if value == LeaseClass::Stranded as u8 => {
                return if self.proof_ticket.load(Ordering::Acquire) == ticket {
                    Ok(())
                } else {
                    Err(Error::Rejected(crate::RejectionReason::ModuleLifecycle(
                        crate::ModuleLifecycleRejection::RecoveryOwnerMismatch,
                    )))
                };
            }
            value if value == LeaseClass::Unclassified as u8 => {}
            _ => {
                return Err(Error::Rejected(crate::RejectionReason::ModuleLifecycle(
                    crate::ModuleLifecycleRejection::RecoveryOwnerMismatch,
                )))
            }
        }
        domain
            .advanced_stranded
            .update_checked(Ordering::AcqRel, Ordering::Acquire, |n| n.checked_add(1))
            .map_err(|_| {
                domain.advanced_count_invalid.store(true, Ordering::Release);
                Error::Rejected(crate::RejectionReason::ModuleLifecycle(
                    crate::ModuleLifecycleRejection::RecoveryOwnerMismatch,
                ))
            })?;
        self.proof_ticket.store(ticket, Ordering::Release);
        if self
            .class
            .compare_exchange(
                LeaseClass::Unclassified as u8,
                LeaseClass::Stranded as u8,
                Ordering::AcqRel,
                Ordering::Acquire,
            )
            .is_err()
        {
            // Even a concurrent Stranded value violates the gate proof; undo
            // this exact increment and keep the integrity failure sticky.
            let _ =
                domain
                    .advanced_stranded
                    .update_checked(Ordering::AcqRel, Ordering::Acquire, |n| n.checked_sub(1));
            domain.advanced_count_invalid.store(true, Ordering::Release);
            return Err(Error::Rejected(crate::RejectionReason::ModuleLifecycle(
                crate::ModuleLifecycleRejection::RecoveryOwnerMismatch,
            )));
        }
        Ok(())
    }

    pub(super) fn stranded_in(&self, domain: &Arc<SlotDomain>) -> bool {
        self.class.load(Ordering::Acquire) == LeaseClass::Stranded as u8
            && matches!(&self.binding, Binding::Bound { domain: own, .. }
                if own.ptr_eq(&Arc::downgrade(domain)))
    }

    pub(super) fn prove_stranded(
        &self,
        ledger: &crate::session_budget::SessionLedger,
    ) -> Result<()> {
        let Binding::Bound { uid, entry, .. } = &self.binding else {
            return Err(Error::Rejected(crate::RejectionReason::ModuleLifecycle(
                crate::ModuleLifecycleRejection::RecoveryOwnerMismatch,
            )));
        };
        if self.class.load(Ordering::Acquire) != LeaseClass::Stranded as u8 {
            return Err(Error::Rejected(crate::RejectionReason::ModuleLifecycle(
                crate::ModuleLifecycleRejection::RecoveryOwnerMismatch,
            )));
        }
        ledger.prove_stranded(
            *uid,
            entry,
            self.proof_ticket.load(Ordering::Acquire),
            |entry| self.matches(entry),
        )
    }

    pub(super) fn matches(&self, entry: &SessionEntry) -> bool {
        match &self.binding {
            Binding::Unbound => false,
            Binding::Bound {
                uid,
                domain,
                token,
                generation,
                entry: observed,
            } => {
                *uid == entry.credit.uid()
                    && domain.ptr_eq(&Arc::downgrade(&entry.snapshot.domain))
                    && token == &entry.snapshot.capabilities.identity
                    && *generation == entry.snapshot.generation
                    && std::ptr::eq(observed.as_ptr(), entry)
            }
        }
    }

    pub(super) fn slot(&self) -> u64 {
        match &self.binding {
            Binding::Bound { token, .. } => token.slot,
            Binding::Unbound => unreachable!("only bound leases are published"),
        }
    }

    pub(super) fn retired_binding(&self) -> bool {
        match &self.binding {
            Binding::Bound { entry, .. } => entry
                .upgrade()
                .is_some_and(|entry| entry.native_handle_retired()),
            Binding::Unbound => false,
        }
    }

    pub(super) fn uid(&self) -> u64 {
        match &self.binding {
            Binding::Bound { uid, .. } => *uid,
            Binding::Unbound => unreachable!("only bound lease identities are published"),
        }
    }
}

pub(super) struct PreparedIdentity(Arc<Identity>);
impl PreparedIdentity {
    pub(super) fn allocation_bytes() -> usize {
        // Payload and the Arc's strong/weak counters; not an allocator/RSS bound.
        std::mem::size_of::<Identity>() + 2 * std::mem::size_of::<usize>()
    }

    pub(super) fn from_prepaid(prepaid: &mut Credit) -> Result<Self> {
        Ok(Self(Arc::new(Identity {
            binding: Binding::Unbound,
            class: AtomicU8::new(LeaseClass::Unclassified as u8),
            proof_ticket: AtomicU64::new(0),
            _credit: prepaid.split(Self::allocation_bytes())?,
        })))
    }
}

pub(super) struct TokenLease {
    domain: Arc<SlotDomain>,
    identity: Arc<Identity>,
    // Restoration changes authentication after native commit; immutable close
    // identity above deliberately excludes this observation epoch.
    pub(super) authentication: u64,
}
impl crate::symmetric::memory::RetainedStorage for TokenLease {
    fn retain_credits(&self, retained: &mut crate::symmetric::memory::RetainedBytes) -> Result<()> {
        // This operation keeps its identity alive; the ledger's other Arc is
        // not an independent owner that can return this allocation while we wait.
        crate::symmetric::memory::RetainedStorage::retain_credits(&self.identity._credit, retained)
    }
}
impl TokenLease {
    /// All refusals precede consuming the credited identity. The caller can
    /// retain it beside its access guard and release access first on error.
    pub(super) fn new_retained(
        admission: &LeaseAdmission<'_, '_>,
        prepared: &mut Option<PreparedIdentity>,
    ) -> Result<Self> {
        let snapshot = admission.snapshot();
        let entry = admission.entry();
        let candidate = prepared.as_mut().ok_or(Error::Rejected(
            crate::RejectionReason::OperationOwnership(
                crate::OperationOwnershipRejection::OperationIdentityAbsent,
            ),
        ))?;
        // No clone escapes preparation. The binding copies fixed-width token
        // identity and weak owners only; it cannot allocate after the increment.
        let identity = Arc::get_mut(&mut candidate.0).ok_or(Error::Rejected(
            crate::RejectionReason::OperationOwnership(
                crate::OperationOwnershipRejection::SharedUnboundOperationIdentity,
            ),
        ))?;
        if snapshot
            .domain
            .advanced_count_invalid
            .load(Ordering::Acquire)
        {
            return Err(Error::Rejected(crate::RejectionReason::ModuleLifecycle(
                crate::ModuleLifecycleRejection::RecoveryOwnerMismatch,
            )));
        }
        snapshot
            .domain
            .advanced_active
            .update_checked(Ordering::AcqRel, Ordering::Acquire, |n| n.checked_add(1))
            .map_err(|_| {
                Error::Rejected(crate::RejectionReason::OperationOwnership(
                    crate::OperationOwnershipRejection::TokenOperationCount,
                ))
            })?;
        identity.binding = Binding::Bound {
            uid: entry.credit.uid(),
            domain: Arc::downgrade(&snapshot.domain),
            token: snapshot.capabilities.identity.clone(),
            generation: snapshot.generation,
            entry: Arc::downgrade(entry),
        };
        let identity = prepared.take().expect("identity checked before transfer").0;
        Ok(Self {
            domain: snapshot.domain.clone(),
            identity,
            authentication: snapshot.authentication_stamp(),
        })
    }

    /// Called under the slot writer and operation mutex after retirement and
    /// proof of no executing native call. This settles admission, not memory.
    pub(super) fn retire_admission(&self) -> Result<()> {
        let class = self.identity.class.load(Ordering::Acquire);
        if class == LeaseClass::Retired as u8 {
            return Ok(());
        }
        if class != LeaseClass::Unclassified as u8 && class != LeaseClass::Stranded as u8 {
            return Err(Error::Rejected(crate::RejectionReason::OperationOwnership(
                crate::OperationOwnershipRejection::RetiredOperationLeaseIdentity,
            )));
        }
        self.identity
            .class
            .store(LeaseClass::Retired as u8, Ordering::Release);
        let result = (|| {
            if class == LeaseClass::Stranded as u8 {
                self.domain
                    .advanced_stranded
                    .update_checked(Ordering::AcqRel, Ordering::Acquire, |n| n.checked_sub(1))
                    .map_err(|_| {
                        Error::Rejected(crate::RejectionReason::OperationOwnership(
                            crate::OperationOwnershipRejection::RetiredStrandedCount,
                        ))
                    })?;
            }
            self.domain
                .advanced_active
                .update_checked(Ordering::AcqRel, Ordering::Acquire, |n| n.checked_sub(1))
                .map_err(|_| {
                    Error::Rejected(crate::RejectionReason::OperationOwnership(
                        crate::OperationOwnershipRejection::RetiredOperationCount,
                    ))
                })?;
            Ok(())
        })();
        if result.is_err() {
            self.domain
                .advanced_count_invalid
                .store(true, Ordering::Release);
        }
        self.domain.activity.notify();
        result
    }

    pub(super) fn identity(&self) -> &Arc<Identity> {
        &self.identity
    }
}
impl Drop for TokenLease {
    fn drop(&mut self) {
        let class = self
            .identity
            .class
            .swap(LeaseClass::Released as u8, Ordering::AcqRel);
        if class == LeaseClass::Retired as u8 {
            return;
        }
        if class == LeaseClass::Stranded as u8 {
            if self
                .domain
                .advanced_stranded
                .update_checked(Ordering::AcqRel, Ordering::Acquire, |n| n.checked_sub(1))
                .is_err()
            {
                self.domain
                    .advanced_count_invalid
                    .store(true, Ordering::Release);
            }
        } else if class != LeaseClass::Unclassified as u8 {
            self.domain
                .advanced_count_invalid
                .store(true, Ordering::Release);
        }
        // S is decremented before A. A reader under the slot writer reads A
        // before S, so this destruction cannot fabricate an A<S observation.
        if self
            .domain
            .advanced_active
            .update_checked(Ordering::AcqRel, Ordering::Acquire, |n| n.checked_sub(1))
            .is_err()
        {
            // A counter inconsistency cannot become permission to administer
            // the token. Keep the refusal sticky for this domain's lifetime.
            self.domain
                .advanced_count_invalid
                .store(true, Ordering::Release);
        }
        self.domain.activity.notify();
    }
}
