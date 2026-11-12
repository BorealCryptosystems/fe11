// SPDX-License-Identifier: Apache-2.0
//! Aggregate admission of owned bytes, without a lock across native operations.
use crate::{
    admission_wait::{Attempt, Wake},
    Error, Result,
};
use std::sync::{
    atomic::{AtomicU64, AtomicUsize, Ordering},
    Arc, Mutex,
};
use zeroize::Zeroize;

/// Aggregate buffer and owned metadata credit ceiling across all sessions.
#[derive(Clone, Copy, Debug)]
pub struct SymmetricLimits {
    /// Credit ceiling, including the module's resident coordination storage.
    /// History records retain their actual Rust payload sizes and resource keys.
    /// Object activity and creation coordination retain their planned peak payload
    /// credits until their last owner, including outstanding native-call permits.
    /// Each new advanced operation prepays its inline cancellation slot (tag,
    /// payload, padding and credit metadata at the actual Rust size). That credit
    /// remains resident until the operation shell is released; cancellation does
    /// not acquire it again. Replacing a body reuses the existing shell's slot.
    /// Its immutable lease identity is also prepaid, including the shared Rust
    /// payload and Arc counters. Weak identity links retain no session or module.
    /// Fixed session coordination metadata is excluded: the inline progress
    /// cell and the shared protection cell of its serialized access. Access
    /// clones share that cell; retaining it withdraws the exact session Entry
    /// from further admission. Its object/creation/inventory payloads keep their
    /// own credits until their last owner. Cleanup takes no new cell credit.
    /// Module opening also earmarks its initialization frame, notification
    /// progress metadata and two finalization diagnostic leaves.
    /// That module-lifetime storage counts toward this ceiling and every
    /// operation's intrinsic bound. Finalize reuses it even when operation
    /// storage occupies the remaining budget; it never waits for those bytes.
    /// This is a credit ceiling, not a process RSS or allocator-heap limit.
    /// Consumer copies, allocator overhead and native provider memory are excluded.
    pub maximum_buffer_bytes: usize,
}
pub(crate) struct Budget {
    maximum: usize,
    used: AtomicUsize,
    // Module-lifetime control storage cannot be released to admit another
    // operation. Include it in intrinsic demand as well as in `used`.
    resident: AtomicUsize,
    wake: Arc<Wake>,
    // A private observation uses the same global counter and wake, but also
    // tracks the credits that its continuation cannot release while waiting.
    // There is only one level: the parent is always the module's budget.
    parent: Option<Arc<Budget>>,
    // Only the global account's sequence is used. It serializes immutable
    // footprint walks and their deduplication stamps. The walk releases this
    // mutex before byte admission; it reserves no credit and takes no leaf lock.
    footprint_sequence: Mutex<u64>,
    // Accessed only during a walk under the matching global sequence mutex.
    // Atomic storage preserves Budget's Sync contract without unsafe code.
    last_footprint: AtomicU64,
    // The observation budget's own allocation is prepaid from its parent.
    // Keeping this credit outside the child avoids an ownership cycle.
    _storage: Option<Credit>,
}
/// A routing decision carries no reservation and is interpreted outside Wake.
pub(crate) enum ControlledReservation<T> {
    Acquired(Credit),
    Redirect(T),
}
impl Budget {
    pub(crate) fn new(limits: SymmetricLimits) -> Result<Self> {
        // This ceiling covers the sum of distinct live allocations. The Rust
        // isize::MAX restriction applies to each allocation, not their sum.
        // reserve checks sum overflow; Buffer::new uses fallible allocation.
        Ok(Self {
            maximum: limits.maximum_buffer_bytes,
            used: AtomicUsize::new(0),
            resident: AtomicUsize::new(0),
            wake: Arc::new(Wake::default()),
            parent: None,
            footprint_sequence: Mutex::new(0),
            last_footprint: AtomicU64::new(0),
            _storage: None,
        })
    }
    /// Publish a local ownership transition after its atomic indicators and
    /// ledger commit. No credit is returned by this notification.
    pub(crate) fn notify_progress(&self) {
        self.wake.notify();
    }
    pub(crate) fn admission_wake(&self) -> Arc<Wake> {
        self.wake.clone()
    }
    pub(crate) fn check_successor_limit(&self, limit: crate::SymmetricLimits) -> Result<()> {
        if self.parent.is_some() || self.maximum != limit.maximum_buffer_bytes {
            return Err(Error::Rejected(crate::RejectionReason::MemoryAccounting(
                crate::MemoryAccountingRejection::SuccessorMustPreserveRetainedByteCreditDomain,
            )));
        }
        Ok(())
    }

    pub(crate) fn observation_bytes() -> usize {
        std::mem::size_of::<Self>() + 2 * std::mem::size_of::<usize>()
    }

    /// A private account is reused by descendant preparations; only a new
    /// observation needs another allocation for its accounting header.
    pub(crate) fn observation_overhead(&self) -> usize {
        if self.parent.is_some() {
            0
        } else {
            Self::observation_bytes()
        }
    }

    fn global(self: &Arc<Self>) -> &Arc<Self> {
        self.parent.as_ref().unwrap_or(self)
    }

    pub(crate) fn same_account(self: &Arc<Self>, other: &Arc<Self>) -> bool {
        Arc::ptr_eq(self.global(), other.global())
    }

    /// Intrinsic demand includes every still-live child credit, not the bytes
    /// of unrelated observations. Only those unrelated owners can relieve a
    /// shortage while this continuation waits. Recheck after each wake/retry.
    pub(crate) fn check_request(&self, additional: usize) -> Result<()> {
        let retained = if self.parent.is_some() {
            self.used.load(Ordering::Acquire)
        } else {
            0
        };
        let requested = retained.checked_add(additional).ok_or(Error::Rejected(
            crate::RejectionReason::MemoryAccounting(
                crate::MemoryAccountingRejection::SymmetricBudgetCounterOverflow,
            ),
        ))?;
        self.check_intrinsic(requested)
    }

    fn check_intrinsic(&self, requested: usize) -> Result<()> {
        let global = self.parent.as_deref().unwrap_or(self);
        let requested = requested
            .checked_add(global.resident.load(Ordering::Acquire))
            .ok_or(Error::Rejected(crate::RejectionReason::MemoryAccounting(
                crate::MemoryAccountingRejection::SymmetricBudgetCounterOverflow,
            )))?;
        if requested > self.maximum {
            return Err(Error::ResourceLimitExceeded {
                resource: crate::ResourceKind::SymmetricByteBudget,
                requested,
                limit: self.maximum,
            });
        }
        Ok(())
    }

    fn release_bytes(&self, bytes: usize) {
        self.used.fetch_sub(bytes, Ordering::AcqRel);
        if let Some(parent) = &self.parent {
            parent.used.fetch_sub(bytes, Ordering::AcqRel);
        }
    }

    pub(crate) fn reserve(self: &Arc<Self>, bytes: usize) -> Result<Credit> {
        self.reserve_admitted(bytes, &crate::admission_wait::current())
    }
    /// Both predicates run under the admission Wake. Atomic observations and
    /// pure calculations are allowed. A metadata-only try_lock is also allowed
    /// if contention redirects, its guard leaves before return, and inspection
    /// cannot destroy credited owners or notify. Never wait for another lock,
    /// allocate, call native code, release credit or notify while owning Wake.
    /// A redirect and any resulting reclamation are handled after unlock.
    /// `before` runs before every attempt; `occupied` only after shortage, before refusal or a possible wait.
    pub(crate) fn reserve_controlled<T>(
        self: &Arc<Self>,
        bytes: usize,
        admission: &crate::ResourceAdmission,
        before: impl FnMut() -> Result<Option<T>>,
        occupied: impl FnMut() -> Result<Option<T>>,
    ) -> Result<ControlledReservation<T>> {
        self.reserve_controlled_retaining(bytes, 0, admission, before, occupied)
    }

    /// Include an exclusive caller-owned global credit in this private
    /// continuation's intrinsic bound, without charging or reserving it twice.
    /// Other calls' global credits remain releasable pressure, not this source.
    pub(crate) fn reserve_controlled_retaining<T>(
        self: &Arc<Self>,
        bytes: usize,
        retained: usize,
        admission: &crate::ResourceAdmission,
        mut before: impl FnMut() -> Result<Option<T>>,
        mut occupied: impl FnMut() -> Result<Option<T>>,
    ) -> Result<ControlledReservation<T>> {
        // Preserve the ordinary reservation's intrinsic-bound precedence:
        // no release, cancellation or deadline can make this amount admissible.
        let intrinsic = bytes.checked_add(retained).ok_or(Error::Rejected(
            crate::RejectionReason::MemoryAccounting(
                crate::MemoryAccountingRejection::SymmetricBudgetCounterOverflow,
            ),
        ))?;
        self.check_request(intrinsic)?;
        self.wake.acquire(admission, || {
            if retained != 0 {
                self.check_request(intrinsic)?;
            }
            if let Some(route) = before()? {
                return Ok(Attempt::Acquired(ControlledReservation::Redirect(route)));
            }
            match self.try_reserve(bytes)? {
                Attempt::Acquired(credit) => {
                    Ok(Attempt::Acquired(ControlledReservation::Acquired(credit)))
                }
                Attempt::Occupied(reason) => {
                    // A caller may request one local maintenance pass even
                    // in Immediate mode. The callback chooses that route; it
                    // cannot retain a resource, reclaim owners or wait under
                    // Wake. A transient metadata try_lock follows the contract
                    // above and redirects immediately on contention.
                    if let Some(route) = occupied()? {
                        return Ok(Attempt::Acquired(ControlledReservation::Redirect(route)));
                    }
                    Ok(Attempt::Occupied(reason))
                }
            }
        })
    }

    fn reserve_admitted(
        self: &Arc<Self>,
        bytes: usize,
        admission: &crate::ResourceAdmission,
    ) -> Result<Credit> {
        // Releasing other owners cannot make this request fit the ceiling.
        self.check_request(bytes)?;
        self.wake.acquire(admission, || self.try_reserve(bytes))
    }
    fn try_reserve(self: &Arc<Self>, bytes: usize) -> Result<Attempt<Credit>> {
        self.check_request(bytes)?;
        if let Some(parent) = &self.parent {
            return match parent.try_reserve(bytes)? {
                Attempt::Acquired(mut credit) => {
                    self.used.fetch_add(bytes, Ordering::AcqRel);
                    // Transfer attribution, not admission: the parent counter
                    // was incremented exactly once by the successful attempt.
                    credit.budget = self.clone();
                    Ok(Attempt::Acquired(credit))
                }
                Attempt::Occupied(reason) => Ok(Attempt::Occupied(reason)),
            };
        }
        let mut current = self.used.load(Ordering::Acquire);
        loop {
            let next = current.checked_add(bytes).ok_or(Error::Rejected(
                crate::RejectionReason::MemoryAccounting(
                    crate::MemoryAccountingRejection::SymmetricBudgetCounterOverflow,
                ),
            ))?;
            if next > self.maximum {
                return Ok(Attempt::Occupied(crate::BusyReason::MemoryAccounting(
                    crate::MemoryAccountingBusy::SymmetricByteBudget,
                )));
            }
            match self.used.compare_exchange_weak(
                current,
                next,
                Ordering::AcqRel,
                Ordering::Acquire,
            ) {
                Ok(_) => break,
                Err(observed) => current = observed,
            }
        }
        Ok(Attempt::Acquired(Credit {
            last_footprint: AtomicU64::new(0),
            budget: self.clone(),
            bytes,
        }))
    }
}
pub(crate) struct Credit {
    // Deduplicate immutable aliases during the existing serialized footprint
    // walk. This is neither a resource counter nor a native identity.
    last_footprint: AtomicU64,
    budget: Arc<Budget>,
    bytes: usize,
}

/// Exact credits held by an immutable, consumed source during a transformation.
/// This is a read-only footprint: it neither reserves again nor returns credit.
/// Only private source owners may contribute; visit each owned credit once.
pub(crate) struct RetainedBytes {
    budget: Arc<Budget>,
    bytes: usize,
    // Present only inside measure's callback while its global leaf is held.
    // A completed footprint contains no lock and remains valid across waits.
    measurement: Option<u64>,
}
/// Visit exclusive storage already charged by a source owner. Collection
/// capacity is charged by its enclosing metadata credit, not a second time here.
/// There is deliberately no blanket Arc implementation: shared objects need
/// an explicit ownership argument before they can enter a consumed footprint.
/// Visitors only walk borrowed, immutable storage: no locking, admission, native
/// call, allocation, destruction, or recursive footprint measurement is allowed.
pub(crate) trait RetainedStorage {
    fn retain_credits(&self, retained: &mut RetainedBytes) -> Result<()>;
}
impl RetainedStorage for Credit {
    fn retain_credits(&self, retained: &mut RetainedBytes) -> Result<()> {
        retained.add_credit(self)
    }
}
impl<T: RetainedStorage> RetainedStorage for Option<T> {
    fn retain_credits(&self, retained: &mut RetainedBytes) -> Result<()> {
        if let Some(value) = self {
            value.retain_credits(retained)?;
        }
        Ok(())
    }
}
impl<T: RetainedStorage> RetainedStorage for Vec<T> {
    fn retain_credits(&self, retained: &mut RetainedBytes) -> Result<()> {
        for value in self {
            value.retain_credits(retained)?;
        }
        Ok(())
    }
}
impl<T: RetainedStorage> RetainedStorage for Box<T> {
    fn retain_credits(&self, retained: &mut RetainedBytes) -> Result<()> {
        self.as_ref().retain_credits(retained)
    }
}
impl RetainedBytes {
    /// Count an immutable source in one allocation-free walk. The sequence
    /// mutex serializes only these metadata walks, not native operations
    /// or resource waits. A new stamp makes an interrupted/failed walk harmless
    /// to later measurements; an identifier is never silently reused.
    pub(crate) fn measure(
        destination: &Arc<Budget>,
        visit: impl FnOnce(&mut Self) -> Result<()>,
    ) -> Result<Self> {
        let global = destination.global().clone();
        let mut sequence = global
            .footprint_sequence
            .lock()
            .map_err(|_| Error::Poisoned)?;
        *sequence = sequence.checked_add(1).ok_or(Error::Rejected(
            crate::RejectionReason::MemoryAccounting(
                crate::MemoryAccountingRejection::RetainedSourceObservationExhausted,
            ),
        ))?;
        let mut retained = Self {
            budget: global.clone(),
            bytes: 0,
            measurement: Some(*sequence),
        };
        visit(&mut retained)?;
        retained.measurement = None;
        Ok(retained)
    }

    pub(crate) fn add_credit(&mut self, credit: &Credit) -> Result<()> {
        if !self.budget.same_account(credit.budget()) {
            return Ok(());
        }
        // Domain comparison above precedes reading this domain-local stamp.
        // Immutable shared identities may be reached through several key roles.
        // No allocation, new lock, wait or mutable owner traversal occurs here.
        if self
            .measurement
            .is_some_and(|stamp| credit.last_footprint.load(Ordering::Relaxed) == stamp)
        {
            return Ok(());
        }

        let mut extra = credit.bytes;
        let mut observed = None;
        if let Some(storage) = &credit.budget._storage {
            let stamp = self
                .measurement
                .ok_or(Error::Rejected(crate::RejectionReason::MemoryAccounting(
                crate::MemoryAccountingRejection::PrivateAccountRequiresCompleteSourceMeasurement,
            )))?;
            if credit.budget.last_footprint.load(Ordering::Relaxed) != stamp {
                extra = extra.checked_add(storage.bytes).ok_or(Error::Rejected(
                    crate::RejectionReason::MemoryAccounting(
                        crate::MemoryAccountingRejection::RetainedSourceCreditOverflow,
                    ),
                ))?;
                observed = Some(stamp);
            }
        }
        self.bytes = self.bytes.checked_add(extra).ok_or(Error::Rejected(
            crate::RejectionReason::MemoryAccounting(
                crate::MemoryAccountingRejection::RetainedSourceCreditOverflow,
            ),
        ))?;
        if let Some(stamp) = self.measurement {
            credit.last_footprint.store(stamp, Ordering::Relaxed);
        }
        if let Some(stamp) = observed {
            credit.budget.last_footprint.store(stamp, Ordering::Relaxed);
        }
        Ok(())
    }

    /// Combine separately retained global leaves with one complete private
    /// continuation account. The visitor must exclude that account's credits:
    /// check_request already counts its payload, shell and accounting header.
    pub(crate) fn check_with_account(
        &self,
        destination: &Arc<Budget>,
        additional: usize,
    ) -> Result<()> {
        if !self.budget.same_account(destination) {
            return Err(Error::Rejected(crate::RejectionReason::MemoryAccounting(
                crate::MemoryAccountingRejection::RetainedSourceDestinationChanged,
            )));
        }
        let additional = self.bytes.checked_add(additional).ok_or(Error::Rejected(
            crate::RejectionReason::MemoryAccounting(
                crate::MemoryAccountingRejection::RetainedSourceCreditOverflow,
            ),
        ))?;
        destination.check_request(additional)
    }
    pub(crate) fn check(&self, destination: &Arc<Budget>, additional: usize) -> Result<()> {
        if !self.budget.same_account(destination) {
            return Err(Error::Rejected(crate::RejectionReason::MemoryAccounting(
                crate::MemoryAccountingRejection::RetainedSourceDestinationChanged,
            )));
        }
        let requested = self.bytes.checked_add(additional).ok_or(Error::Rejected(
            crate::RejectionReason::MemoryAccounting(
                crate::MemoryAccountingRejection::RetainedSourceCreditOverflow,
            ),
        ))?;
        self.budget.check_intrinsic(requested)
    }
}
impl Credit {
    /// Earmark already admitted global bytes for module-lifetime control
    /// storage. This credit is never visited as an operation's retained input:
    /// the global intrinsic floor accounts for it once for every operation.
    pub(crate) fn into_module_resident(self) -> Result<ResidentCredit> {
        if self.budget.parent.is_some() {
            return Err(Error::Rejected(crate::RejectionReason::MemoryAccounting(
                crate::MemoryAccountingRejection::ModuleStorageRequiresGlobalCredit,
            )));
        }
        let mut current = self.budget.resident.load(Ordering::Acquire);
        loop {
            let next = current.checked_add(self.bytes).ok_or(Error::Rejected(
                crate::RejectionReason::MemoryAccounting(
                    crate::MemoryAccountingRejection::ResidentByteAccountingOverflow,
                ),
            ))?;
            match self.budget.resident.compare_exchange_weak(
                current,
                next,
                Ordering::AcqRel,
                Ordering::Acquire,
            ) {
                Ok(_) => break,
                Err(observed) => current = observed,
            }
        }
        Ok(ResidentCredit(self))
    }

    /// Start a private continuation before splitting its initial aggregate.
    /// All descendants then retain their attribution through split, release,
    /// error, quarantine and transfer. No source data or native call is replayed.
    pub(crate) fn observation_budget(&mut self) -> Result<Arc<Budget>> {
        if self.budget.parent.is_some() {
            return Ok(self.budget.clone());
        }
        let bytes = self.bytes;
        let storage = self.split(Budget::observation_bytes())?;
        let budget = Arc::new(Budget {
            maximum: self.budget.maximum,
            used: AtomicUsize::new(bytes),
            resident: AtomicUsize::new(0),
            wake: self.budget.wake.clone(),
            parent: Some(self.budget.clone()),
            footprint_sequence: Mutex::new(0),
            last_footprint: AtomicU64::new(0),
            _storage: Some(storage),
        });
        self.budget = budget.clone();
        Ok(budget)
    }
    /// A consumed input cannot be released by another caller while its new
    /// operation waits. Reject a total that cannot fit even with no siblings.
    pub(crate) fn check_additional_capacity(&self, additional: usize) -> Result<()> {
        if self.budget.parent.is_some() {
            return self.budget.check_request(additional);
        }
        let total = self.bytes.checked_add(additional).ok_or(Error::Rejected(
            crate::RejectionReason::MemoryAccounting(
                crate::MemoryAccountingRejection::SymmetricCreditOverflow,
            ),
        ))?;
        self.budget.check_intrinsic(total)
    }

    /// Combine ownership of already admitted storage without acquiring bytes.
    pub(crate) fn merge(&mut self, mut other: Self) -> Result<()> {
        self.merge_retained(&mut other)
    }

    /// Guarded finalization borrows both credits: refusal must leave both
    /// owners intact until the enclosing access guard has been released.
    pub(crate) fn merge_retained(&mut self, other: &mut Self) -> Result<()> {
        if !self.budget.same_account(&other.budget) {
            return Err(Error::Rejected(crate::RejectionReason::MemoryAccounting(
                crate::MemoryAccountingRejection::ForeignByteCredit,
            )));
        }
        let total = self.bytes.checked_add(other.bytes).ok_or(Error::Rejected(
            crate::RejectionReason::MemoryAccounting(
                crate::MemoryAccountingRejection::SymmetricCreditOverflow,
            ),
        ))?;
        if !Arc::ptr_eq(&self.budget, &other.budget) {
            // The merged payload now belongs to this continuation. Its global
            // reservation never changes; move only its private attribution.
            if self.budget.parent.is_some() {
                self.budget.used.fetch_add(other.bytes, Ordering::AcqRel);
            }
            if other.budget.parent.is_some() {
                other.budget.used.fetch_sub(other.bytes, Ordering::AcqRel);
            }
        }
        self.bytes = total;
        other.bytes = 0;
        Ok(())
    }
    pub(crate) fn budget(&self) -> &Arc<Budget> {
        &self.budget
    }

    pub(crate) fn bytes(&self) -> usize {
        self.bytes
    }

    /// Transfer already admitted bytes to another owner without waiting or
    /// changing the shared counter. Each byte is released exactly once.
    pub(crate) fn split(&mut self, bytes: usize) -> Result<Self> {
        if bytes > self.bytes {
            return Err(Error::Rejected(crate::RejectionReason::MemoryAccounting(
                crate::MemoryAccountingRejection::CreditTransferExceedsOwnership,
            )));
        }
        self.bytes -= bytes;
        Ok(Self {
            last_footprint: AtomicU64::new(0),
            budget: self.budget.clone(),
            bytes,
        })
    }

    /// Partition a preparation's admitted credit atomically. Unlike successive
    /// splits, refusal leaves every byte with the original owner. There is no
    /// reservation, wait, allocation or notification at this transfer boundary.
    pub(crate) fn split_group<const N: usize>(&mut self, sizes: [usize; N]) -> Result<[Self; N]> {
        let total = sizes.iter().try_fold(0usize, |total, bytes| {
            total.checked_add(*bytes).ok_or(Error::Rejected(
                crate::RejectionReason::MemoryAccounting(
                    crate::MemoryAccountingRejection::CreditTransferExceedsOwnership,
                ),
            ))
        })?;
        if total > self.bytes {
            return Err(Error::Rejected(crate::RejectionReason::MemoryAccounting(
                crate::MemoryAccountingRejection::CreditTransferExceedsOwnership,
            )));
        }
        self.bytes -= total;
        Ok(sizes.map(|bytes| Self {
            last_footprint: AtomicU64::new(0),
            budget: self.budget.clone(),
            bytes,
        }))
    }

    // Only the owner that has already freed this storage may return its credit.
    pub(crate) fn release(&mut self, bytes: usize) {
        assert!(bytes <= self.bytes, "credit release exceeds ownership");
        self.bytes -= bytes;
        self.budget.release_bytes(bytes);
        if bytes != 0 {
            self.budget.wake.notify();
        }
    }

    pub(crate) fn release_all(&mut self) {
        self.release(self.bytes);
    }

    pub(crate) fn extend(&mut self, additional: usize) -> Result<()> {
        self.extend_admitted(additional, &crate::admission_wait::current())
    }

    // The allocator has already supplied this capacity. Do not wait/yield with
    // uncredited storage: on refusal the caller must discard that allocation.
    pub(crate) fn cover_allocated(&mut self, additional: usize) -> Result<()> {
        self.extend_admitted(additional, &crate::ResourceAdmission::Immediate)
    }

    fn extend_admitted(
        &mut self,
        additional: usize,
        admission: &crate::ResourceAdmission,
    ) -> Result<()> {
        if additional == 0 {
            return Ok(());
        }
        let total = self.bytes.checked_add(additional).ok_or(Error::Rejected(
            crate::RejectionReason::MemoryAccounting(
                crate::MemoryAccountingRejection::SymmetricCreditOverflow,
            ),
        ))?;
        self.budget.check_intrinsic(total)?;
        let mut extra = self.budget.reserve_admitted(additional, admission)?;
        // Transfer the newly reserved amount to this owner. Dropping the
        // emptied credit releases its Arc but must not release these bytes.
        self.bytes = total;
        extra.bytes = 0;
        Ok(())
    }
}
/// A nontransferable reservation for storage owned by the module itself.
/// Place it after that storage. Removing the floor precedes ordinary credit
/// release and its wake, so an observer never sees a released byte as resident.
pub(crate) struct ResidentCredit(Credit);

impl Drop for ResidentCredit {
    fn drop(&mut self) {
        self.0
            .budget
            .resident
            .fetch_sub(self.0.bytes, Ordering::AcqRel);
    }
}

impl Drop for Credit {
    fn drop(&mut self) {
        self.budget.release_bytes(self.bytes);
        if self.bytes != 0 {
            self.budget.wake.notify();
        }
    }
}
// Vec length covers its entire capacity; logical output length is independent.
// The byte allocation is released before its credit, even during unwinding.
pub(crate) struct Buffer {
    bytes: Vec<u8>,
    length: usize,
    capacity: usize,
    _credit: Credit,
}
impl RetainedStorage for Buffer {
    fn retain_credits(&self, retained: &mut RetainedBytes) -> Result<()> {
        self.retain_credit(retained)
    }
}
pub(crate) enum PreparedBuffer<T> {
    Ready(Buffer),
    Redirect(T),
}

/// Empty storage in an unpublished aggregate candidate. Its caller holds the
/// aggregate credit and checks all real capacities before binding any child.
/// It has no byte or pointer accessor, so it cannot be dispatched or populated
/// before its exact credit has been transferred. Drop erases even on unwind.
pub(crate) struct UnboundBuffer {
    bytes: Vec<u8>,
    logical: usize,
}
impl UnboundBuffer {
    pub(crate) fn allocate(size: usize) -> Result<Self> {
        let mut bytes = Vec::new();
        bytes.try_reserve_exact(size).map_err(|_| {
            Error::Rejected(crate::RejectionReason::MemoryAccounting(
                crate::MemoryAccountingRejection::SymmetricAllocation,
            ))
        })?;
        bytes.resize(bytes.capacity(), 0);
        Ok(Self {
            bytes,
            logical: size,
        })
    }
    pub(crate) fn allocated(&self) -> usize {
        self.bytes.capacity()
    }
    pub(crate) fn bind(mut self, prepaid: &mut Credit) -> Result<Buffer> {
        let credit = prepaid.split(self.allocated())?;
        Ok(Buffer {
            bytes: std::mem::take(&mut self.bytes),
            length: self.logical,
            capacity: self.logical,
            _credit: credit,
        })
    }
}
impl Drop for UnboundBuffer {
    fn drop(&mut self) {
        self.bytes.as_mut_slice().zeroize();
    }
}
impl Buffer {
    pub(crate) fn retain_credit(&self, retained: &mut RetainedBytes) -> Result<()> {
        retained.add_credit(&self._credit)
    }
    /// Prepare one byte owner together with its containing metadata. Callers
    /// must release coordination guards first; no partial credit survives a
    /// retry caused by the allocator's actual capacity.
    pub(crate) fn with_metadata(
        budget: &Arc<Budget>,
        size: usize,
        metadata: usize,
        before: impl FnMut() -> Result<()>,
    ) -> Result<(Self, Credit)> {
        Self::with_metadata_retained(budget, size, metadata, None, before)
    }

    pub(crate) fn with_metadata_retained(
        budget: &Arc<Budget>,
        size: usize,
        metadata: usize,
        retained: Option<&RetainedBytes>,
        mut before: impl FnMut() -> Result<()>,
    ) -> Result<(Self, Credit)> {
        let admission = crate::admission_wait::current();
        let mut required = metadata.checked_add(size).ok_or(Error::Rejected(
            crate::RejectionReason::MemoryAccounting(
                crate::MemoryAccountingRejection::SymmetricAllocationAccounting,
            ),
        ))?;
        loop {
            if let Some(retained) = retained {
                retained.check(budget, required)?;
            }
            let mut credit = match budget.reserve_controlled::<std::convert::Infallible>(
                required,
                &admission,
                || {
                    before()?;
                    Ok(None)
                },
                || Ok(None),
            )? {
                ControlledReservation::Acquired(credit) => credit,
                ControlledReservation::Redirect(never) => match never {},
            };
            let bytes = UnboundBuffer::allocate(size)?;
            let actual = metadata
                .checked_add(bytes.allocated())
                .ok_or(Error::Rejected(crate::RejectionReason::MemoryAccounting(
                    crate::MemoryAccountingRejection::SymmetricAllocationAccounting,
                )))?;
            if actual > required {
                drop(bytes);
                drop(credit);
                required = actual;
                continue;
            }
            credit.release(required - actual);
            let bytes = bytes.bind(&mut credit)?;
            return Ok((bytes, credit));
        }
    }

    /// Caller-owned global storage is part of every intrinsic capacity check,
    /// including allocator-capacity replans. It is retained, not charged twice.
    pub(crate) fn new_controlled_retaining<T>(
        budget: &Arc<Budget>,
        size: usize,
        retained: usize,
        admission: &crate::ResourceAdmission,
        mut before: impl FnMut() -> Result<Option<T>>,
    ) -> Result<PreparedBuffer<T>> {
        let mut required = size;
        loop {
            let mut credit = match budget.reserve_controlled_retaining(
                required,
                retained,
                admission,
                &mut before,
                || Ok(None),
            )? {
                ControlledReservation::Acquired(credit) => credit,
                ControlledReservation::Redirect(route) => {
                    return Ok(PreparedBuffer::Redirect(route))
                }
            };
            let mut bytes = Vec::new();
            bytes.try_reserve_exact(size).map_err(|_| {
                Error::Rejected(crate::RejectionReason::MemoryAccounting(
                    crate::MemoryAccountingRejection::SymmetricAllocation,
                ))
            })?;
            let allocated = bytes.capacity();
            if allocated > required {
                drop(bytes);
                drop(credit);
                required = allocated;
                continue;
            }
            credit.release(required - allocated);
            bytes.resize(allocated, 0);
            return Ok(PreparedBuffer::Ready(Self {
                bytes,
                length: size,
                capacity: size,
                _credit: credit,
            }));
        }
    }
    pub(crate) fn new_prepaid(prepaid: &mut Credit, size: usize) -> Result<Self> {
        let mut credit = prepaid.split(size)?;
        let mut bytes = Vec::new();
        bytes.try_reserve_exact(size).map_err(|_| {
            Error::Rejected(crate::RejectionReason::MemoryAccounting(
                crate::MemoryAccountingRejection::SymmetricAllocation,
            ))
        })?;
        let additional = bytes.capacity().checked_sub(size).ok_or(Error::Rejected(
            crate::RejectionReason::MemoryAccounting(
                crate::MemoryAccountingRejection::SymmetricAllocatorCapacity,
            ),
        ))?;
        credit.cover_allocated(additional)?;
        bytes.resize(bytes.capacity(), 0);
        Ok(Self {
            bytes,
            length: size,
            capacity: size,
            _credit: credit,
        })
    }
    /// Transfer storage and its existing reservation without allocating. The
    /// empty source remains a valid owner and cannot release the transferred credit.
    pub(crate) fn take(&mut self) -> Self {
        let credit = Credit {
            last_footprint: AtomicU64::new(0),
            budget: Arc::clone(&self._credit.budget),
            bytes: std::mem::take(&mut self._credit.bytes),
        };
        Self {
            bytes: std::mem::take(&mut self.bytes),
            length: std::mem::take(&mut self.length),
            capacity: std::mem::take(&mut self.capacity),
            _credit: credit,
        }
    }
    pub(crate) fn capacity(&self) -> usize {
        self.capacity
    }
    pub(crate) fn as_mut(&mut self) -> &mut [u8] {
        &mut self.bytes[..self.capacity]
    }
    pub(crate) fn as_slice(&self) -> &[u8] {
        &self.bytes[..self.length]
    }
    /// Initialized backing bytes, including storage beyond the published length.
    /// Used for private continuation copies after native memory return. This is
    /// not a result accessor: only `as_slice` identifies bytes ready for delivery.
    pub(crate) fn initialized_storage(&self) -> &[u8] {
        &self.bytes[..self.capacity]
    }
    pub(crate) fn set_length(&mut self, n: usize) -> Result<()> {
        if n > self.capacity {
            return Err(Error::Rejected(crate::RejectionReason::MemoryAccounting(
                crate::MemoryAccountingRejection::SymmetricOutputLength,
            )));
        }
        self.length = n;
        Ok(())
    }
}
impl Drop for Buffer {
    fn drop(&mut self) {
        self.bytes.as_mut_slice().zeroize();
    }
}
