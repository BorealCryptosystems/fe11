// SPDX-License-Identifier: Apache-2.0
//! Prepare and admit per-object activity while tracking reader storage.
//! Reusable owner slots and newly allocated capacity are separate admission alternatives.

use super::*;

impl ActivityState {
    /// Attribution capacity can become reusable without returning its credit.
    /// Capture the budget's notification domain while this state is held, but
    /// notify only after releasing it. Cloning the Arc allocates no storage.
    pub(super) fn reader_storage_wake(&self) -> Option<Arc<Wake>> {
        self.allocation_credit
            .as_ref()
            .map(|credit| credit.budget().admission_wake())
    }

    /// Readers may coexist with a transient Init writer only when all of them
    /// belong to the possessed, quiescent session. Never borrow a writer.
    pub(super) fn operation_writer_available(&self, borrowed_uid: Option<u64>) -> Result<bool> {
        if self.poisoned {
            return Err(Error::Poisoned);
        }
        if self.writer {
            return Ok(false);
        }
        let mut allowed = 0usize;
        for owner in &self.owned {
            if Some(owner.uid) == borrowed_uid {
                allowed = allowed.checked_add(owner.readers).ok_or(Error::Rejected(
                    crate::RejectionReason::ReferenceRegistry(
                        crate::ReferenceRegistryRejection::ObjectActivityCount,
                    ),
                ))?;
            }
        }
        Ok(self.readers == allowed)
    }
}

impl Activity {
    pub(crate) fn bind_context_wake(&self, wake: &Arc<Wake>) -> Result<()> {
        let expected = Arc::downgrade(wake);
        let mut state = self.0.lock().map_err(|_| Error::Poisoned)?;
        if state.poisoned {
            return Err(Error::Poisoned);
        }
        match &state.context_wake {
            Some(current) if !current.ptr_eq(&expected) => {
                Err(Error::Rejected(crate::RejectionReason::ReferenceRegistry(
                    crate::ReferenceRegistryRejection::ActivityContextNotifierMismatch,
                )))
            }
            Some(_) => Ok(()),
            None => {
                state.context_wake = Some(expected);
                Ok(())
            }
        }
    }

    pub(crate) fn allocation_bytes(metadata: usize) -> Result<usize> {
        let bytes = std::mem::size_of::<Self>()
            .checked_add(std::mem::size_of::<Mutex<ActivityState>>())
            .and_then(|n| n.checked_add(std::mem::size_of::<Wake>()))
            // Three Arc allocations: Activity, state, and wake.
            .and_then(|n| n.checked_add(6 * std::mem::size_of::<usize>()))
            .and_then(|n| n.checked_add(metadata))
            .ok_or(Error::Rejected(crate::RejectionReason::ReferenceRegistry(
                crate::ReferenceRegistryRejection::ActivityStorageAccounting,
            )))?;
        Ok(bytes)
    }

    pub(crate) fn from_credit(credit: crate::symmetric::memory::Credit) -> Self {
        Self(
            Arc::new(Mutex::new(ActivityState {
                allocation_credit: Some(credit),
                ..Default::default()
            })),
            Arc::new(Wake::default()),
        )
    }

    /// Prepare attribution storage without holding a native or activity guard.
    /// No read permission is granted here. Final possession acquires only a
    /// pre-existing slot and can therefore be strictly nonblocking.
    pub(crate) fn prepare_reader(self: &Arc<Self>, uid: u64) -> Result<PreparedReader> {
        self.prepare_reader_checked(uid, &crate::admission_wait::current(), || Ok(()))
    }

    /// The context predicate must use only pure/atomic observations: resource
    /// admission may invoke it while holding its Wake, never ActivityState.
    pub(crate) fn prepare_reader_checked(
        self: &Arc<Self>,
        uid: u64,
        admission: &crate::ResourceAdmission,
        before: impl FnMut() -> Result<()>,
    ) -> Result<PreparedReader> {
        self.prepare_reader_retaining(uid, admission, None, before)
    }

    /// A consumed archive remains resident even while attribution is prepared.
    /// Include it in every growth attempt, before waiting for unrelated owners.
    pub(crate) fn prepare_reader_retaining(
        self: &Arc<Self>,
        uid: u64,
        admission: &crate::ResourceAdmission,
        retained: Option<&crate::symmetric::memory::RetainedBytes>,
        before: impl FnMut() -> Result<()>,
    ) -> Result<PreparedReader> {
        admission.try_once(|| self.prepare_reader_storage(uid, admission, retained, before))
    }

    /// A budget predicate may inspect metadata but must never wait for this
    /// mutex. Recompute outside Wake on contention or when the planned table
    /// is no longer needed/current. Only the outer loop grants a preparation.
    pub(super) fn reader_storage_recheck(&self, uid: u64, count: usize) -> Result<Option<()>> {
        let state = match self.0.try_lock() {
            Ok(state) => state,
            Err(TryLockError::WouldBlock) => return Ok(Some(())),
            Err(TryLockError::Poisoned(_)) => return Err(Error::Poisoned),
        };
        if state.poisoned {
            return Err(Error::Poisoned);
        }
        let changed = state.owned.len() < state.owned.capacity()
            || state.owned.iter().any(|owner| owner.uid == uid)
            || state.owned.len().checked_add(1) != Some(count);
        Ok(changed.then_some(()))
    }

    pub(super) fn prepare_reader_storage(
        self: &Arc<Self>,
        uid: u64,
        admission: &crate::ResourceAdmission,
        retained: Option<&crate::symmetric::memory::RetainedBytes>,
        mut before: impl FnMut() -> Result<()>,
    ) -> Result<PreparedReader> {
        if uid == 0 {
            return Err(Error::Rejected(crate::RejectionReason::ReferenceRegistry(
                crate::ReferenceRegistryRejection::ObjectActivityOwner,
            )));
        }
        'prepare: loop {
            before()?;
            let (count, budget) = {
                let mut state = self.0.lock().map_err(|_| Error::Poisoned)?;
                if state.poisoned {
                    return Err(Error::Poisoned);
                }
                if let Some(owner) = state.owned.iter_mut().find(|owner| owner.uid == uid) {
                    owner.preparations = owner.preparations.checked_add(1).ok_or(
                        Error::Rejected(crate::RejectionReason::ReferenceRegistry(
                            crate::ReferenceRegistryRejection::ObjectActivityCount,
                        )),
                    )?;
                    return Ok(PreparedReader {
                        activity: self.clone(),
                        uid,
                    });
                }
                if state.owned.len() < state.owned.capacity() {
                    state.owned.push(ReaderOwner {
                        uid,
                        readers: 0,
                        transferred_writers: 0,
                        preparations: 1,
                    });
                    let wake = state.reader_storage_wake();
                    drop(state);
                    if let Some(wake) = wake {
                        wake.notify();
                    }
                    return Ok(PreparedReader {
                        activity: self.clone(),
                        uid,
                    });
                }
                (
                    state.owned.len().checked_add(1).ok_or(Error::Rejected(
                        crate::RejectionReason::ReferenceRegistry(
                            crate::ReferenceRegistryRejection::ObjectActivityCount,
                        ),
                    ))?,
                    state
                        .allocation_credit
                        .as_ref()
                        .map(|credit| credit.budget().clone()),
                )
            };
            let mut required = count
                .checked_mul(std::mem::size_of::<ReaderOwner>())
                .ok_or(Error::Rejected(crate::RejectionReason::ReferenceRegistry(
                    crate::ReferenceRegistryRejection::ActivityOwnerStorageAccounting,
                )))?;
            // Keep storage before its credit in one owner: lock failure and
            // unwind must free the allocation before making capacity reusable.
            let mut candidate = loop {
                let mut credit = if let Some(budget) = &budget {
                    if let Some(source) = retained {
                        source.check(budget, required)?;
                    }
                    match budget.reserve_controlled(
                        required,
                        admission,
                        || {
                            before()?;
                            self.reader_storage_recheck(uid, count)
                        },
                        || Ok(None),
                    )? {
                        crate::symmetric::memory::ControlledReservation::Acquired(credit) => {
                            Some(credit)
                        }
                        crate::symmetric::memory::ControlledReservation::Redirect(()) => {
                            continue 'prepare;
                        }
                    }
                } else {
                    None
                };
                let mut candidate = Vec::<ReaderOwner>::new();
                candidate.try_reserve_exact(count).map_err(|_| {
                    Error::Rejected(crate::RejectionReason::ReferenceRegistry(
                        crate::ReferenceRegistryRejection::ObjectActivityAllocation,
                    ))
                })?;
                let actual = candidate
                    .capacity()
                    .checked_mul(std::mem::size_of::<ReaderOwner>())
                    .ok_or(Error::Rejected(crate::RejectionReason::ReferenceRegistry(
                        crate::ReferenceRegistryRejection::ActivityOwnerStorageAccounting,
                    )))?;
                if actual > required {
                    drop(candidate);
                    drop(credit);
                    required = actual;
                    continue;
                }
                if let Some(credit) = &mut credit {
                    credit.release(required - actual);
                }
                break (candidate, credit);
            };

            let mut state = self.0.lock().map_err(|_| Error::Poisoned)?;
            if state.poisoned {
                return Err(Error::Poisoned);
            }
            if state.owned.iter().any(|owner| owner.uid == uid)
                || state.owned.len() >= candidate.0.capacity()
            {
                drop(state);
                drop(candidate);
                continue;
            }
            candidate.0.extend_from_slice(&state.owned);
            candidate.0.push(ReaderOwner {
                uid,
                readers: 0,
                transferred_writers: 0,
                preparations: 1,
            });
            let old = (
                std::mem::replace(&mut state.owned, candidate.0),
                std::mem::replace(&mut state.owned_credit, candidate.1),
            );
            let wake = state.reader_storage_wake();
            drop(state);
            // Free replaced storage before credit; notification never occurs
            // under the short Activity mutex or an admission Wake predicate.
            drop(old);
            if let Some(wake) = wake {
                wake.notify();
            }
            return Ok(PreparedReader {
                activity: self.clone(),
                uid,
            });
        }
    }

    // The closing path supplies only abandoned, synchronous, natively quiescent
    // owners, snapshotted under the slot writer. Never borrow foreign writers.
    pub(crate) fn write_for_close_with_abandoned(
        self: &Arc<Self>,
        uid: u64,
        abandoned: &[u64],
    ) -> Result<WritePermit> {
        if uid == 0 {
            return Err(Error::Rejected(crate::RejectionReason::ReferenceRegistry(
                crate::ReferenceRegistryRejection::ObjectActivityOwner,
            )));
        }
        self.acquire_write(Some(uid), abandoned)
    }

    pub(crate) fn write_for_operation_admitted(
        self: &Arc<Self>,
        uid: u64,
        admission: &crate::ResourceAdmission,
    ) -> Result<WritePermit> {
        if uid == 0 {
            return Err(Error::Rejected(crate::RejectionReason::ReferenceRegistry(
                crate::ReferenceRegistryRejection::ObjectActivityOwner,
            )));
        }
        self.acquire_operation_writer(uid, admission, None)
    }

    /// The proof cannot outlive the session guard that excludes every native
    /// continuation of the existing operation. Foreign/anonymous readers and
    /// every writer remain excluded; the original reader permits stay owned.
    pub(crate) fn write_for_init_admitted(
        self: &Arc<Self>,
        proof: &crate::advanced::InitReaderBorrow<'_>,
        admission: &crate::ResourceAdmission,
    ) -> Result<WritePermit> {
        self.acquire_operation_writer(proof.uid(), admission, Some(proof.uid()))
    }

    pub(super) fn acquire_operation_writer(
        self: &Arc<Self>,
        uid: u64,
        admission: &crate::ResourceAdmission,
        borrowed_uid: Option<u64>,
    ) -> Result<WritePermit> {
        self.1.acquire(admission, || {
            let mut state = self.0.lock().map_err(|_| Error::Poisoned)?;
            if !state.operation_writer_available(borrowed_uid)? {
                return Ok(Attempt::Occupied(crate::BusyReason::ObjectMutation(
                    crate::ObjectMutationBusy::ObjectActivity,
                )));
            }
            state.writer = true;
            state.base_writer = true;
            state.owned_writer = Some((uid, 1));
            Ok(Attempt::Acquired(WritePermit {
                activity: Arc::clone(self),
                was_panicking: std::thread::panicking(),
            }))
        })
    }

    pub(crate) fn wait_operation_writer_checked(
        &self,
        admission: &crate::ResourceAdmission,
        before: impl FnMut() -> Result<()>,
    ) -> Result<()> {
        self.wait_operation_writer_on(&self.1, admission, None, before)
    }

    /// Observe both context invalidation and Activity release on one Wake. The
    /// context publisher and every reader/writer release notify this domain.
    /// Binding happens before the first predicate check, so no transition can
    /// be lost between checking availability and sleeping.
    pub(crate) fn wait_operation_writer_in_context(
        &self,
        wake: &Arc<Wake>,
        admission: &crate::ResourceAdmission,
        before: impl FnMut() -> Result<()>,
    ) -> Result<()> {
        self.bind_context_wake(wake)?;
        self.wait_operation_writer_on(wake, admission, None, before)
    }

    /// Availability only: no permission is acquired or lent while sleeping.
    /// The caller revalidates the Init category and obtains a new proof on retry.
    pub(crate) fn wait_init_writer_available(
        &self,
        wake: Option<&Arc<Wake>>,
        admission: &crate::ResourceAdmission,
        borrowed_uid: Option<u64>,
        before: impl FnMut() -> Result<()>,
    ) -> Result<()> {
        if let Some(wake) = wake {
            self.bind_context_wake(wake)?;
        }
        self.wait_operation_writer_on(wake.unwrap_or(&self.1), admission, borrowed_uid, before)
    }

    pub(super) fn wait_operation_writer_on(
        &self,
        wake: &Arc<Wake>,
        admission: &crate::ResourceAdmission,
        borrowed_uid: Option<u64>,
        mut before: impl FnMut() -> Result<()>,
    ) -> Result<()> {
        wake.acquire(admission, || {
            before()?;
            let state = self.0.lock().map_err(|_| Error::Poisoned)?;
            if !state.operation_writer_available(borrowed_uid)? {
                return Ok(Attempt::Occupied(crate::BusyReason::ObjectMutation(
                    crate::ObjectMutationBusy::ObjectActivity,
                )));
            }
            Ok(Attempt::Acquired(()))
        })
    }

    // The collective close's anchored batch is the only authority for
    // borrowing owned activity. Anonymous or foreign owners stay excluded.
    pub(crate) fn try_write_for_recovery(
        self: &Arc<Self>,
        batch: &crate::session_budget::RecoveryBatch,
        admission: &crate::ResourceAdmission,
    ) -> Result<WritePermit> {
        admission.try_once(|| {
            self.acquire_write_owners(
                &crate::ResourceAdmission::Immediate,
                |uid| batch.owns_uid(uid),
                |uid| batch.owns_uid(uid),
            )
        })
    }

    /// Called only after releasing the slot writer and all partial close
    /// reservations. The anchored batch supplies ownership, never a raw UID
    /// supplied by the caller. The transient permit is not a close authority:
    /// the entire batch must be checked again under the next slot writer.
    pub(crate) fn wait_for_recovery(
        self: &Arc<Self>,
        batch: &crate::session_budget::RecoveryBatch,
        admission: &crate::ResourceAdmission,
    ) -> Result<()> {
        self.acquire_write_owners(
            admission,
            |uid| batch.owns_uid(uid),
            |uid| batch.owns_uid(uid),
        )
        .map(drop)
    }

    pub(super) fn acquire_write(
        self: &Arc<Self>,
        closing: Option<u64>,
        abandoned: &[u64],
    ) -> Result<WritePermit> {
        let admission = if closing.is_some() {
            crate::ResourceAdmission::Immediate
        } else {
            crate::admission_wait::current()
        };
        self.acquire_write_owners(
            &admission,
            |uid| closing == Some(uid) || abandoned.contains(&uid),
            |uid| closing == Some(uid),
        )
    }

    pub(super) fn acquire_write_owners(
        self: &Arc<Self>,
        admission: &crate::ResourceAdmission,
        reader_allowed: impl Fn(u64) -> bool,
        writer_allowed: impl Fn(u64) -> bool,
    ) -> Result<WritePermit> {
        self.1.acquire(admission, || {
            let mut state = self.0.lock().map_err(|_| Error::Poisoned)?;
            if state.poisoned {
                return Err(Error::Poisoned);
            }
            let mut allowed = 0usize;
            for owner in &state.owned {
                if reader_allowed(owner.uid) {
                    allowed = allowed.checked_add(owner.readers).ok_or(Error::Rejected(
                        crate::RejectionReason::ReferenceRegistry(
                            crate::ReferenceRegistryRejection::ObjectActivityCount,
                        ),
                    ))?;
                }
            }
            // A competing Init can retain a writer alongside readers borrowed
            // from the same session. Cleanup must borrow both, but only when
            // every reader is covered by its closing/recovery ownership proof.
            // Unattributed or foreign readers still exclude the close writer.
            if state.readers != allowed {
                return Ok(Attempt::Occupied(crate::BusyReason::ObjectMutation(
                    crate::ObjectMutationBusy::ObjectActivity,
                )));
            }
            if state.writer {
                // A close may borrow only permissions wholly attributable to
                // that closing session. A captured transfer to another session
                // keeps the key protected even after its original writer drops.
                if state
                    .owned
                    .iter()
                    .any(|owner| owner.transferred_writers != 0 && !writer_allowed(owner.uid))
                {
                    return Ok(Attempt::Occupied(crate::BusyReason::ObjectMutation(
                        crate::ObjectMutationBusy::ObjectActivity,
                    )));
                }
                if !state.base_writer {
                    let owner = state
                        .owned
                        .iter()
                        .find(|owner| owner.transferred_writers != 0)
                        .ok_or(Error::Rejected(crate::RejectionReason::ReferenceRegistry(
                            crate::ReferenceRegistryRejection::TransferredWriterAttribution,
                        )))?
                        .uid;
                    if !writer_allowed(owner) {
                        return Ok(Attempt::Occupied(crate::BusyReason::ObjectMutation(
                            crate::ObjectMutationBusy::ObjectActivity,
                        )));
                    }
                    state.base_writer = true;
                    state.owned_writer = Some((owner, 0));
                }
                match state.owned_writer {
                    Some((owner, count)) if writer_allowed(owner) => {
                        let count = count.checked_add(1).ok_or(Error::Rejected(
                            crate::RejectionReason::ReferenceRegistry(
                                crate::ReferenceRegistryRejection::ObjectWriterCount,
                            ),
                        ))?;
                        state.owned_writer = Some((owner, count));
                    }
                    _ => {
                        return Ok(Attempt::Occupied(crate::BusyReason::ObjectMutation(
                            crate::ObjectMutationBusy::ObjectActivity,
                        )))
                    }
                }
            } else {
                state.writer = true;
                state.base_writer = true;
            }
            Ok(Attempt::Acquired(WritePermit {
                activity: Arc::clone(self),
                was_panicking: std::thread::panicking(),
            }))
        })
    }
}
