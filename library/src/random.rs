// SPDX-License-Identifier: Apache-2.0
use crate::symmetric::memory::{Budget, Credit};
use crate::{bounds, native::frame::NativeFrame, Error, Module, Result, Session};
use fe11_sys::*;
use std::{mem::size_of, sync::Arc};
use zeroize::Zeroize;

#[doc = include_str!("../docs/api/random/SecretBytes.md")]
pub struct SecretBytes {
    bytes: Vec<u8>,
    length: usize,
    credit: Option<Credit>,
}
impl crate::symmetric::memory::RetainedStorage for SecretBytes {
    fn retain_credits(&self, retained: &mut crate::symmetric::memory::RetainedBytes) -> Result<()> {
        self.credit.retain_credits(retained)
    }
}
impl SecretBytes {
    /// Allocate zeros for the requested length, without an additional policy ceiling.
    /// Allocation is fallible. Empty data is allowed. The allocator may retain
    /// extra capacity; all owned capacity is initialized and erased on release.
    pub fn new(length: usize) -> Result<Self> {
        let mut bytes = Vec::new();
        bytes.try_reserve_exact(length).map_err(|_| {
            Error::Rejected(crate::RejectionReason::RandomGeneration(
                crate::RandomGenerationRejection::SecretBufferAllocation,
            ))
        })?;
        bytes.resize(bytes.capacity(), 0);
        Ok(Self {
            bytes,
            length,
            credit: None,
        })
    }

    pub(crate) fn bind_prepaid(mut self, prepaid: &mut Credit) -> Result<Self> {
        if self.credit.is_some() {
            return Err(Error::Rejected(crate::RejectionReason::RandomGeneration(
                crate::RandomGenerationRejection::SecretBufferAlreadyCredited,
            )));
        }
        let amount = self
            .allocated_bytes()
            .checked_add(size_of::<Self>())
            .ok_or(Error::Rejected(crate::RejectionReason::RandomGeneration(
                crate::RandomGenerationRejection::SecretBufferAccounting,
            )))?;
        self.credit = Some(prepaid.split(amount)?);
        Ok(self)
    }
    /// The enclosing frame already charges the inline SecretBytes header.
    /// Only its independent allocation follows the completed output here.
    pub(crate) fn bind_prepaid_payload(mut self, prepaid: &mut Credit) -> Result<Self> {
        if self.credit.is_some() {
            return Err(Error::Rejected(crate::RejectionReason::RandomGeneration(
                crate::RandomGenerationRejection::SecretBufferAlreadyCredited,
            )));
        }
        self.credit = Some(prepaid.split(self.allocated_bytes())?);
        Ok(self)
    }
    fn credited_to(&self, budget: &Arc<Budget>) -> bool {
        self.credit
            .as_ref()
            .is_some_and(|credit| credit.budget().same_account(budget))
    }
    /// Borrow initialized bytes. The caller must not log secret values.
    pub fn as_slice(&self) -> &[u8] {
        &self.bytes[..self.length]
    }
    /// Populate the stable allocation without an intermediate unprotected copy.
    pub fn as_mut_slice(&mut self) -> &mut [u8] {
        &mut self.bytes[..self.length]
    }
    /// Logical byte count.
    pub fn len(&self) -> usize {
        self.length
    }
    /// Whether no data is present.
    pub fn is_empty(&self) -> bool {
        self.length == 0
    }
    /// Actual initialized allocation charged by native call owners.
    pub(crate) fn allocated_bytes(&self) -> usize {
        self.bytes.capacity()
    }
    // Native readers may return fewer bytes than the supplied capacity. Erase
    // the discarded initialized tail immediately, not merely when the owner drops.
    pub(crate) fn truncate(&mut self, length: usize) -> Result<()> {
        if length > self.length {
            return Err(Error::Rejected(crate::RejectionReason::RandomGeneration(
                crate::RandomGenerationRejection::SecretLengthExceedsCapacity,
            )));
        }
        self.bytes[length..].zeroize();
        self.length = length;
        Ok(())
    }
    fn erase(&mut self) {
        self.bytes.as_mut_slice().zeroize();
    }
}
impl Drop for SecretBytes {
    fn drop(&mut self) {
        self.erase();
    }
}

// The output keeps its payload/header credit after success. The separate frame
// credit stays with the call owner on uncertain completion, and is released
// only when that owner leaves; it never burdens the returned output.
struct RandomOutput {
    output: SecretBytes,
    _frame_credit: Credit,
}

// Keep publication diagnostics outside the native-addressable frame. The
// public root retains their charge even after that frame yields its output.
struct PreparedRandom {
    output: RandomOutput,
    diagnostic: crate::error::PreparedCompletionCell,
}

impl RandomOutput {
    fn prepare(
        session: &Session,
        length: usize,
        progress: &crate::session::AdmissionProgress,
    ) -> Result<PreparedRandom> {
        // CallData and SessionFrame are distinct stable allocations. Charge
        // both inline payloads together with the output's owned byte capacity.
        let fixed = size_of::<Self>()
            .checked_add(crate::native::frame::SessionFrame::<Self>::allocation_bytes())
            .and_then(|n| n.checked_add(crate::error::CompletionStorage::allocation_bytes()))
            .ok_or(Error::Rejected(crate::RejectionReason::RandomGeneration(
                crate::RandomGenerationRejection::RandomOutputAccounting,
            )))?;
        let mut required = length.checked_add(fixed).ok_or(Error::Rejected(
            crate::RejectionReason::RandomGeneration(
                crate::RandomGenerationRejection::RandomOutputAccounting,
            ),
        ))?;
        loop {
            let mut prepaid =
                crate::advanced::reserve_preparation_with_progress(session, required, progress)?;
            let output = SecretBytes::new(length)?;
            let actual = output
                .allocated_bytes()
                .checked_add(fixed)
                .ok_or(Error::Rejected(crate::RejectionReason::RandomGeneration(
                    crate::RandomGenerationRejection::RandomOutputAccounting,
                )))?;
            if actual > required {
                // Never wait for allocator excess while retaining the partial
                // candidate or its credit. No session is possessed here.
                drop(output);
                drop(prepaid);
                required = actual;
                continue;
            }
            prepaid.release(required - actual);
            let output = output.bind_prepaid(&mut prepaid)?;
            let diagnostic = crate::error::PreparedCompletionCell::prepare(&mut prepaid)?;
            return Ok(PreparedRandom {
                output: Self {
                    output,
                    _frame_credit: prepaid,
                },
                diagnostic,
            });
        }
    }
}

impl Session {
    /// Generate bytes on the selected provider, with no OS fallback or retry.
    /// If native completion is unproven, retain output and session ownership.
    /// The module's byte credit remains attached to the returned SecretBytes
    /// until it is dropped; retaining outputs therefore retains their credit.
    pub fn generate_random(&self, length: usize) -> Result<SecretBytes> {
        bounds::ck_length(length)?;
        let progress = crate::session::AdmissionProgress::default();
        let (prepared, access) = self.prepare_with_roles([], false, &progress, || {
            RandomOutput::prepare(self, length, &progress)
        })?;
        self.generate_random_prepared(&access, prepared.output, prepared.diagnostic.cell())
    }

    // Retain the exact outer access owner without another session lock or
    // native call. Only completed output can leave this frame and its credit.
    fn generate_random_prepared(
        &self,
        access: &crate::session::SessionAccess<'_>,
        output: RandomOutput,
        diagnostic: &crate::error::CompletionCell,
    ) -> Result<SecretBytes> {
        let native_length = bounds::ck_length(output.output.len())?;
        let handle = self.entry(access)?.handle;
        let call = access.native.table.C_GenerateRandom.ok_or(Error::Rejected(
            crate::RejectionReason::RandomGeneration(
                crate::RandomGenerationRejection::CGenerateRandomUnavailable,
            ),
        ))?;
        let mut frame = NativeFrame::session(access.clone(), output)?;
        {
            let (returned, body) = frame.session_parts();
            let s = &body.access;
            s.native.record("C_GenerateRandom")?;
            let sequence =
                crate::session::Sequence::for_frame_prepared(s, self, returned, diagnostic);
            // SAFETY: the stable output, session guards, referents and image
            // stay owned on any uncompleted return or classification unwind.
            let rv = returned.observe(
                unsafe {
                    call(
                        handle,
                        body.data.output.as_mut_slice().as_mut_ptr(),
                        native_length,
                    )
                },
                &s.native,
            );
            // RNG has no Init/Final operation. Ordinary refusals release the
            // frame without withdrawing unrelated sessions or invoking a retry.
            sequence.check(rv, "C_GenerateRandom", true)?;
        }
        let completed = frame.into_inner()?;

        diagnostic.finish(
            "C_GenerateRandom",
            self.public_result(&completed.access, Ok(completed.data.into_inner().output)),
        )
    }

    /// Explicit provider seeding. Unsupported seeding stays a native error.
    /// Consumed seed storage is erased on ordinary release; an uncompleted
    /// native call keeps its frame and session ownership until safe termination.
    pub fn seed_random(&self, seed: SecretBytes) -> Result<()> {
        struct SeedCall {
            seed: SecretBytes,
            // Freed after the seed, and retained with it on uncertain completion.
            _credit: Credit,
        }
        let length = bounds::ck_length(seed.len())?;
        let budget = &self.inner.symmetric_budget;
        let input_credit = if seed.credited_to(budget) {
            0
        } else {
            seed.allocated_bytes()
        };
        let amount = input_credit
            .checked_add(seed.len())
            .and_then(|n| n.checked_add(crate::error::CompletionStorage::allocation_bytes()))
            .and_then(|n| n.checked_add(size_of::<SeedCall>()))
            .and_then(|n| {
                n.checked_add(crate::native::frame::SessionFrame::<SeedCall>::allocation_bytes())
            })
            .ok_or(Error::Rejected(crate::RejectionReason::RandomGeneration(
                crate::RandomGenerationRejection::SeedOwnershipAccounting,
            )))?;
        let retained = crate::symmetric::memory::RetainedBytes::measure(budget, |retained| {
            crate::symmetric::memory::RetainedStorage::retain_credits(&seed, retained)
        })?;
        let progress = crate::session::AdmissionProgress::default().retaining(retained)?;
        let ((expected, prepaid, diagnostic), access) =
            self.prepare_with_roles([], false, &progress, || {
                let mut required = amount;
                loop {
                    // The consumed seed cannot be released by another caller.
                    // Wait only when other owners can make this combined peak
                    // fit; repeat the check after allocator-capacity adjustment.
                    if seed.credited_to(budget) {
                        if let Some(credit) = &seed.credit {
                            credit.check_additional_capacity(required)?;
                        }
                    }
                    let mut prepaid = crate::advanced::reserve_preparation_with_progress(
                        self, required, &progress,
                    )?;
                    let storage = crate::symmetric::memory::UnboundBuffer::allocate(seed.len())?;
                    let actual = input_credit
                        .checked_add(crate::error::CompletionStorage::allocation_bytes())
                        .and_then(|n| n.checked_add(size_of::<SeedCall>()))
                        .and_then(|n| {
                            n.checked_add(
                                crate::native::frame::SessionFrame::<SeedCall>::allocation_bytes(),
                            )
                        })
                        .and_then(|n| n.checked_add(storage.allocated()))
                        .ok_or(Error::Rejected(crate::RejectionReason::RandomGeneration(
                            crate::RandomGenerationRejection::SeedOwnershipAccounting,
                        )))?;
                    if actual > required {
                        drop(storage);
                        drop(prepaid);
                        required = actual;
                        continue;
                    }
                    prepaid.release(required - actual);
                    let mut expected = storage.bind(&mut prepaid)?;
                    expected.as_mut().copy_from_slice(seed.as_slice());
                    let diagnostic = crate::error::PreparedCompletionCell::prepare(&mut prepaid)?;
                    break Ok((expected, prepaid, diagnostic));
                }
            })?;
        // The original caller-owned seed is transferred only after possession.
        // Its extra integrity copy is discarded by prepare_with_roles on Busy.
        let prepared = SeedCall {
            seed,
            _credit: prepaid,
        };
        let handle = self.entry(&access)?.handle;
        let call = access.native.table.C_SeedRandom.ok_or(Error::Rejected(
            crate::RejectionReason::RandomGeneration(
                crate::RandomGenerationRejection::CSeedRandomUnavailable,
            ),
        ))?;
        let mut frame = NativeFrame::session(access, prepared)?;
        let (returned, body) = frame.session_parts();
        let s = &body.access;
        s.native.record("C_SeedRandom")?;
        let sequence =
            crate::session::Sequence::for_frame_prepared(s, self, returned, diagnostic.cell());
        // SAFETY: owned seed and credit remain in the stable session frame.
        // The independently credited integrity witness never reaches native code.
        let rv = returned.observe(
            unsafe { call(handle, body.data.seed.as_mut_slice().as_mut_ptr(), length) },
            &s.native,
        );
        let native_result = sequence.check(rv, "C_SeedRandom", true);
        if sequence.termination_known() && body.data.seed.as_slice() != expected.as_slice() {
            returned.quarantine(&s.native);
            let error = sequence.invalid_output(crate::RejectionReason::RandomGeneration(
                crate::RandomGenerationRejection::NativeSeedInputChanged,
            ));
            return Err(diagnostic
                .cell()
                .boundary_failure("C_SeedRandom", rv, error));
        }
        native_result?;
        diagnostic
            .cell()
            .finish("C_SeedRandom", self.public_result(s, Ok(())))
    }
}

/// Result of one caller-selected native slot-event request.
#[derive(Debug, PartialEq, Eq)]
pub enum SlotEvent {
    /// Provider returned CKR_NO_EVENT.
    NoEvent,
    /// Provider reported this slot. Existing contexts of that slot are now stale.
    Changed(u64),
    /// The provider returned NOT_INITIALIZED after this owner issued Finalize.
    /// This is the waiter's observation, not proof that Finalize succeeded.
    InterruptedByFinalization,
}

/// Registry owners needed to publish an event after releasing module admission.
/// These references contain no borrowed Native or provider pointer.
pub(crate) struct EventContext {
    foreign: std::sync::Arc<crate::module::foreign::Registry>,
    tokens: std::sync::Arc<std::sync::Mutex<crate::module::TokenRegistry>>,
    objects: crate::registry::Registry<crate::managed::NativeIdentity>,
    managed: crate::registry::Registry<crate::managed::NativeIdentity>,
    uncertain: std::sync::Arc<crate::native::Uncertainty>,
    session_ledger: std::sync::Arc<crate::session_budget::SessionLedger>,
}

/// The output slot and image form one independently retained native graph.
/// A returned boundary anomaly must not free pSlot even after Finalize succeeds.
struct SlotEventOutput {
    slot: CK_SLOT_ID,
    _image: Arc<crate::native::image::LoadedImage>,
    // The one native-addressed allocation remains charged if its return is
    // unproven, independently of the public diagnostic leaves.
    _credit: crate::symmetric::memory::Credit,
}

/// Error leaves belong to the public invocation, not to the native output
/// graph. Pending retains pSlot independently; a returned error transfers its
/// leaves to the caller only after all local publication work has finished.
struct SlotEventDiagnostics {
    completion: crate::error::PreparedCompletion,
    publication: crate::error::PreparedFailurePair,
    output: Option<crate::symmetric::memory::Credit>,
}

impl SlotEventDiagnostics {
    fn prepare(inner: &crate::module::Inner) -> Result<Self> {
        use crate::symmetric::memory::ControlledReservation;
        let amount = crate::error::PreparedCompletion::allocation_bytes()
            + crate::error::PreparedFailurePair::allocation_bytes()
            + std::mem::size_of::<SlotEventOutput>();
        let mut prepaid = match inner.symmetric_budget.reserve_controlled(
            amount,
            &crate::admission_wait::current(),
            || {
                inner.state.check_admission(false)?;
                inner.availability.check_available()?;
                inner.slot_events.check_preparation()?;
                Ok(None::<std::convert::Infallible>)
            },
            || Ok(None),
        )? {
            ControlledReservation::Acquired(credit) => credit,
            ControlledReservation::Redirect(never) => match never {},
        };
        Ok(Self {
            completion: crate::error::PreparedCompletion::prepare(
                "C_WaitForSlotEvent",
                &mut prepaid,
            )?,
            publication: crate::error::PreparedFailurePair::prepare(&mut prepaid)?,
            output: Some(prepaid.split(std::mem::size_of::<SlotEventOutput>())?),
        })
    }
}

impl EventContext {
    pub(crate) fn new(state: &crate::module::State) -> Self {
        Self {
            foreign: state.foreign.clone(),
            tokens: state.current_tokens.clone(),
            objects: state.objects.clone(),
            managed: state.managed.clone(),
            uncertain: state.native.uncertainty_flag(),
            session_ledger: state.session_ledger.clone(),
        }
    }
    fn withdraw(&self) {
        self.uncertain.mark();
    }
    pub(crate) fn invalidate(&self, slot: CK_SLOT_ID) -> Result<()> {
        let result = (|| {
            let last_generation = {
                let mut registry = self.tokens.lock().map_err(|_| {
                    self.uncertain.mark_token_registry_unverifiable();
                    Error::Poisoned
                })?;
                // Despite its name, next_generation stores the last assigned
                // value. Publication increments it with checked arithmetic.
                // A replacement published after this retirement has a greater
                // generation, so one scalar replaces the allocated identity set.
                let last_generation = registry.next_generation;
                // Check revision capacity before any local retirement. No native
                // call, alias-registry lock or consumer callback is made here.
                registry.advance()?;
                let foreign_epoch = self.foreign.observed_slot_epoch(slot as u64)?;
                for token in registry
                    .tokens
                    .iter()
                    .filter(|token| token.capabilities.identity.slot == slot as u64)
                {
                    token.invalidate();
                    token.forget_authentication()?;
                }
                // Foreign sessions can exist without a discovered Fe11 token.
                // Retire the epoch observed in this original runtime exactly
                // once, even if a token above already retired the shared domain.
                // This withdraws handles, never their retained native graphs.
                if let Some((domain, epoch)) = foreign_epoch {
                    domain.retire_foreign_epoch(epoch);
                }
                last_generation
            };

            // Never revoke a replacement published after the observed retirement.
            // The native-identity visitor pins its cursor and boundary, drops
            // owners outside Entries, and needs no temporary snapshot storage.
            // Registries may prune expired entries while this walk progresses.
            let revoke = |object: &crate::managed::NativeIdentity| {
                if object.slot == slot && object.generation <= last_generation {
                    object
                        .revoked
                        .store(true, std::sync::atomic::Ordering::Release);
                }
            };
            self.objects.visit_native_identities(revoke)?;
            self.managed.visit_native_identities(revoke)
        })();
        self.session_ledger.notify_admission();
        if result.is_err() {
            self.withdraw();
        }
        result
    }
}

impl Module {
    /// Observe local waiter/finalization ownership even while Finalize is in
    /// progress or after close. No provider call or module-admission guard is used.
    pub fn slot_event_status(&self) -> Result<crate::SlotEventStatus> {
        self.inner.slot_events.status()
    }

    /// Poll exactly once with CKF_DONT_BLOCK. No retry or rediscovery occurs.
    /// Poll and blocking waits share one per-module admission reservation.
    pub fn poll_slot_event(&self) -> Result<SlotEvent> {
        let mut diagnostics = None;
        self.slot_event(crate::native::events::EventMode::Poll, &mut diagnostics)
    }

    /// Issue one blocking C_WaitForSlotEvent with no library execution deadline.
    /// The caller chooses this blocking behavior. With Concurrent initialization,
    /// closing after other resources drain may issue Finalize concurrently.
    /// With Serialized initialization, close returns Busy while this waiter is
    /// engaged; it neither waits behind the native call nor changes lifecycle.
    /// The image and its exclusive initialization reservation remain owned until
    /// the waiter returns. Finalize refusal does not guarantee that it will return.
    pub fn wait_slot_event(&self) -> Result<SlotEvent> {
        let mut diagnostics = None;
        self.slot_event(crate::native::events::EventMode::Blocking, &mut diagnostics)
    }

    fn slot_event(
        &self,
        mode: crate::native::events::EventMode,
        diagnostics: &mut Option<SlotEventDiagnostics>,
    ) -> Result<SlotEvent> {
        use crate::native::events::EventMode;
        // No module guard or event lease is held during byte admission. In
        // particular, this preparation cannot exclude a concurrent Finalize.
        *diagnostics = Some(SlotEventDiagnostics::prepare(&self.inner)?);
        let diagnostics = diagnostics.as_mut().expect("slot diagnostics prepared");
        let diagnostic = diagnostics.completion.take()?;
        let state = self.inner.read()?;
        let call = state
            .native
            .table
            .C_WaitForSlotEvent
            .ok_or(Error::Rejected(crate::RejectionReason::RandomGeneration(
                crate::RandomGenerationRejection::CWaitForSlotEventUnavailable,
            )))?;
        let mut slot = NativeFrame::new(SlotEventOutput {
            slot: 0,
            _image: state.native.image.clone(),
            _credit: diagnostics
                .output
                .take()
                .expect("slot output prepared before admission"),
        })?;
        let context = EventContext::new(&state);
        let mut lease =
            state
                .native
                .events
                .reserve(self.inner.clone(), mode, context.uncertain.clone())?;

        let flags = if mode == EventMode::Poll {
            CKF_DONT_BLOCK
        } else {
            0
        };
        state.native.record("C_WaitForSlotEvent")?;
        let mut admission = Some(state);
        lease.dispatch();
        if mode == EventMode::Blocking {
            // The short registry transition was made under module admission.
            // In concurrent mode Finalize may accompany this call. Serialized
            // mode retains a distinct exclusion until the event return; close
            // observes that reservation before acquiring its module writer.
            drop(admission.take());
        }
        // SAFETY: the lease owns Inner/image independently of admission; pSlot
        // is stable owned output, pReserved is null. Only one waiter is issued.
        let rv = unsafe { call(flags as CK_FLAGS, &mut slot.slot, std::ptr::null_mut()) };
        if rv == CKR_PENDING {
            // context.withdraw below wakes new admissions before lease Drop.
            lease.retain_unproven();
        }
        if !crate::native_return::call_memory_returned(rv) {
            // PENDING retains both the output graph and its waiter lease.
            slot.retain_uncompleted();
            context.withdraw();
        }
        if rv == CKR_PENDING {
            // No native asynchronous mode recovery. The uncompleted lease also keeps instance
            // finalization excluded; returning from C is not its completion.
            return crate::error::check(rv, "C_WaitForSlotEvent", true).map(|_| unreachable!());
        }
        lease.native_returned();
        // Complete local retirement before allowing a subsequent waiter. This
        // does not reacquire module admission or delay Finalize's native return.
        let publication = if rv == CKR_OK {
            context.invalidate(slot.slot)
        } else {
            Ok(())
        };
        let retirement = lease.finish(rv);
        let local = match (publication, retirement) {
            (Ok(()), result) => result,
            (Err(error), Ok(_)) => Err(error),
            (Err(primary), Err(secondary)) => {
                Err(diagnostics.publication.finish(primary, secondary))
            }
        };
        let finalization_issued = diagnostic.finish_native(rv, local)?;
        if rv == CKR_CRYPTOKI_NOT_INITIALIZED && finalization_issued {
            return Ok(SlotEvent::InterruptedByFinalization);
        }
        if rv == CKR_NO_EVENT {
            return Ok(SlotEvent::NoEvent);
        }
        let scope = crate::native_return::slot_scope("C_WaitForSlotEvent", rv);
        crate::error::check(
            rv,
            "C_WaitForSlotEvent",
            matches!(
                scope,
                crate::native_return::FailureScope::Token
                    | crate::native_return::FailureScope::Module
            ),
        )?;
        Ok(SlotEvent::Changed(slot.slot as u64))
    }
}
