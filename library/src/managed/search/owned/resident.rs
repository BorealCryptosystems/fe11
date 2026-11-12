// SPDX-License-Identifier: Apache-2.0
//! A search whose returned batches survive guard-free resource admission.
//!
//! The enclosing session owner keeps this value and its catalogue protection.
//! Native storage has a separate stable allocation. A completed C call and the
//! end of the native search are different facts: only Final releases the latter.
//! The enclosing owner credits its inline SearchOwner; this component credits
//! only its separate call allocation, template graph and dynamic handle storage.
use super::*;

use crate::{
    attributes::OwnedTemplateStorage,
    error::check,
    native_return::sequence::{self, Completion, OutputRequest},
};
use std::{mem::size_of, sync::Arc};

#[derive(Clone, Copy)]
enum Phase {
    Init,
    Find,
    Batch(usize),
    Final,
    Complete,
    InFlight,
    Uncertain,
}

pub(crate) struct SearchOwner {
    call: Box<SearchCall>,
    collection: SearchCollection,
    phase: Phase,
    epoch: u64,
    // No strong Inner/SessionEntry link: the session registry owns this value.
    _image: Arc<crate::native::image::LoadedImage>,
}

pub(crate) struct Storage {
    template: OwnedTemplateStorage,
    batch: Vec<CK_OBJECT_HANDLE>,
    call: crate::allocation::Slot<SearchCall>,
    diagnostic: crate::error::CompletionStorage,
}
impl Storage {
    pub(crate) fn requested(template: &Template, plan: SearchPlan) -> Result<usize> {
        Self::requested_bytes(template.owned_storage_bytes()?, plan)
    }
    pub(crate) fn requested_bytes(template_bytes: usize, plan: SearchPlan) -> Result<usize> {
        bounds::ck_length(plan.batch_size.get())?;
        template_bytes
            .checked_add(size_of::<SearchCall>() - size_of::<OwnedTemplate>())
            .and_then(|n| n.checked_add(crate::error::CompletionStorage::allocation_bytes()))
            .and_then(|n| {
                plan.batch_size
                    .get()
                    .checked_mul(size_of::<CK_OBJECT_HANDLE>())
                    .and_then(|batch| n.checked_add(batch))
            })
            .ok_or(Error::Rejected(crate::RejectionReason::ObjectSearch(
                crate::ObjectSearchRejection::SearchStorageSize,
            )))
    }
    pub(crate) fn allocate(template: &Template, plan: SearchPlan) -> Result<Self> {
        Self::allocate_owned(template.try_duplicate()?, plan)
    }
    pub(crate) fn allocate_owned(template: Template, plan: SearchPlan) -> Result<Self> {
        let template = OwnedTemplateStorage::allocate(template)?;
        let mut batch = Vec::new();
        batch
            .try_reserve_exact(plan.batch_size.get())
            .map_err(|_| {
                Error::Rejected(crate::RejectionReason::ObjectSearch(
                    crate::ObjectSearchRejection::SearchBatchAllocation,
                ))
            })?;
        batch.resize(plan.batch_size.get(), CK_INVALID_HANDLE);
        Ok(Self {
            template,
            batch,
            call: crate::allocation::Slot::new()?,
            diagnostic: crate::error::CompletionStorage::allocate()?,
        })
    }
    pub(crate) fn allocated_bytes(&self) -> Result<usize> {
        self.template
            .allocated_bytes()?
            .checked_add(size_of::<SearchCall>() - size_of::<OwnedTemplate>())
            .and_then(|n| n.checked_add(crate::error::CompletionStorage::allocation_bytes()))
            .and_then(|n| {
                self.batch
                    .capacity()
                    .checked_mul(size_of::<CK_OBJECT_HANDLE>())
                    .and_then(|batch| n.checked_add(batch))
            })
            .ok_or(Error::Rejected(crate::RejectionReason::ObjectSearch(
                crate::ObjectSearchRejection::SearchStorageSize,
            )))
    }
    pub(crate) fn bind(
        self,
        plan: SearchPlan,
        epoch: u64,
        access: &SessionAccess<'_>,
        prepaid: &mut Credit,
    ) -> Result<SearchOwner> {
        Self::bind_retained(&mut Some(self), plan, epoch, access, prepaid)
    }

    /// Keep all buffers in the enclosing candidate until the full credit
    /// partition succeeds. The stable call slot was allocated before access.
    pub(crate) fn bind_retained(
        candidate: &mut Option<Self>,
        plan: SearchPlan,
        epoch: u64,
        access: &SessionAccess<'_>,
        prepaid: &mut Credit,
    ) -> Result<SearchOwner> {
        let storage =
            candidate
                .as_ref()
                .ok_or(Error::Rejected(crate::RejectionReason::ObjectSearch(
                    crate::ObjectSearchRejection::SearchPreparationAlreadyConsumed,
                )))?;
        let call_bytes = (size_of::<SearchCall>() - size_of::<OwnedTemplate>()
            + crate::error::CompletionStorage::allocation_bytes())
        .checked_add(
            storage
                .batch
                .capacity()
                .checked_mul(size_of::<CK_OBJECT_HANDLE>())
                .ok_or(Error::Rejected(crate::RejectionReason::ObjectSearch(
                    crate::ObjectSearchRejection::SearchStorageSize,
                )))?,
        )
        .ok_or(Error::Rejected(crate::RejectionReason::ObjectSearch(
            crate::ObjectSearchRejection::SearchStorageSize,
        )))?;
        let template_bytes = storage.template.allocated_bytes()?;
        let [template_credit, call_credit, collection_credit] =
            prepaid.split_group([template_bytes, call_bytes, 0])?;
        let storage = candidate.take().expect("validated search preparation");
        let template = storage.template.into_prepaid(template_credit);
        Ok(SearchOwner {
            call: storage.call.write(SearchCall {
                template: SearchTemplate::Descriptive(template),
                batch: storage.batch,
                diagnostic: Some(storage.diagnostic),
                count: 0,
                _credit: call_credit,
            }),
            collection: SearchCollection::from_credit(plan, collection_credit),
            phase: Phase::Init,
            epoch,
            _image: access.native.image.clone(),
        })
    }
}

/// Batch storage for an exact caller template. Its parameter arena is prepared
/// in the same credit reservation, before possession, and is never rewritten.
pub(crate) struct NativeStorage {
    batch: Vec<CK_OBJECT_HANDLE>,
    diagnostic: crate::error::CompletionStorage,
}
impl NativeStorage {
    pub(crate) fn requested(template: usize, plan: SearchPlan) -> Result<usize> {
        bounds::ck_length(plan.batch_size.get())?;
        Self::bytes(plan.batch_size.get())?
            .checked_add(template)
            .ok_or(Error::Rejected(crate::RejectionReason::ObjectSearch(
                crate::ObjectSearchRejection::NativeSearchStorageSize,
            )))
    }
    fn bytes(capacity: usize) -> Result<usize> {
        capacity
            .checked_mul(size_of::<CK_OBJECT_HANDLE>())
            .and_then(|bytes| {
                bytes.checked_add(
                    size_of::<SearchCall>() - size_of::<crate::attribute_values::InputTemplate>()
                        + crate::error::CompletionStorage::allocation_bytes(),
                )
            })
            .ok_or(Error::Rejected(crate::RejectionReason::ObjectSearch(
                crate::ObjectSearchRejection::NativeSearchStorageSize,
            )))
    }
    pub(crate) fn allocate(plan: SearchPlan) -> Result<Self> {
        let mut batch = Vec::new();
        batch
            .try_reserve_exact(plan.batch_size.get())
            .map_err(|_| {
                Error::Rejected(crate::RejectionReason::ObjectSearch(
                    crate::ObjectSearchRejection::NativeSearchBatchAllocation,
                ))
            })?;
        batch.resize(plan.batch_size.get(), CK_INVALID_HANDLE);
        Ok(Self {
            batch,
            diagnostic: crate::error::CompletionStorage::allocate()?,
        })
    }
    pub(crate) fn allocated_bytes(&self) -> Result<usize> {
        Self::bytes(self.batch.capacity())
    }

    /// Prepare streaming ownership before session possession. The caller pins
    /// the current image and revalidates the session generation before publish.
    pub(crate) fn bind_image(
        self,
        template: crate::attribute_values::InputTemplate,
        plan: SearchPlan,
        epoch: u64,
        image: Arc<crate::native::image::LoadedImage>,
        prepaid: &mut Credit,
    ) -> Result<SearchOwner> {
        let bytes = self.allocated_bytes()?;
        Ok(SearchOwner {
            call: Box::new(SearchCall {
                template: SearchTemplate::Native(template),
                batch: self.batch,
                diagnostic: Some(self.diagnostic),
                count: 0,
                _credit: prepaid.split(bytes)?,
            }),
            collection: SearchCollection::from_prepaid(plan, prepaid)?,
            phase: Phase::Init,
            epoch,
            _image: image,
        })
    }
}

impl SearchOwner {
    pub(crate) fn complete(&self) -> bool {
        matches!(self.phase, Phase::Complete)
    }
    pub(crate) fn claimed(&self) -> bool {
        !self.complete()
    }
    pub(crate) fn pending(&self) -> bool {
        !matches!(self.phase, Phase::Init | Phase::Complete)
    }
    pub(crate) fn need(&mut self) -> Result<Option<super::super::SearchNeed>> {
        let Phase::Batch(count) = self.phase else {
            return Ok(None);
        };
        self.collection
            .preparation_need(&mut self.call.batch[..count])
            .map_err(collection_error)
    }
    pub(crate) fn attach(&mut self, candidate: super::super::SearchCandidate) -> Result<()> {
        if self.need()? != Some(candidate.need()) {
            return Err(Error::Rejected(crate::RejectionReason::ObjectSearch(
                crate::ObjectSearchRejection::SearchContinuationChanged,
            )));
        }
        self.collection.attach(candidate)
    }
    pub(crate) fn into_collection(self) -> Result<SearchCollection> {
        if !self.complete() {
            return Err(Error::Rejected(crate::RejectionReason::ObjectSearch(
                crate::ObjectSearchRejection::SearchIncomplete,
            )));
        }
        Ok(self.collection)
    }
    /// Read metadata only while preparing publication of the resident results.
    pub(crate) fn completed_len(&self) -> Result<usize> {
        if !self.complete() {
            return Err(Error::Rejected(crate::RejectionReason::ObjectSearch(
                crate::ObjectSearchRejection::SearchIncomplete,
            )));
        }
        Ok(self.collection.len())
    }
    /// Inspect a completed selection while the collection remains resident.
    pub(crate) fn selected(&self, index: usize) -> Result<Option<CK_OBJECT_HANDLE>> {
        if !self.complete() {
            return Err(Error::Rejected(crate::RejectionReason::ObjectSearch(
                crate::ObjectSearchRejection::SearchIncomplete,
            )));
        }
        Ok(self.collection.get(index).copied())
    }
    fn context(&self, session: &Session, access: &SessionAccess<'_>) -> Result<()> {
        if !access.owns_session(session) {
            return Err(Error::Rejected(crate::RejectionReason::ObjectSearch(
                crate::ObjectSearchRejection::SearchAccessOwner,
            )));
        }
        // Cleanup of an already active Find is also permitted if an unrelated
        // advanced owner was installed while this inventory waited. This does
        // not admit a new ordinary operation or replace that advanced owner.
        session.entry_common(access)?;
        session.snapshot.check_authentication_unchanged(self.epoch)
    }
    pub(crate) fn check_functions(access: &SessionAccess<'_>) -> Result<()> {
        if access.native.table.C_FindObjectsInit.is_none() {
            return Err(Error::Rejected(crate::RejectionReason::SessionLifecycle(
                crate::SessionLifecycleRejection::CFindObjectsInitUnavailable,
            )));
        }
        if access.native.table.C_FindObjects.is_none() {
            return Err(Error::Rejected(crate::RejectionReason::SessionLifecycle(
                crate::SessionLifecycleRejection::CFindObjectsUnavailable,
            )));
        }
        if access.native.table.C_FindObjectsFinal.is_none() {
            return Err(Error::Rejected(crate::RejectionReason::SessionLifecycle(
                crate::SessionLifecycleRejection::CFindObjectsFinalUnavailable,
            )));
        }
        Ok(())
    }
    fn dispatch(&mut self, session: &Session, access: &SessionAccess<'_>) -> Result<()> {
        // Match the non-resident search's observation boundaries. Withdrawal
        // during a pause is checked before counting or dispatching another call.

        self.context(session, access)?;
        Self::check_functions(access)?;
        // The existing search contract requires all three entries, including
        // Final before Init can create a search that needs cleanup.
        let find_init = crate::native::functions::resolve(
            access.native.table.C_FindObjectsInit,
            "C_FindObjectsInit",
        )?;
        let find =
            crate::native::functions::resolve(access.native.table.C_FindObjects, "C_FindObjects")?;
        let find_final = crate::native::functions::resolve(
            access.native.table.C_FindObjectsFinal,
            "C_FindObjectsFinal",
        )?;
        let phase = self.phase;
        let name = match phase {
            Phase::Init => "C_FindObjectsInit",
            Phase::Find => "C_FindObjects",
            Phase::Final => "C_FindObjectsFinal",
            _ => {
                return Err(Error::Rejected(crate::RejectionReason::ObjectSearch(
                    crate::ObjectSearchRejection::SearchDispatchPhase,
                )))
            }
        };
        let count = self.call.template.count()?;
        let capacity = bounds::ck_length(self.call.batch.len())?;
        access.native.record(name)?;
        self.call.count = 0;
        self.phase = Phase::InFlight;
        // SAFETY: the session possession serializes dispatch; the boxed call
        // owns template, descriptor witnesses, batch and count at stable addresses.
        // Its enclosing resident owner retains the image and all buffers even
        // on unwind, a pending return, context loss or a boundary anomaly.
        let rv = unsafe {
            match phase {
                Phase::Init => {
                    find_init(session.entry.handle, self.call.template.as_mut_ptr(), count)
                }
                Phase::Find => find(
                    session.entry.handle,
                    self.call.batch.as_mut_ptr(),
                    capacity,
                    &mut self.call.count,
                ),
                Phase::Final => find_final(session.entry.handle),
                _ => unreachable!("dispatch phase checked"),
            }
        };
        if rv == CKR_PENDING as CK_RV {
            // The resident owner retains addresses; this separate receipt is
            // consulted by session/slot/module cleanup before dispatch.
            session.entry.recovery.mark_pending_call();
            access.native.mark_uncertain();
        }
        access.apply_session_failure(
            &session.entry,
            rv,
            crate::native_return::native_context_scope(rv),
        );
        let v = access.native.table.version;
        let completion = if matches!(phase, Phase::Init) {
            sequence::init((v.major, v.minor), name, rv)
        } else {
            sequence::returned((v.major, v.minor), name, OutputRequest::Unspecified, rv)
        };
        // A returned Init/batch releases its call loan, not an active search.
        // Final still needs a termination proof: an unsuccessful Final is never
        // replayed merely because its call returned. Refused output is not read.
        let returned = match phase {
            Phase::Init | Phase::Find => crate::native_return::call_memory_returned(rv),
            Phase::Final => completion == Completion::Terminated,
            _ => false,
        };
        if !returned || completion == Completion::Uncertain {
            self.phase = Phase::Uncertain;
            session.poison(access);
            return check_native(
                session,
                rv,
                name,
                crate::native_return::effect_uncertain(rv),
            )
            .and(Err(Error::Rejected(crate::RejectionReason::ObjectSearch(
                crate::ObjectSearchRejection::SearchOutcomeUncertain,
            ))));
        }
        if !self.call.template.unchanged()
            || matches!(phase, Phase::Find)
                && rv == CKR_OK
                && self.call.count as u128 > self.call.batch.len() as u128
        {
            self.phase = Phase::Uncertain;
            access.native.mark_uncertain();
            let _ = check_native(
                session,
                rv,
                name,
                crate::native_return::effect_uncertain(rv),
            );
            return Err(self
                .call
                .diagnostic
                .take()
                .expect("search diagnostic prepared before possession")
                .bind(name)
                .boundary_failure(
                    rv,
                    Error::Rejected(crate::RejectionReason::ObjectSearch(
                        crate::ObjectSearchRejection::SearchTemplateOrCapacityChanged,
                    )),
                ));
        }
        let initialization_refused = matches!(phase, Phase::Init)
            && sequence::initialization_refused((v.major, v.minor), name, rv);
        // A failed Init retires only this attempt. In particular it must
        // not release the identity of an older search after OPERATION_ACTIVE.
        // Conversely, an unexpected successful competing Init cannot silently
        // redirect either iterator's later Find/Final to the other search.
        let owner = std::ptr::addr_of!(*self.call) as usize;
        let publication = if matches!(phase, Phase::Init) {
            if rv == CKR_OK {
                session
                    .entry
                    .recovery
                    .observations
                    .search_initialized(owner)
            } else {
                Ok(())
            }
        } else if completion == Completion::Terminated {
            session.entry.recovery.observations.search_terminated(owner)
        } else {
            Ok(())
        };
        if let Err(error) = publication {
            self.phase = Phase::Uncertain;
            access.native.mark_uncertain();
            session.poison(access);
            // Retain authentication observations and both the native return
            // and publication failure. The prepared leaf is not allocated here.
            let _ = check_native(session, rv, name, true);
            return self
                .call
                .diagnostic
                .take()
                .expect("search diagnostic prepared before possession")
                .bind(name)
                .finish_native(rv, Err(error));
        }
        self.phase = if completion == Completion::Terminated || initialization_refused {
            Phase::Complete
        } else if rv == CKR_OK {
            match phase {
                Phase::Init => Phase::Find,
                Phase::Find => Phase::Batch(bounds::final_length(
                    self.call.count,
                    self.call.batch.len(),
                )?),
                _ => Phase::Uncertain,
            }
        } else {
            // A returned ordinary Next failure still requires one Final.
            Phase::Final
        };
        check_native(
            session,
            rv,
            name,
            crate::native_return::effect_uncertain(rv),
        )?;
        // The returned batch and its bounds are recorded above, before further processing.
        // The resident owner keeps data and catalogue access until explicit
        // native cleanup, independently of the Rust stack.

        self.context(session, access)
    }
    /// Start the already registered search without fetching any objects.
    /// The complete-search driver remains separate; streaming never appends to
    /// its collection, and every native call uses the same return classifier.
    pub(crate) fn initialize_stream(
        &mut self,
        session: &Session,
        access: &SessionAccess<'_>,
    ) -> Result<()> {
        self.context(session, access)?;
        if !matches!(self.phase, Phase::Init) {
            return Err(Error::Rejected(crate::RejectionReason::ObjectSearch(
                crate::ObjectSearchRejection::SearchStreamAlreadyInitialized,
            )));
        }
        self.dispatch(session, access)
    }

    /// Fetch at most one native batch. Re-entering after an allocation wait
    /// returns the resident batch; it cannot repeat Find or grow a collection.
    pub(crate) fn stream_batch(
        &mut self,
        session: &Session,
        access: &SessionAccess<'_>,
    ) -> Result<usize> {
        self.context(session, access)?;
        if matches!(self.phase, Phase::Find) {
            self.dispatch(session, access)?;
        }
        self.stream_batch_len()
    }

    pub(crate) fn stream_batch_len(&self) -> Result<usize> {
        match self.phase {
            Phase::Batch(count) => Ok(count),
            _ => Err(Error::Rejected(crate::RejectionReason::ObjectSearch(
                crate::ObjectSearchRejection::SearchStreamBatchUnavailable,
            ))),
        }
    }

    pub(crate) fn stream_handle(&self, index: usize) -> Result<CK_OBJECT_HANDLE> {
        let count = self.stream_batch_len()?;
        if index >= count {
            return Err(Error::Rejected(crate::RejectionReason::ObjectSearch(
                crate::ObjectSearchRejection::SearchStreamIndexOutsideBatch,
            )));
        }
        let handle = self.call.batch[index];
        if handle == CK_INVALID_HANDLE {
            return Err(Error::Rejected(crate::RejectionReason::ObjectSearch(
                crate::ObjectSearchRejection::InvalidSearchResultHandle,
            )));
        }
        Ok(handle)
    }

    /// The publication owner acknowledges only after every identity has been
    /// published. A zero batch must go through finish, never another Find.
    pub(crate) fn acknowledge_stream_batch(&mut self) -> Result<()> {
        if self.stream_batch_len()? == 0 {
            return Err(Error::Rejected(crate::RejectionReason::ObjectSearch(
                crate::ObjectSearchRejection::EmptySearchBatchRequiresFinalization,
            )));
        }
        self.phase = Phase::Find;
        Ok(())
    }

    pub(crate) fn advance(&mut self, session: &Session, access: &SessionAccess<'_>) -> Result<()> {
        loop {
            self.context(session, access)?;
            match self.phase {
                Phase::Init | Phase::Find | Phase::Final => self.dispatch(session, access)?,
                Phase::Batch(count) => {
                    if self.need()?.is_some() {
                        return Ok(());
                    }
                    self.collection
                        .append_prepared(&mut self.call.batch[..count])
                        .map_err(collection_error)?;
                    self.phase = if count == 0 {
                        Phase::Final
                    } else {
                        Phase::Find
                    };
                }
                Phase::Complete => return Ok(()),
                Phase::InFlight | Phase::Uncertain => {
                    return Err(Error::Rejected(crate::RejectionReason::ObjectSearch(
                        crate::ObjectSearchRejection::SearchOutcomeUncertain,
                    )))
                }
            }
        }
    }
    /// Explicit error-path cleanup, never background maintenance. An attempted
    /// Final cannot be repeated after its context/dispatch/result becomes uncertain.
    pub(crate) fn finish(&mut self, session: &Session, access: &SessionAccess<'_>) -> Result<()> {
        match self.phase {
            Phase::Init | Phase::Complete => Ok(()),
            Phase::InFlight | Phase::Uncertain => {
                Err(Error::Rejected(crate::RejectionReason::ObjectSearch(
                    crate::ObjectSearchRejection::SearchOutcomeUncertain,
                )))
            }
            _ => {
                if let Err(error) = self.context(session, access) {
                    self.phase = Phase::Uncertain;
                    session.poison(access);
                    return Err(error);
                }
                self.phase = Phase::Final;
                let result = self.dispatch(session, access);
                if !self.complete() {
                    self.phase = Phase::Uncertain;
                    session.poison(access);
                }
                result
            }
        }
    }
}
fn collection_error(error: CollectionError) -> Error {
    match error {
        CollectionError::Malformed => Error::Rejected(crate::RejectionReason::KeyAdmission(
            crate::KeyAdmissionRejection::InvalidOrRepeatedObjectHandle,
        )),
        CollectionError::Local(error) => error,
    }
}

pub(crate) struct SearchWithdrawal<'a> {
    session: &'a Session,
    active: &'a std::cell::Cell<bool>,
}
impl Drop for SearchWithdrawal<'_> {
    fn drop(&mut self) {
        if self.active.get() {
            // Includes unwind after dispatch. The session owner, not this stack
            // marker, retains the native storage and catalogue permission.
            self.session
                .entry
                .poisoned
                .store(true, std::sync::atomic::Ordering::Release);
            self.session.snapshot.notify_admission();
        }
    }
}

impl<'a> SearchWithdrawal<'a> {
    pub(crate) fn new(session: &'a Session, active: &'a std::cell::Cell<bool>) -> Self {
        Self { session, active }
    }
}

// Preserve the outer synchronous reader's authentication-error observation even
// when native failure prevents completing the compound report.
fn check_native(session: &Session, rv: CK_RV, function: &'static str, effect: bool) -> Result<()> {
    let result = check(rv, function, effect);
    if let Err(error) = &result {
        session.observe_authentication_error(error);
    }
    result
}
