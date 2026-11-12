// SPDX-License-Identifier: Apache-2.0
//! Exact native search with explicit selection and no descriptive prerequisite.
//!
//! Search owns the catalog exclusion until publication. A suspended allocation
//! keeps returned handles in session recovery, never in a guard-free waiter.
use super::*;
use crate::{
    attribute_values::InputTemplate,
    session::{
        recovery::observations::{context, Prepared, Waiting},
        SessionAccess,
    },
    symmetric::memory::Credit,
    AttributeInput, AttributeTemplateLimits,
};
use search::{owned::resident::NativeStorage, SearchCandidate, SearchOwner, SearchPreparation};

/// Result of explicit selection in one complete native-order search.
/// Different searches are not snapshots of each other: their order may change.
pub struct NativeObjectSelection {
    /// Number of handles returned by this search, before selecting the index.
    pub matched: usize,
    /// Selected handle, or None when the requested index was outside this result.
    /// Missing optional attributes never prevent its publication or native use.
    pub object: Option<NativeObjectRef>,
}

/// Generic references from one completed search, in native return order.
/// The vector and its storage credit share a lifetime. Cloning a reference
/// shares its existing identity/quota; dropping it never destroys the object.
pub struct NativeObjectMatches {
    objects: Vec<NativeObjectRef>,
    _credit: Credit,
}
impl NativeObjectMatches {
    /// Borrow every reference from this search without another native call.
    pub fn as_slice(&self) -> &[NativeObjectRef] {
        &self.objects
    }
}

#[derive(Clone, Copy)]
enum SelectionRequest {
    Index(usize),
    All,
}
enum Selection {
    Index {
        identity: Arc<NativeIdentity>,
        permit: crate::registry::Reservation<NativeIdentity>,
        index: usize,
    },
    // Count is discovered only after FindObjectsFinal. Preparation then takes
    // the complete quota, never a prefix that could block its own next slot.
    AllPending,
    All(AllMatches),
}
enum SearchResult {
    Index(NativeObjectSelection),
    All(NativeObjectMatches),
}
// Publication is complete under possession; conversion and destruction of
// its private output storage occur only after that possession has left scope.
enum PreparedSearchResult {
    Index(NativeObjectSelection),
    All { matches: AllMatches, count: usize },
}
impl PreparedSearchResult {
    fn resolve(self, session: &Session) -> Result<SearchResult> {
        match self {
            Self::Index(selected) => Ok(SearchResult::Index(selected)),
            Self::All { matches, count } => matches.result(session, count).map(SearchResult::All),
        }
    }
}

// Declared before all access locals and before error cleanup. Drop is also the
// unwind fallback; it runs before Waiting can schedule registry maintenance.
struct CompleteSearchRetirement<'a> {
    session: &'a Session,
    coordination: &'a Arc<crate::session::recovery::observations::Coordination>,
    open: &'a std::cell::Cell<bool>,
}
impl CompleteSearchRetirement<'_> {
    fn retire(&self) -> Result<()> {
        use crate::session::recovery::observations::SearchRetirement;
        self.open.set(true);
        match self
            .session
            .entry
            .recovery
            .observations
            .retire_native_search(self.coordination)?
        {
            SearchRetirement::Returned(retired) => {
                drop(retired);
                self.open.set(false);
                Ok(())
            }
            SearchRetirement::Absent => {
                self.open.set(false);
                Ok(())
            }
            SearchRetirement::Pending => {
                Err(Error::Rejected(crate::RejectionReason::ObjectSearch(
                    crate::ObjectSearchRejection::NativeSearchStillPending,
                )))
            }
        }
    }
}
impl Drop for CompleteSearchRetirement<'_> {
    fn drop(&mut self) {
        let _ = self.retire();
    }
}

mod all;
mod stream;
use all::AllMatches;
pub use stream::NativeObjectIterator;
pub(crate) use stream::NativeSearchStreamOwner;

pub(crate) struct NativeSearchOwner {
    search: SearchOwner,
    selection: Selection,
    epoch: u64,
    _inventory: InventoryGuard,
    _credit: Credit,
}
impl NativeSearchOwner {
    pub(crate) fn pending(&self) -> bool {
        self.search.pending()
    }
    pub(crate) fn search_claimed(&self) -> bool {
        self.search.claimed()
    }
    fn publication_activity(
        &mut self,
        session: &Session,
    ) -> Result<Option<Arc<crate::registry::Activity>>> {
        context(session, Some(self.epoch), self.epoch)?;
        let (index, identity, permit) = match &mut self.selection {
            Selection::Index {
                identity,
                permit,
                index,
            } => (*index, identity, permit),
            Selection::All(matches) => {
                let Some(identity) = matches.identities.get_mut(matches.published) else {
                    return Ok(None);
                };
                (matches.published, identity, &mut matches.permit)
            }
            Selection::AllPending => {
                return Err(Error::Rejected(crate::RejectionReason::ObjectSearch(
                    crate::ObjectSearchRejection::SearchPublicationNotPrepared,
                )))
            }
        };
        self.search
            .selected(index)?
            .map(|handle| {
                let activity = mutations::object_activity_at(
                    &session.inner,
                    ResourceIdentity {
                        handle,
                        ..identity.resource()
                    },
                    crate::Observation::NotRequested,
                    permit,
                )?;
                let wake = session
                    .inner
                    .reservations
                    .lock()
                    .map_err(|_| Error::Poisoned)?
                    .scan_wake();
                activity.bind_context_wake(&wake)?;
                Ok(activity)
            })
            .transpose()
    }
    fn result(
        &mut self,
        session: &Session,
        access: &SessionAccess<'_>,
        mut publication: [Option<crate::registry::ReadPermit>; 1],
    ) -> Result<PreparedSearchResult> {
        context(session, Some(self.epoch), self.epoch)?;
        let count = self.search.completed_len()?;
        match &mut self.selection {
            Selection::Index {
                identity,
                permit,
                index,
            } => {
                let object = if let Some(handle) = self.search.selected(*index)? {
                    NativeIdentity::publish_discovered(
                        identity,
                        session,
                        access,
                        handle,
                        permit,
                        &mut publication,
                    )?;
                    Some(NativeObjectRef {
                        inner: session.inner.clone(),
                        identity: identity.clone(),
                        output_slot: None,
                    })
                } else {
                    None
                };
                Ok(PreparedSearchResult::Index(NativeObjectSelection {
                    matched: count,
                    object,
                }))
            }
            Selection::All(_) => {
                let Selection::All(matches) =
                    std::mem::replace(&mut self.selection, Selection::AllPending)
                else {
                    unreachable!("checked complete-search publication kind")
                };
                Ok(PreparedSearchResult::All { matches, count })
            }
            Selection::AllPending => Err(Error::Rejected(crate::RejectionReason::ObjectSearch(
                crate::ObjectSearchRejection::SearchPublicationNotPrepared,
            ))),
        }
    }
}

// A waiter carries only coordination and the shared Activity attribution.
// Handles and unpublished/published identities stay in the resident owner.
fn publish_selected(
    session: &Session,
    waiter: &Waiting<'_>,
    progress: &crate::session::AdmissionProgress,
    policy: &crate::ResourceAdmission,
    mut activity: Arc<crate::registry::Activity>,
) -> Result<PreparedSearchResult> {
    loop {
        let reader = activity.prepare_reader_checked(session.uid, policy, || waiter.check())?;
        loop {
            let mut permits = [None];
            let access = session.access_progress(progress)?;
            waiter.check()?;
            let slot = session
                .entry
                .recovery
                .observations
                .get(&waiter.coordination)?;
            let mut payload = slot.owner.lock().map_err(|_| Error::Poisoned)?;
            match reader.acquire_into(policy, &mut permits[0]) {
                Ok(()) => {
                    let owner = payload
                        .as_mut()
                        .ok_or(Error::Rejected(crate::RejectionReason::ObjectSearch(
                            crate::ObjectSearchRejection::NativeSearchOwnerAbsent,
                        )))?
                        .native_search_mut()?;
                    if let Selection::All(matches) = &mut owner.selection {
                        let handle =
                            owner
                                .search
                                .selected(matches.published)?
                                .ok_or(Error::Rejected(crate::RejectionReason::ObjectSearch(
                                    crate::ObjectSearchRejection::SearchPublicationIndexAbsent,
                                )))?;
                        NativeIdentity::publish_discovered(
                            &mut matches.identities[matches.published],
                            session,
                            &access,
                            handle,
                            &mut matches.permit,
                            &mut permits,
                        )?;
                        matches.published += 1;
                        if let Some(next) = owner.publication_activity(session)? {
                            activity = next;
                            // Release the old attributed reader and every possession
                            // before preparing the next canonical Activity reader.
                            drop(payload);
                            drop(slot);
                            drop(access);
                            break;
                        }
                        return payload
                            .as_mut()
                            .ok_or(Error::Rejected(crate::RejectionReason::ObjectSearch(
                                crate::ObjectSearchRejection::NativeSearchOwnerAbsent,
                            )))?
                            .native_search_mut()?
                            .result(session, &access, [None]);
                    }
                    return payload
                        .as_mut()
                        .ok_or(Error::Rejected(crate::RejectionReason::ObjectSearch(
                            crate::ObjectSearchRejection::NativeSearchOwnerAbsent,
                        )))?
                        .native_search_mut()?
                        .result(session, &access, permits);
                }
                Err(Error::Busy(_)) => {
                    drop(payload);
                    drop(slot);
                    drop(access);
                    reader.wait_available_in_context(policy, || waiter.check())?;
                }
                Err(error) => return Err(error),
            }
        }
    }
}

impl Session {
    /// Search with the caller's exact template and select an explicit native-order
    /// index. No CKA_CLASS, CKA_KEY_TYPE or optional attribute read is added.
    /// The template preserves omission, empty values, ordering and repetitions.
    /// `search` bounds storage and native batch width; it does not assert uniqueness.
    pub fn find_native_object_at<'a>(
        &self,
        template: &'a [AttributeInput<'a>],
        limits: AttributeTemplateLimits,
        search: SearchPlan,
        index: usize,
    ) -> Result<NativeObjectSelection> {
        match find(
            self,
            template,
            limits,
            search,
            SelectionRequest::Index(index),
        )? {
            SearchResult::Index(selected) => Ok(selected),
            SearchResult::All(_) => Err(Error::Rejected(crate::RejectionReason::ObjectSearch(
                crate::ObjectSearchRejection::SearchResultKindMismatch,
            ))),
        }
    }

    /// Return every generic reference from one complete native-order search.
    /// No class, key type or optional attribute read is required. The exact
    /// template, storage bounds and native errors have the same semantics as
    /// [`Self::find_native_object_at`]. This materializes one search; it is not
    /// a lazy iterator or a snapshot against changes made outside this library.
    ///
    /// Publication reserves the complete reference quota after the result count
    /// is known. The caller's admission deadline/cancellation applies to waits;
    /// a local refusal never repeats Find or destroys a discovered object.
    pub fn find_native_objects<'a>(
        &self,
        template: &'a [AttributeInput<'a>],
        limits: AttributeTemplateLimits,
        search: SearchPlan,
    ) -> Result<NativeObjectMatches> {
        match find(self, template, limits, search, SelectionRequest::All)? {
            SearchResult::All(matches) => Ok(matches),
            SearchResult::Index(_) => Err(Error::Rejected(crate::RejectionReason::ObjectSearch(
                crate::ObjectSearchRejection::SearchResultKindMismatch,
            ))),
        }
    }
}

fn find<'a>(
    session: &Session,
    input: &'a [AttributeInput<'a>],
    limits: AttributeTemplateLimits,
    plan: SearchPlan,
    selection: SelectionRequest,
) -> Result<SearchResult> {
    let template = InputTemplate::plan_scoped(input, limits, &session.inner)?;
    let reference =
        session.reference_admission(crate::session::ReferenceMode::Synchronous, |state| {
            if state.native.table.C_FindObjectsInit.is_none() {
                return Err(Error::Unsupported(
                    crate::UnsupportedReason::NativeFunction {
                        function: "C_FindObjectsInit",
                    },
                ));
            }
            if state.native.table.C_FindObjects.is_none() {
                return Err(Error::Unsupported(
                    crate::UnsupportedReason::NativeFunction {
                        function: "C_FindObjects",
                    },
                ));
            }
            if state.native.table.C_FindObjectsFinal.is_none() {
                return Err(Error::Unsupported(
                    crate::UnsupportedReason::NativeFunction {
                        function: "C_FindObjectsFinal",
                    },
                ));
            }
            Ok(())
        })?;
    let epoch = session.snapshot.authentication_stamp();
    let policy = crate::admission_wait::current();
    let image = session.inner.read()?.native.image.clone();
    let inventory_bytes = mutations::PreparedInventory::allocation_bytes()?;
    let identity_bytes = match selection {
        SelectionRequest::Index(_) => NativeIdentity::allocation_bytes(),
        SelectionRequest::All => 0,
    };
    let fixed = Prepared::allocation_bytes()
        .checked_add(std::mem::size_of::<NativeSearchOwner>())
        .and_then(|n| n.checked_add(crate::error::PreparedCleanupDiagnostic::allocation_bytes()))
        .and_then(|n| n.checked_add(crate::error::PreparedCleanupDiagnostic::allocation_bytes()))
        .and_then(|n| n.checked_add(identity_bytes))
        .and_then(|n| n.checked_add(inventory_bytes))
        .ok_or(Error::Rejected(crate::RejectionReason::ObjectSearch(
            crate::ObjectSearchRejection::NativeSearchStorageAccounting,
        )))?;
    let mut required = NativeStorage::requested(template.prepared_allocation_bytes()?, plan)?
        .checked_add(fixed)
        .ok_or(Error::Rejected(crate::RejectionReason::ObjectSearch(
            crate::ObjectSearchRejection::NativeSearchStorageAccounting,
        )))?;
    let (mut search_cleanup, mut retirement_cleanup, coordination, first_access) = loop {
        context(session, Some(epoch), epoch)?;
        // A failed preparation drops its unknown-creator participant. Obtain a
        // new reservation for each attempt instead of reusing a consumed token.
        let (mut permit, mut credit) = match selection {
            SelectionRequest::Index(_) => {
                let (permit, credit) = reference
                    .objects_with_storage(1, required, || context(session, Some(epoch), epoch))?;
                (Some(permit), credit)
            }
            SelectionRequest::All => {
                let credit = crate::advanced::reserve_preparation_while(
                    session,
                    required,
                    reference.progress(),
                    || {
                        context(session, Some(epoch), epoch)?;
                        Ok(true)
                    },
                )?
                .ok_or(Error::Rejected(crate::RejectionReason::ObjectSearch(
                    crate::ObjectSearchRejection::SearchPreparationUnexpectedlyInvalidated,
                )))?;
                (None, credit)
            }
        };
        let progress = reference.progress();
        let input = template.allocate()?;
        let storage = NativeStorage::allocate(plan)?;
        let actual = input
            .allocated_bytes()?
            .checked_add(storage.allocated_bytes()?)
            .and_then(|n| n.checked_add(fixed))
            .ok_or(Error::Rejected(crate::RejectionReason::ObjectSearch(
                crate::ObjectSearchRejection::NativeSearchStorageAccounting,
            )))?;
        if actual > required {
            drop((input, storage, credit, permit));
            required = actual;
            continue;
        }
        credit.release(required - actual);
        credit.observation_budget()?;
        let search_cleanup = crate::error::PreparedCleanupDiagnostic::prepare(&mut credit)?;
        let retirement_cleanup = crate::error::PreparedCleanupDiagnostic::prepare(&mut credit)?;
        let input = input.bind(&mut credit)?;
        input.check_extensions(&session.inner)?;
        let publication = match (selection, permit.take()) {
            (SelectionRequest::Index(index), Some(mut permit)) => Selection::Index {
                identity: NativeIdentity::prepare_discovery(
                    session,
                    epoch,
                    &mut permit,
                    &mut credit,
                )?,
                permit,
                index,
            },
            (SelectionRequest::All, None) => Selection::AllPending,
            _ => {
                return Err(Error::Rejected(crate::RejectionReason::ObjectSearch(
                    crate::ObjectSearchRejection::SearchPreparationKindMismatch,
                )))
            }
        };
        let mut registry = Some(Prepared::allocate(
            &session.inner.symmetric_budget,
            &mut credit,
        )?);
        let mut inventory = mutations::PreparedInventory::from_prepaid(session, &mut credit)?;
        let search = storage.bind_image(input, plan, epoch, image.clone(), &mut credit)?;
        let owner_credit = credit.split(std::mem::size_of::<NativeSearchOwner>())?;
        let access = match session.try_operation_access_progress(false, progress) {
            Ok(access) => access,
            Err(Error::Busy(_)) => {
                drop((search_cleanup, retirement_cleanup));
                drop((
                    search,
                    registry,
                    inventory,
                    publication,
                    owner_credit,
                    credit,
                    permit,
                ));
                drop(session.access_progress(progress)?);
                continue;
            }
            Err(error) => return Err(error),
        };
        reference.check(&access)?;
        context(session, Some(epoch), epoch)?;
        // Native Init decides whether another search prevents this one.
        // This attempt has independent resident storage; refusal must not
        // finalize or retire the earlier search.
        let protection = match inventory.publish_retained(session) {
            Ok(inventory) => inventory,
            Err(Error::Busy(_)) => {
                drop(access);
                drop((search_cleanup, retirement_cleanup));
                drop((
                    search,
                    registry,
                    inventory,
                    publication,
                    owner_credit,
                    credit,
                    permit,
                ));
                mutations::PreparedInventory::wait_available(session, epoch)?;
                continue;
            }
            Err(error) => return Err(error),
        };
        // No fallible construction after moving the early private resources.
        // The early registry local retains the complete owner on publication
        // refusal; its destructor therefore runs after access has been released.
        let owner = NativeSearchOwner {
            search,
            selection: publication,
            epoch,
            _inventory: protection,
            _credit: owner_credit,
        };
        registry = Some(
            registry
                .take()
                .expect("prepared search registry")
                .bind_native_search(owner),
        );
        let coordination = session
            .entry
            .recovery
            .observations
            .publish_retained(&mut registry)?;
        break (search_cleanup, retirement_cleanup, coordination, access);
    };
    let waiter = Waiting::new(session, coordination, Some(epoch), epoch);
    let open = std::cell::Cell::new(false);
    let _withdrawal = search::SearchWithdrawal::new(session, &open);
    let retirement = CompleteSearchRetirement {
        session,
        coordination: &waiter.coordination,
        open: &open,
    };
    let mut access = Some(first_access);
    let result = (|| loop {
        waiter.check()?;
        let held = access
            .take()
            .ok_or(Error::Rejected(crate::RejectionReason::ObjectSearch(
                crate::ObjectSearchRejection::NativeSearchPossessionAbsent,
            )))?;
        let slot = session
            .entry
            .recovery
            .observations
            .get(&waiter.coordination)?;
        let mut payload = slot.owner.lock().map_err(|_| Error::Poisoned)?;
        let owner = payload
            .as_mut()
            .ok_or(Error::Rejected(crate::RejectionReason::ObjectSearch(
                crate::ObjectSearchRejection::NativeSearchOwnerAbsent,
            )))?
            .native_search_mut()?;
        open.set(owner.search_claimed());
        let advanced = owner.search.advance(session, &held);
        open.set(owner.search_claimed() && owner.pending());
        advanced?;
        if owner.search.complete() {
            if matches!(owner.selection, Selection::AllPending) {
                let count = owner.search.completed_len()?;
                drop(payload);
                drop(slot);
                drop(held);
                loop {
                    let matches = AllMatches::prepare(session, epoch, count, &waiter, |bytes| {
                        reference.objects_with_storage_observing(
                            count,
                            bytes,
                            waiter.budget(),
                            || waiter.check(),
                        )
                    })?;
                    let resumed =
                        match session.try_operation_access_progress(false, reference.progress()) {
                            Ok(access) => access,
                            Err(Error::Busy(_)) => {
                                drop(matches);
                                drop(session.access_progress(reference.progress())?);
                                continue;
                            }
                            Err(error) => return Err(error),
                        };
                    waiter.check()?;
                    reference.check(&resumed)?;
                    let slot = session
                        .entry
                        .recovery
                        .observations
                        .get(&waiter.coordination)?;
                    let mut payload = slot.owner.lock().map_err(|_| Error::Poisoned)?;
                    let owner = payload
                        .as_mut()
                        .ok_or(Error::Rejected(crate::RejectionReason::ObjectSearch(
                            crate::ObjectSearchRejection::NativeSearchOwnerAbsent,
                        )))?
                        .native_search_mut()?;
                    if !matches!(owner.selection, Selection::AllPending)
                        || owner.search.completed_len()? != count
                    {
                        return Err(Error::Rejected(crate::RejectionReason::ObjectSearch(
                            crate::ObjectSearchRejection::SearchPublicationChanged,
                        )));
                    }
                    owner.selection = Selection::All(matches);
                    drop(payload);
                    drop(slot);
                    access = Some(resumed);
                    break;
                }
                continue;
            }
            if let Some(activity) = owner.publication_activity(session)? {
                drop(payload);
                drop(slot);
                drop(held);
                return publish_selected(session, &waiter, reference.progress(), &policy, activity);
            }
            return payload
                .as_mut()
                .expect("complete native search")
                .native_search_mut()?
                .result(session, &held, [None]);
        }
        let need =
            owner
                .search
                .need()?
                .ok_or(Error::Rejected(crate::RejectionReason::ObjectSearch(
                    crate::ObjectSearchRejection::NativeSearchResourceNeedAbsent,
                )))?;
        drop(payload);
        drop(slot);
        drop(held);
        loop {
            let candidate = match SearchCandidate::prepare(need, waiter.budget(), &policy, || {
                waiter.check()?;
                Ok(None::<()>)
            })? {
                SearchPreparation::Ready(candidate) => candidate,
                SearchPreparation::Redirect(()) => unreachable!("no redirect"),
            };
            let resumed = match session.try_operation_access_progress(false, reference.progress()) {
                Ok(access) => access,
                Err(Error::Busy(_)) => {
                    drop(candidate);
                    drop(session.access_progress(reference.progress())?);
                    continue;
                }
                Err(error) => return Err(error),
            };
            waiter.check()?;
            let slot = session
                .entry
                .recovery
                .observations
                .get(&waiter.coordination)?;
            let mut payload = slot.owner.lock().map_err(|_| Error::Poisoned)?;
            payload
                .as_mut()
                .ok_or(Error::Rejected(crate::RejectionReason::ObjectSearch(
                    crate::ObjectSearchRejection::NativeSearchOwnerAbsent,
                )))?
                .native_search_mut()?
                .search
                .attach(candidate)?;
            drop(payload);
            drop(slot);
            access = Some(resumed);
            break;
        }
    })();
    drop(access);
    let result = search::finish_failed_search(
        session,
        &waiter.coordination,
        &open,
        result,
        &mut search_cleanup,
        None,
        || session.try_advanced_access_progress(reference.progress()),
        |owner, access| {
            let owner = owner.native_search_mut()?;
            let result = owner.search.finish(session, access);
            open.set(owner.search_claimed() && owner.pending());
            result
        },
    )
    .and_then(|prepared| prepared.resolve(session));
    // Native cleanup and result conversion have released all possession.
    // Preserve the original failure when terminal metadata retirement fails.
    let retired = retirement.retire();
    match (result, retired) {
        (Err(error), Err(cleanup)) => Err(retirement_cleanup
            .take(error)
            .finish_sequence(Some(cleanup))),
        (Err(error), Ok(())) | (Ok(_), Err(error)) => Err(error),
        (Ok(value), Ok(())) => Ok(value),
    }
}
