// SPDX-License-Identifier: Apache-2.0
//! One resident inventory: native discovery, class reads and metadata reads.
//!
//! Catalogue protection outlives every child read. Completed handles and rows
//! never move into a resource waiter, and closing the session can reclaim the
//! entire protocol once native termination has been proved.
use super::*;
use crate::{
    attributes::owned::resident::{LegacyOwner, ReadStorage, Recipe, ValueNeed},
    session::{
        recovery::observations::{context, Prepared, Waiting},
        AdmissionProgress, SessionAccess,
    },
    symmetric::memory::{ControlledReservation, Credit},
};
use search::{
    owned::resident::{SearchOwner, Storage as SearchStorage},
    SearchCandidate, SearchCollection, SearchNeed, SearchPreparation,
};

#[derive(Clone, Copy, PartialEq, Eq)]
enum ReadKind {
    Class,
    Details(ManagedClass),
}
#[derive(Clone, Copy, PartialEq, Eq)]
enum Need {
    Search(SearchNeed),
    Rows(usize),
    Read { kind: ReadKind, maximum: usize },
    Value(ValueNeed),
}
enum ReadPhase {
    NeedClass,
    Class(LegacyOwner),
    NeedDetails(ManagedClass),
    Details {
        class: ManagedClass,
        read: LegacyOwner,
    },
    Stopped,
}
struct Metadata {
    handles: SearchCollection,
    rows: Vec<ObjectMetadata>,
    order: Vec<usize>,
    remaining: usize,
    index: usize,
    phase: ReadPhase,
}
enum Phase {
    Search(SearchOwner),
    Rows(SearchCollection),
    Metadata(Metadata),
    Complete(Vec<ObjectMetadata>),
    Stopped,
}
pub(crate) struct InventoryOwner {
    phase: Phase,
    plan: crate::AttributeReadPlan,
    epoch: u64,
    _inventory: InventoryGuard,
    _credit: Credit,
}
impl InventoryOwner {
    pub(crate) fn pending(&self) -> bool {
        match &self.phase {
            Phase::Search(search) => search.pending(),
            Phase::Metadata(metadata) => match &metadata.phase {
                ReadPhase::Class(read) | ReadPhase::Details { read, .. } => read.pending(),
                _ => false,
            },
            _ => false,
        }
    }
    pub(crate) fn search_claimed(&self) -> bool {
        matches!(&self.phase, Phase::Search(search) if search.claimed())
    }
    fn need(&mut self) -> Result<Option<Need>> {
        Ok(match &mut self.phase {
            Phase::Search(search) => search.need()?.map(Need::Search),
            Phase::Rows(handles) => Some(Need::Rows(handles.len())),
            Phase::Metadata(metadata) => match &metadata.phase {
                ReadPhase::NeedClass => Some(Need::Read {
                    kind: ReadKind::Class,
                    maximum: metadata.remaining,
                }),
                ReadPhase::NeedDetails(class) => Some(Need::Read {
                    kind: ReadKind::Details(*class),
                    maximum: metadata.remaining,
                }),
                ReadPhase::Class(read) | ReadPhase::Details { read, .. } => {
                    read.need().map(Need::Value)
                }
                ReadPhase::Stopped => None,
            },
            _ => None,
        })
    }
    fn complete(&self) -> bool {
        matches!(self.phase, Phase::Complete(_))
    }
    fn advance(&mut self, session: &Session, access: &SessionAccess<'_>) -> Result<()> {
        loop {
            context(session, Some(self.epoch), self.epoch)?;
            match &mut self.phase {
                Phase::Search(search) => {
                    // Keep the child in its parent during dispatch and unwind.
                    search.advance(session, access)?;
                    if !search.complete() {
                        return Ok(());
                    }
                    let Phase::Search(search) = std::mem::replace(&mut self.phase, Phase::Stopped)
                    else {
                        unreachable!()
                    };
                    let handles = search.into_collection()?;
                    // Keep the completed search resident while preparing its
                    // row table and stable-order index outside possession.
                    self.phase = Phase::Rows(handles);
                }
                Phase::Rows(_) => return Ok(()),
                Phase::Metadata(metadata) => {
                    if metadata.index == metadata.handles.len() {
                        metadata::sort(&mut metadata.rows, &mut metadata.order)?;
                        let rows = std::mem::take(&mut metadata.rows);
                        self.phase = Phase::Complete(rows);
                        continue;
                    }
                    let handle = metadata.handles[metadata.index];
                    match &mut metadata.phase {
                        ReadPhase::NeedClass | ReadPhase::NeedDetails(_) => return Ok(()),
                        ReadPhase::Class(read) | ReadPhase::Details { read, .. } => {
                            read.advance(session, access, handle)?;
                            if !read.complete() {
                                return Ok(());
                            }
                        }
                        ReadPhase::Stopped => {
                            return Err(Error::Rejected(crate::RejectionReason::ObjectSearch(
                                crate::ObjectSearchRejection::InventoryMetadataPhase,
                            )))
                        }
                    }
                    match std::mem::replace(&mut metadata.phase, ReadPhase::Stopped) {
                        ReadPhase::Class(read) => {
                            let identity = read.required_result(session, access)?;
                            let raw = identity.bytes(CKA_CLASS)?;
                            let class = ManagedClass::from_raw(CK_ULONG::from_ne_bytes(
                                raw.try_into().map_err(|_| {
                                    Error::Rejected(crate::RejectionReason::ObjectSearch(
                                        crate::ObjectSearchRejection::IntegerAttributeWidth,
                                    ))
                                })?,
                            ));
                            metadata.remaining = metadata.remaining.checked_sub(raw.len()).ok_or(
                                Error::Rejected(crate::RejectionReason::ObjectSearch(
                                    crate::ObjectSearchRejection::InventoryByteQuota,
                                )),
                            )?;
                            metadata.phase = ReadPhase::NeedDetails(class);
                        }
                        ReadPhase::Details { class, read } => {
                            let values = read.public_result(session, access)?;
                            let row = values.map_retaining(&mut self._credit, |values| {
                                metadata::row(class, true, values, &mut metadata.remaining)
                            })?;
                            metadata.rows.push(row);
                            metadata.index += 1;
                            metadata.phase = ReadPhase::NeedClass;
                        }
                        _ => unreachable!("completed read phase"),
                    }
                }
                Phase::Complete(_) => return Ok(()),
                Phase::Stopped => {
                    return Err(Error::Rejected(crate::RejectionReason::ObjectSearch(
                        crate::ObjectSearchRejection::InventoryPhase,
                    )))
                }
            }
        }
    }
    fn attach(&mut self, session: &Session, need: Need, candidate: Candidate) -> Result<()> {
        if self.need()? != Some(need) {
            return Err(Error::Rejected(crate::RejectionReason::ObjectSearch(
                crate::ObjectSearchRejection::InventoryContinuationChanged,
            )));
        }
        match (&mut self.phase, candidate) {
            (Phase::Search(search), Candidate::Search(value)) => search.attach(value),
            (
                phase @ Phase::Rows(_),
                Candidate::Rows {
                    rows,
                    order,
                    mut credit,
                },
            ) => {
                let Need::Rows(count) = need else {
                    return Err(Error::Rejected(crate::RejectionReason::ObjectSearch(
                        crate::ObjectSearchRejection::InventoryRowsNeed,
                    )));
                };
                if !rows.is_empty()
                    || !order.is_empty()
                    || rows.capacity() < count
                    || order.capacity() < count
                {
                    return Err(Error::Rejected(crate::RejectionReason::ObjectSearch(
                        crate::ObjectSearchRejection::InventoryRowsCapacity,
                    )));
                }
                self._credit.merge_retained(&mut credit)?;
                let Phase::Rows(handles) = std::mem::replace(phase, Phase::Stopped) else {
                    unreachable!("inventory row preparation checked")
                };
                *phase = Phase::Metadata(Metadata {
                    handles,
                    rows,
                    order,
                    remaining: self.plan.maximum_bytes,
                    index: 0,
                    phase: ReadPhase::NeedClass,
                });
                Ok(())
            }
            (Phase::Metadata(metadata), Candidate::Value(value)) => match &mut metadata.phase {
                ReadPhase::Class(read) | ReadPhase::Details { read, .. } => {
                    let Need::Value(need) = need else {
                        return Err(Error::Rejected(crate::RejectionReason::ObjectSearch(
                            crate::ObjectSearchRejection::InventoryValueNeed,
                        )));
                    };
                    read.attach(need, value)
                }
                _ => Err(Error::Rejected(crate::RejectionReason::ObjectSearch(
                    crate::ObjectSearchRejection::InventoryReadPhase,
                ))),
            },
            (
                Phase::Metadata(metadata),
                Candidate::Read {
                    storage,
                    mut credit,
                },
            ) => {
                let Need::Read { kind, maximum } = need else {
                    return Err(Error::Rejected(crate::RejectionReason::ObjectSearch(
                        crate::ObjectSearchRejection::InventoryReadNeed,
                    )));
                };
                let handle = metadata.handles[metadata.index];
                let read = with_recipe(kind, maximum, self.plan.clarification, |recipe| {
                    storage.bind_inventory(
                        &mut credit,
                        recipe,
                        handle,
                        Some(self.epoch),
                        session,
                        &self._inventory,
                    )
                })?;
                metadata.phase = match kind {
                    ReadKind::Class => ReadPhase::Class(read),
                    ReadKind::Details(class) => ReadPhase::Details { class, read },
                };
                Ok(())
            }
            _ => Err(Error::Rejected(crate::RejectionReason::ObjectSearch(
                crate::ObjectSearchRejection::InventoryCandidateKind,
            ))),
        }
    }
    fn finish_search(&mut self, session: &Session, access: &SessionAccess<'_>) -> Result<()> {
        match &mut self.phase {
            Phase::Search(search) => search.finish(session, access),
            _ => Ok(()),
        }
    }
    fn result(self, session: &Session, access: &SessionAccess<'_>) -> Result<Vec<ObjectMetadata>> {
        let Phase::Complete(rows) = self.phase else {
            return Err(Error::Rejected(crate::RejectionReason::ObjectSearch(
                crate::ObjectSearchRejection::InventoryIncomplete,
            )));
        };
        let guarded = rows.iter().any(
            |row| !matches!(&row.private, AttributeValue::Available(value) if value == &[CK_FALSE]),
        );
        // The catalogue protection is still live during this final validation.

        session.metadata_result(access, guarded.then_some(self.epoch), Ok(rows))
    }
}

fn with_recipe<T>(
    kind: ReadKind,
    maximum: usize,
    clarification: crate::AttributeClarification,
    action: impl FnOnce(Recipe<'_>) -> Result<T>,
) -> Result<T> {
    match kind {
        ReadKind::Class => action(Recipe::Required {
            fields: &[CKA_CLASS],
            maximum,
        }),
        ReadKind::Details(class) => {
            let fields = metadata::fields(class, true);
            action(Recipe::Public {
                fields: fields.as_slice(),
                plan: crate::AttributeReadPlan {
                    maximum_bytes: maximum,
                    clarification,
                },
            })
        }
    }
}
enum Candidate {
    Search(SearchCandidate),
    Rows {
        rows: Vec<ObjectMetadata>,
        order: Vec<usize>,
        credit: Credit,
    },
    Read {
        storage: ReadStorage,
        credit: Credit,
    },
    Value(crate::attributes::owned::resident::ValueCandidate),
}
fn prepare(
    need: Need,
    waiter: &Waiting<'_>,
    policy: &crate::ResourceAdmission,
    clarification: crate::AttributeClarification,
) -> Result<Candidate> {
    match need {
        Need::Rows(count) => {
            let mut required = row_bytes(count, count)?;
            loop {
                let mut credit = match waiter.budget().reserve_controlled_retaining(
                    required,
                    crate::session::lifecycle_diagnostics::Store::allocation_bytes(),
                    policy,
                    || {
                        waiter.check()?;
                        Ok(None::<()>)
                    },
                    || Ok(None),
                )? {
                    ControlledReservation::Acquired(credit) => credit,
                    ControlledReservation::Redirect(()) => unreachable!("no redirect"),
                };
                let mut rows = Vec::new();
                rows.try_reserve_exact(count).map_err(|_| {
                    Error::Rejected(crate::RejectionReason::ObjectSearch(
                        crate::ObjectSearchRejection::InventoryMetadataAllocation,
                    ))
                })?;
                let mut order = Vec::new();
                order.try_reserve_exact(count).map_err(|_| {
                    Error::Rejected(crate::RejectionReason::ObjectSearch(
                        crate::ObjectSearchRejection::InventorySortAllocation,
                    ))
                })?;
                let actual = row_bytes(rows.capacity(), order.capacity())?;
                if actual > required {
                    drop((rows, order));
                    drop(credit);
                    required = actual;
                    continue;
                }
                credit.release(required - actual);
                return Ok(Candidate::Rows {
                    rows,
                    order,
                    credit,
                });
            }
        }
        Need::Search(need) => {
            match SearchCandidate::prepare(need, waiter.budget(), policy, || {
                waiter.check()?;
                Ok(None::<()>)
            })? {
                SearchPreparation::Ready(value) => Ok(Candidate::Search(value)),
                SearchPreparation::Redirect(()) => unreachable!("no redirect"),
            }
        }
        Need::Value(need) => {
            crate::attributes::owned::resident::prepare_value(need, waiter.budget(), policy, || {
                waiter.check()
            })
            .map(Candidate::Value)
        }
        Need::Read { kind, maximum } => {
            let mut required = with_recipe(kind, maximum, clarification, ReadStorage::requested)?;
            loop {
                let mut credit = match waiter.budget().reserve_controlled_retaining(
                    required,
                    crate::session::lifecycle_diagnostics::Store::allocation_bytes(),
                    policy,
                    || {
                        waiter.check()?;
                        Ok(None::<()>)
                    },
                    || Ok(None),
                )? {
                    ControlledReservation::Acquired(credit) => credit,
                    ControlledReservation::Redirect(()) => unreachable!("no redirect"),
                };
                let storage = with_recipe(kind, maximum, clarification, ReadStorage::allocate)?;
                let actual = storage.allocated_bytes()?;
                if actual > required {
                    drop(storage);
                    drop(credit);
                    required = actual;
                    continue;
                }
                credit.release(required - actual);
                return Ok(Candidate::Read { storage, credit });
            }
        }
    }
}

fn row_bytes(rows: usize, indices: usize) -> Result<usize> {
    rows.checked_mul(std::mem::size_of::<ObjectMetadata>())
        .and_then(|bytes| {
            indices
                .checked_mul(std::mem::size_of::<usize>())
                .and_then(|more| bytes.checked_add(more))
        })
        .ok_or(Error::Rejected(crate::RejectionReason::ObjectSearch(
            crate::ObjectSearchRejection::InventoryMetadataSize,
        )))
}

pub(super) fn observe(
    session: &Session,
    plan: crate::AttributeReadPlan,
    search: SearchPlan,
) -> Result<Vec<ObjectMetadata>> {
    let epoch = session.snapshot.authentication_stamp();
    let policy = crate::admission_wait::current();
    let progress = AdmissionProgress::default();
    let template = Template::new();
    let inventory_bytes = mutations::PreparedInventory::allocation_bytes()?;
    let fixed = Prepared::allocation_bytes()
        .checked_add(std::mem::size_of::<InventoryOwner>())
        .and_then(|n| n.checked_add(crate::error::PreparedCleanupDiagnostic::allocation_bytes()))
        .and_then(|bytes| bytes.checked_add(inventory_bytes))
        .ok_or(Error::Rejected(crate::RejectionReason::ObjectSearch(
            crate::ObjectSearchRejection::InventoryStorageSize,
        )))?;
    let mut required = SearchStorage::requested(&template, search)?
        .checked_add(fixed)
        .ok_or(Error::Rejected(crate::RejectionReason::ObjectSearch(
            crate::ObjectSearchRejection::InventoryStorageSize,
        )))?;
    let (mut search_cleanup, coordination, first_access) = loop {
        context(session, Some(epoch), epoch)?;
        policy.check_available()?;
        session.admission().check_available()?;
        let mut credit =
            crate::advanced::reserve_preparation_with_progress(session, required, &progress)?;
        let storage = SearchStorage::allocate(&template, search)?;
        let actual = storage
            .allocated_bytes()?
            .checked_add(fixed)
            .ok_or(Error::Rejected(crate::RejectionReason::ObjectSearch(
                crate::ObjectSearchRejection::InventoryStorageSize,
            )))?;
        if actual > required {
            drop(storage);
            drop(credit);
            required = actual;
            continue;
        }
        credit.release(required - actual);
        credit.observation_budget()?;
        let search_cleanup = crate::error::PreparedCleanupDiagnostic::prepare(&mut credit)?;
        let registry = Prepared::allocate(&session.inner.symmetric_budget, &mut credit)?;
        let inventory = mutations::PreparedInventory::from_prepaid(session, &mut credit)?;
        let access = match session.try_operation_access_progress(false, &progress) {
            Ok(access) => access,
            Err(Error::Busy(_)) => {
                drop(search_cleanup);
                drop(storage);
                drop(registry);
                drop(inventory);
                drop(credit);
                drop(session.access_progress(&progress)?);
                continue;
            }
            Err(error) => return Err(error),
        };
        context(session, Some(epoch), epoch)?;
        SearchOwner::check_functions(&access)?;
        session
            .entry
            .recovery
            .observations
            .check_search_available()?;
        let inventory = inventory.publish(session)?;
        let owner = InventoryOwner {
            phase: Phase::Search(storage.bind(search, epoch, &access, &mut credit)?),
            plan,
            epoch,
            _inventory: inventory,
            _credit: credit.split(std::mem::size_of::<InventoryOwner>())?,
        };
        let coordination = session
            .entry
            .recovery
            .observations
            .publish(registry.bind_inventory(owner))?;
        break (search_cleanup, coordination, access);
    };
    let waiter = Waiting::new(session, coordination, Some(epoch), epoch);
    let search_open = std::cell::Cell::new(false);
    let _withdrawal = search::SearchWithdrawal::new(session, &search_open);
    let mut access = Some(first_access);
    let result = (|| loop {
        waiter.check()?;
        let owned_access =
            access
                .take()
                .ok_or(Error::Rejected(crate::RejectionReason::ObjectSearch(
                    crate::ObjectSearchRejection::InventoryPossessionAbsent,
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
                crate::ObjectSearchRejection::InventoryOwnerAbsent,
            )))?
            .inventory_mut()?;
        search_open.set(owner.search_claimed());
        let advanced = owner.advance(session, &owned_access);
        search_open.set(owner.search_claimed() && owner.pending());
        advanced?;
        if owner.complete() {
            let owner = payload
                .take()
                .expect("complete inventory")
                .into_inventory()?;
            return owner.result(session, &owned_access);
        }
        let need = owner
            .need()?
            .ok_or(Error::Rejected(crate::RejectionReason::ObjectSearch(
                crate::ObjectSearchRejection::InventoryResourceNeedAbsent,
            )))?;
        drop(payload);
        drop(slot);
        drop(owned_access);
        loop {
            let candidate = prepare(need, &waiter, &policy, plan.clarification)?;
            let resumed = match session.try_operation_access_progress(false, &progress) {
                Ok(access) => access,
                Err(Error::Busy(_)) => {
                    drop(candidate);
                    drop(session.access_progress(&progress)?);
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
                    crate::ObjectSearchRejection::InventoryOwnerAbsent,
                )))?
                .inventory_mut()?
                .attach(session, need, candidate)?;
            drop(payload);
            drop(slot);
            access = Some(resumed);
            break;
        }
    })();
    drop(access);
    let result = crate::managed::search::finish_failed_search(
        session,
        &waiter.coordination,
        &search_open,
        result,
        &mut search_cleanup,
        None,
        || session.try_advanced_access_progress(&progress),
        |owner, access| {
            let owner = owner.inventory_mut()?;
            let cleanup = owner.finish_search(session, access);
            search_open.set(owner.search_claimed() && owner.pending());
            cleanup
        },
    );
    result
}
