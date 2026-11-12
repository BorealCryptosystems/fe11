// SPDX-License-Identifier: Apache-2.0
//! One admission for unpublished creation bookkeeping and destination activities.
//!
//! Borrowed operands, creation bookkeeping, activities and shared close capacity
//! join one preparation. No new sibling credit survives a wait for another
//! sibling. A catalogue race discards the entire unpublished preparation before
//! planning against the new live activities.
use super::{identity_parts::PreparedParts, origins::CreationAllocation, Destination, Reservation};
use crate::{registry::Activity, symmetric::memory::Credit, Error, ManagedClass, Result, Session};
use std::{mem::size_of, sync::Arc};

/// Local identity operands only: no allocation, admission or native alias claim.
#[derive(Clone, Copy, PartialEq, Eq)]
pub(crate) struct DestinationRecipe<'a> {
    pub(super) slot: fe11_sys::CK_SLOT_ID,
    pub(super) generation: u64,
    pub(super) class: Option<fe11_sys::CK_OBJECT_CLASS>,
    pub(super) parts: [Option<&'a [u8]>; 3],
}

impl<'a> DestinationRecipe<'a> {
    pub(crate) fn token_scope(session: &Session) -> Self {
        Self {
            slot: session.entry.slot,
            generation: session.snapshot.generation,
            class: None,
            parts: [None, None, None],
        }
    }

    pub(super) fn with_parts(
        session: &Session,
        class: ManagedClass,
        parts: [Option<&'a [u8]>; 3],
    ) -> Result<Self> {
        // Extension callers can supply Other(u64) directly. Preserve the full
        // identifier until this ABI boundary: truncation could reserve the
        // destination of an unrelated class on a 32-bit CK_ULONG platform.
        let class = fe11_sys::CK_OBJECT_CLASS::try_from(class.identifier()).map_err(|_| {
            Error::Rejected(crate::RejectionReason::ObjectMutation(
                crate::ObjectMutationRejection::DestinationClassExceedsNativeWidth,
            ))
        })?;
        Ok(Self {
            slot: session.entry.slot,
            generation: session.snapshot.generation,
            class: Some(class),
            parts,
        })
    }

    pub(crate) fn new(session: &Session, class: ManagedClass, parts: &[&'a [u8]]) -> Result<Self> {
        let expected = if class == ManagedClass::Data { 3 } else { 1 };
        if parts.len() != expected {
            return Err(Error::Rejected(crate::RejectionReason::ObjectMutation(
                crate::ObjectMutationRejection::DestinationClassTupleShape,
            )));
        }
        let mut selected = [None, None, None];
        for (target, source) in selected.iter_mut().zip(parts) {
            *target = Some(*source);
        }
        Self::with_parts(session, class, selected)
    }

    pub(super) fn class_scope(session: &Session, class: ManagedClass) -> Result<Self> {
        if matches!(class, ManagedClass::Other(_)) {
            return Err(Error::Rejected(crate::RejectionReason::ObjectMutation(
                crate::ObjectMutationRejection::UnknownClassSelectionContract,
            )));
        }
        Self::with_parts(session, class, [None, None, None])
    }

    pub(super) fn matches(&self, key: &Destination) -> bool {
        self.slot == key.slot
            && self.generation == key.generation
            && self.class == key.class
            && self
                .parts
                .iter()
                .copied()
                .eq(key.parts.iter().map(Option::as_deref))
    }
}

// A descriptor preserves logical component boundaries while allowing an ID
// to remain split across caller storage and an inline digest until admission.
pub(crate) trait DestinationOperands {
    fn head(&self) -> (fe11_sys::CK_SLOT_ID, u64, Option<fe11_sys::CK_OBJECT_CLASS>);
    fn operands(&self) -> [Option<crate::attributes::ByteParts<'_>>; 3];
    fn matches_destination(&self, key: &Destination) -> bool {
        self.head() == (key.slot, key.generation, key.class)
            && self.operands().into_iter().eq(key
                .parts
                .iter()
                .map(|part| part.as_deref().map(crate::attributes::ByteParts::from)))
    }
}
impl DestinationOperands for DestinationRecipe<'_> {
    fn head(&self) -> (fe11_sys::CK_SLOT_ID, u64, Option<fe11_sys::CK_OBJECT_CLASS>) {
        (self.slot, self.generation, self.class)
    }
    fn operands(&self) -> [Option<crate::attributes::ByteParts<'_>>; 3] {
        self.parts
            .map(|part| part.map(crate::attributes::ByteParts::from))
    }
}
pub(crate) struct PublicImportDestination<'a> {
    recipe: DestinationRecipe<'a>,
    id: crate::attributes::ByteParts<'a>,
}
impl<'a> PublicImportDestination<'a> {
    pub(crate) fn new(session: &Session, id: crate::attributes::ByteParts<'a>) -> Result<Self> {
        Ok(Self {
            recipe: DestinationRecipe::with_parts(
                session,
                ManagedClass::PublicKey,
                [None, None, None],
            )?,
            id,
        })
    }
}
impl DestinationOperands for PublicImportDestination<'_> {
    fn head(&self) -> (fe11_sys::CK_SLOT_ID, u64, Option<fe11_sys::CK_OBJECT_CLASS>) {
        self.recipe.head()
    }
    fn operands(&self) -> [Option<crate::attributes::ByteParts<'_>>; 3] {
        [Some(self.id), None, None]
    }
}

// Equal byte components may share immutable storage, including unchanged fields
// of a renamed data object. This never establishes native handle aliasing.
fn previous_part(
    recipes: &[impl DestinationOperands],
    index: usize,
    part: usize,
) -> Option<(usize, usize)> {
    let value = recipes[index].operands()[part]?;
    for (previous, recipe) in recipes[..=index].iter().enumerate() {
        let operands = recipe.operands();
        let end = if previous == index {
            part
        } else {
            operands.len()
        };
        if let Some(component) = operands[..end]
            .iter()
            .position(|bytes| *bytes == Some(value))
        {
            return Some((previous, component));
        }
    }
    None
}
fn unique_parts(
    recipes: &[impl DestinationOperands],
    index: usize,
) -> [Option<crate::attributes::ByteParts<'_>>; 3] {
    std::array::from_fn(|part| {
        if previous_part(recipes, index, part).is_some() {
            None
        } else {
            recipes[index].operands()[part]
        }
    })
}

struct DestinationAllocation<'a> {
    parts: Vec<PreparedParts<'a>>,
    keys: Vec<Destination>,
}

impl<'a> DestinationAllocation<'a> {
    fn requested(recipes: &[impl DestinationOperands]) -> Result<usize> {
        (0..recipes.len()).try_fold(
            array_bytes::<PreparedParts<'_>>(recipes.len())?,
            |sum, index| {
                add(
                    sum,
                    PreparedParts::requested_parts(unique_parts(recipes, index))?,
                )
            },
        )
    }

    fn allocate(recipes: &'a [impl DestinationOperands]) -> Result<Self> {
        let mut parts = Vec::new();
        parts.try_reserve_exact(recipes.len()).map_err(|_| {
            Error::Rejected(crate::RejectionReason::ObjectMutation(
                crate::ObjectMutationRejection::DestinationPreparationAllocation,
            ))
        })?;
        let mut keys = Vec::new();
        keys.try_reserve_exact(recipes.len()).map_err(|_| {
            Error::Rejected(crate::RejectionReason::ObjectMutation(
                crate::ObjectMutationRejection::ReservationDestinationAllocation,
            ))
        })?;
        for index in 0..recipes.len() {
            parts.push(PreparedParts::allocate_parts(unique_parts(recipes, index))?);
        }
        Ok(Self { parts, keys })
    }

    fn allocated_bytes(&self) -> Result<usize> {
        self.parts.iter().try_fold(
            array_bytes::<PreparedParts<'_>>(self.parts.capacity())?,
            |sum, parts| add(sum, parts.allocated_bytes()),
        )
    }

    fn bind(
        mut self,
        recipes: &'a [impl DestinationOperands],
        prepaid: &mut Credit,
    ) -> Result<Vec<Destination>> {
        for (index, (recipe, prepared)) in recipes.iter().zip(self.parts).enumerate() {
            let mut parts = prepared.bind(prepaid)?;
            for part in 0..parts.len() {
                if let Some((previous, component)) = previous_part(recipes, index, part) {
                    parts[part] = if previous == index {
                        parts[component].clone()
                    } else {
                        self.keys[previous].parts[component].clone()
                    };
                }
            }
            self.keys.push(Destination {
                slot: recipe.head().0,
                generation: recipe.head().1,
                class: recipe.head().2,
                parts,
            });
        }
        Ok(self.keys)
    }
}

fn activity_bytes() -> Result<usize> {
    Activity::allocation_bytes(size_of::<Destination>() + size_of::<std::sync::Weak<Activity>>())
}

pub(super) fn selection_activity_in_context(
    session: &Session,
    recipe: DestinationRecipe<'_>,
    progress: &crate::session::AdmissionProgress,
    epoch: Option<u64>,
) -> Result<Arc<Activity>> {
    let before = || match epoch {
        Some(epoch) => crate::session::recovery::observations::context(session, Some(epoch), epoch),
        None => crate::advanced::preparation_context(session),
    };
    before()?;
    {
        let catalog = session
            .inner
            .reservations
            .lock()
            .map_err(|_| Error::Poisoned)?;
        if catalog.broken {
            return Err(Error::Poisoned);
        }
        if let Some(live) = catalog
            .destination_activities
            .iter()
            .find(|(key, _)| recipe.matches(key))
            .and_then(|(_, weak)| weak.upgrade())
        {
            return Ok(live);
        }
    }
    let activity_bytes = activity_bytes()?;
    let mut required = add(PreparedParts::requested(recipe.parts)?, activity_bytes)?;
    let (parts, mut prepaid) = loop {
        let prepaid = match epoch {
            Some(epoch) => {
                crate::advanced::reserve_preparation_at_epoch(session, required, progress, epoch)?
            }
            None => {
                crate::advanced::reserve_preparation_with_progress(session, required, progress)?
            }
        };
        let parts = PreparedParts::allocate(recipe.parts)?;
        let actual = add(parts.allocated_bytes(), activity_bytes)?;
        if actual > required {
            drop(parts);
            drop(prepaid);
            required = actual;
            continue;
        }
        break (parts, prepaid);
    };
    let destination = Destination {
        slot: recipe.slot,
        generation: recipe.generation,
        class: recipe.class,
        parts: parts.bind(&mut prepaid)?,
    };
    let prepared = Arc::new(Activity::from_credit(prepaid.split(activity_bytes)?));
    drop(prepaid);
    before()?;
    let mut catalog = session
        .inner
        .reservations
        .lock()
        .map_err(|_| Error::Poisoned)?;
    if catalog.broken {
        return Err(Error::Poisoned);
    }
    if let Some(live) = catalog
        .destination_activities
        .get(&destination)
        .and_then(std::sync::Weak::upgrade)
    {
        // Losing candidates retire after the catalogue guard on every exit.
        drop(catalog);
        drop((destination, prepared));
        return Ok(live);
    }
    catalog
        .destination_activities
        .retain(|_, weak| weak.strong_count() > 0);
    catalog.destination_activities.try_reserve(1).map_err(|_| {
        Error::Rejected(crate::RejectionReason::ReferenceRegistry(
            crate::ReferenceRegistryRejection::ObjectActivityAllocation,
        ))
    })?;
    catalog
        .destination_activities
        .insert(destination, Arc::downgrade(&prepared));
    drop(catalog);
    Ok(prepared)
}

fn missing_activities(session: &Session, keys: &[impl DestinationOperands]) -> Result<usize> {
    let catalog = session
        .inner
        .reservations
        .lock()
        .map_err(|_| Error::Poisoned)?;
    if catalog.broken {
        return Err(Error::Poisoned);
    }
    // This is only a sizing hint. Publication upgrades and pins every existing
    // activity, then either supplies all missing activities or replans.
    Ok(keys
        .iter()
        .filter(|key| {
            catalog
                .destination_activities
                .iter()
                .find(|(owned, _)| key.matches_destination(owned))
                .map_or(true, |(_, entry)| entry.strong_count() == 0)
        })
        .count())
}

/// Declared before a private creation candidate, so error/unwind drops its
/// owners first. Successful returned owners keep their Activity alive and are
/// never removed. Explicit retire also runs before availability/readmission.
pub(crate) struct DestinationRetirement<'a> {
    session: &'a Session,
}

impl<'a> DestinationRetirement<'a> {
    pub(crate) fn new(session: &'a Session) -> Self {
        Self { session }
    }

    /// Pure admission observation under a quota/byte Wake. Never wait for the
    /// catalogue: its existing publishers can release credits while owning it.
    /// Redirecting on contention lets that owner finish after Wake is released.
    /// No Activity is upgraded and no credited key is cloned or destroyed here.
    pub(crate) fn current(&self) -> Result<bool> {
        let catalog = match self.session.inner.reservations.try_lock() {
            Ok(catalog) => catalog,
            Err(std::sync::TryLockError::WouldBlock) => return Ok(false),
            Err(std::sync::TryLockError::Poisoned(_)) => return Err(Error::Poisoned),
        };
        if catalog.broken {
            return Err(Error::Poisoned);
        }
        Ok(!catalog
            .destination_activities
            .values()
            .any(|activity| activity.strong_count() == 0))
    }

    pub(crate) fn retire(&self) {
        // The byte budget is shared across destinations. Reclaim every dead
        // cache entry, including a key belonging to a contender waiting for
        // our reference quota; restricting this to our recipes could preserve
        // the cross-destination resource cycle. Live Activities remain pinned.
        // Bound this destructor pass by the observed catalogue size. Concurrent
        // publishers cannot extend it indefinitely; admission rechecks current
        // afterwards and performs another pass if newly dead entries remain.
        let entries = self
            .session
            .inner
            .reservations
            .lock()
            .unwrap_or_else(|error| error.into_inner())
            .destination_activities
            .len();
        for _ in 0..entries {
            let retired = {
                // Reclamation grants no admission. Recovering the contents of
                // a poisoned lock does not clear its poison or admit an operation.
                let mut catalog = self
                    .session
                    .inner
                    .reservations
                    .lock()
                    .unwrap_or_else(|error| error.into_inner());
                let key = catalog
                    .destination_activities
                    .iter()
                    .find(|(_, activity)| activity.strong_count() == 0)
                    .map(|(key, _)| key.clone());
                // The temporary lookup key only clones immutable Arc components;
                // the removed entry pins them until after the catalogue unlocks.
                key.and_then(|key| catalog.destination_activities.remove_entry(&key))
            };
            // Last SharedBytes/Credit destruction may notify a byte waiter whose
            // predicate accesses the catalogue. It must happen outside its lock.
            match retired {
                Some(entry) => drop(entry),
                None => break,
            }
        }
    }
}

impl Drop for DestinationRetirement<'_> {
    fn drop(&mut self) {
        self.retire();
    }
}

/// Recheck borrowed destinations after discarding a private creation candidate.
/// The catalogue lock leaves before waiting, and the selected Activity already
/// belongs to another live owner. No reference quota or destination candidate
/// is held while its writer/readers drain. A vanished activity needs no wait.
pub(crate) fn wait_available(
    session: &Session,
    recipes: &[impl DestinationOperands],
    admission: &crate::ResourceAdmission,
    before: impl Fn() -> Result<()>,
) -> Result<()> {
    for recipe in recipes {
        before()?;
        let (activity, wake) = {
            let catalog = session
                .inner
                .reservations
                .lock()
                .map_err(|_| Error::Poisoned)?;
            if catalog.broken {
                return Err(Error::Poisoned);
            }
            let activity = catalog
                .destination_activities
                .iter()
                .find(|(key, _)| recipe.matches_destination(key))
                .and_then(|(_, weak)| weak.upgrade());
            (activity, catalog.scan_wake())
        };
        if let Some(activity) = activity {
            activity.wait_operation_writer_in_context(&wake, admission, &before)?;
        }
    }
    Ok(())
}

fn add(left: usize, right: usize) -> Result<usize> {
    left.checked_add(right)
        .ok_or(Error::Rejected(crate::RejectionReason::ObjectMutation(
            crate::ObjectMutationRejection::ReservationPreparationSize,
        )))
}

fn vector_bytes(capacity: usize) -> Result<usize> {
    capacity
        .checked_mul(size_of::<Arc<Activity>>())
        .ok_or(Error::Rejected(crate::RejectionReason::ObjectMutation(
            crate::ObjectMutationRejection::ReservationActivityVectorSize,
        )))
}

fn array_bytes<T>(capacity: usize) -> Result<usize> {
    capacity.checked_mul(size_of::<T>()).ok_or(Error::Rejected(
        crate::RejectionReason::ObjectMutation(
            crate::ObjectMutationRejection::ReservationVectorSize,
        ),
    ))
}

fn coordination_bytes(key_capacity: usize, key_count: usize, activities: usize) -> Result<usize> {
    let keys_bytes = array_bytes::<Destination>(key_capacity)?;
    let permits = array_bytes::<crate::registry::WritePermit>(key_count)?;
    add(add(keys_bytes, vector_bytes(activities)?)?, permits)
}

/// All operands are borrowed. No session/native possession is held here.
pub(super) fn prepare(
    session: &Session,
    recipes: &[DestinationRecipe<'_>],
    count: usize,
) -> Result<Reservation> {
    let progress = crate::session::AdmissionProgress::default();
    prepare_grouped(
        session,
        recipes,
        count,
        || crate::advanced::preparation_context(session),
        || {},
        |required, current| {
            crate::advanced::reserve_preparation_while(session, required, &progress, current)
                .map(|credit| credit.map(|credit| ((), credit)))
        },
    )
    .map(|(reservation, ())| reservation)
}

/// Prepare destinations and a companion from the same byte admission. The
/// callback owns the companion's quota/bytes; it returns only the destination
/// share as Credit. A sizing or catalogue race discards both before reentry.
/// `current` invalidates a creator-close size snapshot during admission.
pub(crate) fn prepare_grouped<T>(
    session: &Session,
    recipes: &[impl DestinationOperands],
    count: usize,
    before: impl Fn() -> Result<()>,
    mut retire_before_replan: impl FnMut(),
    mut reserve: impl FnMut(usize, &dyn Fn() -> Result<bool>) -> Result<Option<(T, Credit)>>,
) -> Result<(Reservation, T)> {
    session.snapshot.check()?;
    if recipes.iter().enumerate().any(|(index, recipe)| {
        recipes[..index].iter().any(|previous| {
            previous.head() == recipe.head() && previous.operands() == recipe.operands()
        })
    }) {
        return Err(Error::Rejected(crate::RejectionReason::ObjectMutation(
            crate::ObjectMutationRejection::ObjectDestinationReserved,
        )));
    }
    let admission = crate::admission_wait::current();
    'recipe: loop {
        before()?;
        // A prior companion and all its credits have left before this hook.
        // Generation may now detach keys whose last Activity died during its
        // wait or allocation; the ordinary wrapper needs no extra retirement.
        retire_before_replan();
        let close_plan = session.entry.creator_close.plan(
            count,
            &session.inner.symmetric_budget,
            &admission,
            &before,
        )?;
        let missing = missing_activities(session, recipes)?;
        let activities_bytes = missing
            .checked_mul(activity_bytes()?)
            .ok_or(Error::Rejected(crate::RejectionReason::ObjectMutation(
                crate::ObjectMutationRejection::ReservationActivityStorageSize,
            )))?;
        let mut required = add(
            add(
                add(
                    CreationAllocation::requested_bytes(recipes.len(), count)?,
                    close_plan.requested_bytes()?,
                )?,
                activities_bytes,
            )?,
            add(
                coordination_bytes(recipes.len(), recipes.len(), recipes.len())?,
                add(
                    vector_bytes(missing)?,
                    DestinationAllocation::requested(recipes)?,
                )?,
            )?,
        )?;
        let (destinations, creation, close_storage, mut pool, mut selected, mut prepaid, companion) = loop {
            let Some((companion, prepaid)) = reserve(required, &|| close_plan.current())? else {
                continue 'recipe;
            };
            let destinations = DestinationAllocation::allocate(recipes)?;
            let creation = CreationAllocation::allocate(recipes.len(), count)?;
            let close_storage = close_plan.allocate()?;
            let mut pool = Vec::<Arc<Activity>>::new();
            pool.try_reserve_exact(missing).map_err(|_| {
                Error::Rejected(crate::RejectionReason::ObjectMutation(
                    crate::ObjectMutationRejection::ReservationActivityAllocation,
                ))
            })?;
            let mut selected = Vec::<Arc<Activity>>::new();
            selected.try_reserve_exact(recipes.len()).map_err(|_| {
                Error::Rejected(crate::RejectionReason::ObjectMutation(
                    crate::ObjectMutationRejection::ReservationActivityAllocation,
                ))
            })?;
            let creation_bytes = creation
                .as_ref()
                .map(CreationAllocation::allocated_bytes)
                .transpose()?
                .unwrap_or(0);
            let actual = add(
                add(
                    add(creation_bytes, close_storage.allocated_bytes()?)?,
                    activities_bytes,
                )?,
                add(
                    coordination_bytes(
                        destinations.keys.capacity(),
                        recipes.len(),
                        selected.capacity(),
                    )?,
                    add(
                        vector_bytes(pool.capacity())?,
                        destinations.allocated_bytes()?,
                    )?,
                )?,
            )?;
            if actual > required {
                drop((
                    destinations,
                    creation,
                    close_storage,
                    pool,
                    selected,
                    companion,
                ));
                drop(prepaid);
                required = actual;
                continue;
            }
            break (
                destinations,
                creation,
                close_storage,
                pool,
                selected,
                prepaid,
                companion,
            );
        };
        // Every stable Arc and creation slot is made after the whole amount was
        // admitted. The remaining path contains no byte-budget admission.
        let mut keys = destinations.bind(recipes, &mut prepaid)?;
        keys.sort_unstable();
        for _ in 0..missing {
            pool.push(Arc::new(Activity::from_credit(
                prepaid.split(activity_bytes()?)?,
            )));
        }
        let creation = creation
            .map(|storage| storage.bind(session, &mut prepaid))
            .transpose()?;
        let metadata_bytes = coordination_bytes(keys.capacity(), keys.len(), selected.capacity())?;
        let metadata = prepaid.split(metadata_bytes)?;
        let close_prepared = close_storage.bind(&mut prepaid)?;
        let Some(close) = close_plan.commit(close_prepared)? else {
            drop((keys, creation, selected, pool, metadata, companion));
            drop(prepaid);
            continue;
        };
        if !publish(session, &keys, &mut pool, &mut selected)? {
            // A previously live activity disappeared during preparation. No
            // destination has been reserved and no C call has occurred.
            drop((keys, creation, selected, pool, metadata, close, companion));
            drop(prepaid);
            continue;
        }
        // Publication checked all fallible catalogue conditions. Keep only the
        // durable coordination bytes; scratch vectors and unused Arc candidates
        // retire outside the catalogue lock.
        drop(pool);
        drop(prepaid);
        let reservation = Reservation {
            close: std::sync::Mutex::new(close),
            creation: std::sync::Mutex::new(creation),
            inner: session.inner.clone(),
            keys,
            activities: selected,
            metadata: Some(metadata),
        };

        return Ok((reservation, companion));
    }
}

/// No waits or stable-owner allocations under the catalogue lock. False means
/// the caller must discard its complete preparation and take a fresh snapshot.
fn publish(
    session: &Session,
    keys: &[Destination],
    pool: &mut Vec<Arc<Activity>>,
    selected: &mut Vec<Arc<Activity>>,
) -> Result<bool> {
    let mut catalog = session
        .inner
        .reservations
        .lock()
        .map_err(|_| Error::Poisoned)?;
    publish_catalog(&mut catalog, keys, pool, selected)
}

fn publish_catalog(
    catalog: &mut super::Catalog,
    keys: &[Destination],
    pool: &mut Vec<Arc<Activity>>,
    selected: &mut Vec<Arc<Activity>>,
) -> Result<bool> {
    if catalog.broken {
        return Err(Error::Poisoned);
    }
    let mut missing = 0usize;
    for key in keys {
        let activity = catalog
            .destination_activities
            .get(key)
            .and_then(std::sync::Weak::upgrade);
        let activity = match activity {
            Some(activity) => activity,
            None => match pool.pop() {
                Some(activity) => {
                    missing += 1;
                    activity
                }
                None => return Ok(false),
            },
        };
        // Capacity was prepared for every key before entering the catalogue.
        selected.push(activity);
    }
    catalog
        .destination_activities
        .retain(|_, weak| weak.strong_count() > 0);
    catalog
        .destination_activities
        .try_reserve(missing)
        .map_err(|_| {
            Error::Rejected(crate::RejectionReason::ReferenceRegistry(
                crate::ReferenceRegistryRejection::ObjectActivityAllocation,
            ))
        })?;
    catalog.reserve(keys)?;
    // No fallible step after destination publication.
    for (key, activity) in keys.iter().zip(selected.iter()) {
        catalog
            .destination_activities
            .insert(key.clone(), Arc::downgrade(activity));
    }
    Ok(true)
}
