// SPDX-License-Identifier: Apache-2.0
//! Actual native creations bind a shared handle to their real creator.
//! Application identifiers never establish object identity.
use super::*;
use crate::module::SessionEntry;
mod capacity;
mod preparation;
use capacity::PublicationSlots;
pub(super) use preparation::{CreationAllocation, CreationPreparation};

pub(super) struct Origin {
    _close: CloseParticipant,
    pub(super) creator: Arc<SessionEntry>,
    pub(super) destination: Destination,
    pub(super) destination_activity: Arc<crate::registry::Activity>,
    pub(super) resource_activity: Arc<crate::registry::Activity>,
    visibility: Option<crate::Observation<bool>>,
}
// A reservation is not a native object. It remains separate until a successful
// native creation supplies the application handle for this token generation.
pub(super) struct PendingCreation {
    close: CloseParticipants,
    pub(super) creator: Arc<SessionEntry>,
    authentication: u64,
    pub(super) destination_activity: Arc<crate::registry::Activity>,
    pub(super) resource_activity: Arc<crate::registry::Activity>,
}
fn resource(creator: &SessionEntry, handle: CK_OBJECT_HANDLE) -> ResourceIdentity {
    ResourceIdentity {
        slot: creator.slot,
        generation: creator.snapshot.generation,
        session: creator.credit.uid(),
        handle,
    }
}
/// Prepared before native dispatch. Dropping this ticket does not erase a
/// possibly created object: only confirmed destruction/close frees its record.
pub(crate) struct CreationTicket {
    publication: PublicationSlots,
    inner: std::sync::Weak<Inner>,
    keys: Vec<Destination>,
    creator: std::sync::Weak<SessionEntry>,
    authentication: u64,
    // Keep creation metadata alive even when TOKEN=true removes the session
    // origin before admission/publication or corrective cleanup is finished.
    _resources: Vec<Arc<crate::registry::Activity>>,
    group_resources: Vec<Arc<crate::registry::Activity>>,
    _metadata: crate::symmetric::memory::Credit,
}
pub(crate) enum PreparedCreation {
    Ready {
        ticket: CreationTicket,
        activities: Vec<Arc<crate::registry::Activity>>,
        slots: PendingSlots,
        close: CloseParticipants,
        _metadata: crate::symmetric::memory::Credit,
    },
    Committed,
}

/// Reserved insertion capacity is independent of pending native effects. Drop
/// returns only unused capacity; it never erases a creation/origin record.
pub(crate) struct PendingSlots {
    inner: std::sync::Weak<Inner>,
    remaining: usize,
}
impl PendingSlots {
    fn limit(&mut self, count: usize) -> Result<()> {
        let returned = self.remaining.checked_sub(count).ok_or(Error::Rejected(
            crate::RejectionReason::ObjectCreation(
                crate::ObjectCreationRejection::ObjectCreatorAllocation,
            ),
        ))?;
        if returned == 0 {
            return Ok(());
        }
        let inner =
            self.inner
                .upgrade()
                .ok_or(Error::Rejected(crate::RejectionReason::ObjectCreation(
                    crate::ObjectCreationRejection::CreationOwnerUnavailable,
                )))?;
        let mut catalog = inner.reservations.lock().map_err(|_| Error::Poisoned)?;
        if catalog.broken {
            return Err(Error::Poisoned);
        }
        catalog.pending_reserved =
            catalog
                .pending_reserved
                .checked_sub(returned)
                .ok_or(Error::Rejected(crate::RejectionReason::ObjectCreation(
                    crate::ObjectCreationRejection::ObjectCreatorAllocation,
                )))?;
        self.remaining = count;
        Ok(())
    }

    fn new(inner: &Arc<Inner>, count: usize) -> Result<Self> {
        let mut catalog = inner.reservations.lock().map_err(|_| Error::Poisoned)?;
        if catalog.broken {
            return Err(Error::Poisoned);
        }
        let reserved = catalog
            .pending_reserved
            .checked_add(count)
            .ok_or(Error::Rejected(crate::RejectionReason::ObjectCreation(
                crate::ObjectCreationRejection::ObjectCreatorAllocation,
            )))?;
        catalog
            .pending_creations
            .try_reserve(reserved)
            .map_err(|_| {
                Error::Rejected(crate::RejectionReason::ObjectCreation(
                    crate::ObjectCreationRejection::ObjectCreatorAllocation,
                ))
            })?;
        catalog.pending_reserved = reserved;
        Ok(Self {
            inner: Arc::downgrade(inner),
            remaining: count,
        })
    }
}
impl Drop for PendingSlots {
    fn drop(&mut self) {
        if self.remaining == 0 {
            return;
        }
        if let Some(inner) = self.inner.upgrade() {
            let mut catalog = inner
                .reservations
                .lock()
                .unwrap_or_else(|error| error.into_inner());
            match catalog.pending_reserved.checked_sub(self.remaining) {
                Some(remaining) => catalog.pending_reserved = remaining,
                None => catalog.broken = true,
            }
        }
    }
}

impl PreparedCreation {
    // Begin only after the native vacancy search. Every retained allocation and
    // insertion slot was prepared before the enclosing operation was installed.
    pub(crate) fn begin(&mut self) -> Result<CreationTicket> {
        let Self::Ready {
            ticket,
            activities,
            slots,
            close,
            ..
        } = self
        else {
            return Err(Error::Rejected(crate::RejectionReason::ObjectCreation(
                crate::ObjectCreationRejection::ObjectCreatorAlreadyRecorded,
            )));
        };
        let creator = ticket.creator()?;
        // The caller holds this creator's session gate before any dispatch.
        // Conservatively retain the history even if preparation fails below.
        creator.creation_attempted.store(true, Ordering::Release);
        creator
            .snapshot
            .check_authentication_unchanged(ticket.authentication)?;
        let inner = ticket.inner.upgrade().ok_or(Error::Rejected(
            crate::RejectionReason::ObjectCreation(
                crate::ObjectCreationRejection::CreationOwnerUnavailable,
            ),
        ))?;
        let mut catalog = inner.reservations.lock().map_err(|_| Error::Poisoned)?;
        if catalog.broken {
            return Err(Error::Poisoned);
        }
        if ticket.keys.iter().any(|key| {
            catalog.pending_creations.contains_key(key) || !catalog.occupied.contains(key)
        }) {
            return Err(Error::Rejected(crate::RejectionReason::ObjectCreation(
                crate::ObjectCreationRejection::ObjectCreatorAlreadyRecorded,
            )));
        }
        if slots.remaining != ticket.keys.len()
            || catalog.pending_reserved < slots.remaining
            || catalog
                .pending_creations
                .capacity()
                .saturating_sub(catalog.pending_creations.len())
                < slots.remaining
        {
            return Err(Error::Rejected(crate::RejectionReason::ObjectCreation(
                crate::ObjectCreationRejection::ObjectCreatorAllocation,
            )));
        }
        for ((key, activity), resource_activity) in ticket
            .keys
            .iter()
            .zip(activities.iter())
            .zip(&ticket._resources)
        {
            catalog.pending_creations.insert(
                key.clone(),
                PendingCreation {
                    close: close.split(if ticket.keys.len() == 1 {
                        close.remaining()
                    } else {
                        1
                    })?,
                    creator: creator.clone(),
                    authentication: ticket.authentication,
                    destination_activity: activity.clone(),
                    resource_activity: resource_activity.clone(),
                },
            );
        }
        catalog.pending_reserved -= slots.remaining;
        slots.remaining = 0;
        drop(catalog);
        let Self::Ready { ticket, .. } = std::mem::replace(self, Self::Committed) else {
            unreachable!()
        };
        Ok(ticket)
    }
}
impl Reservation {
    pub(crate) fn forget_object(
        &self,
        session: &Session,
        resource: ResourceIdentity,
        activity: &Arc<crate::registry::Activity>,
    ) -> Result<()> {
        forget_object_in(&self.inner, session, resource, activity)
    }
}

/// A successful rename commits already-owned provenance. The unchanged case
/// includes known token objects, which have no session-creator record to update.
pub(super) enum PreparedRename {
    Unchanged,
    Known {
        inner: std::sync::Weak<Inner>,
        resource: ResourceIdentity,
        creator: std::sync::Weak<SessionEntry>,
        destination: Destination,
        activity: Arc<crate::registry::Activity>,
    },
}

impl PreparedRename {
    pub(super) fn finish(self) -> Result<()> {
        let Self::Known {
            inner,
            resource,
            creator,
            destination,
            activity,
        } = self
        else {
            return Ok(());
        };
        let inner =
            inner
                .upgrade()
                .ok_or(Error::Rejected(crate::RejectionReason::ObjectCreation(
                    crate::ObjectCreationRejection::RenameModuleReleased,
                )))?;
        let mut catalog = inner.reservations.lock().map_err(|_| Error::Poisoned)?;
        if catalog.broken {
            return Err(Error::Poisoned);
        }
        let origin = catalog
            .origins
            .get_mut(&resource.native())
            .ok_or(Error::Rejected(crate::RejectionReason::ObjectCreation(
                crate::ObjectCreationRejection::RenameCreatorUnavailable,
            )))?;
        if !std::sync::Weak::ptr_eq(&Arc::downgrade(&origin.creator), &creator) {
            return Err(Error::Rejected(crate::RejectionReason::ObjectCreation(
                crate::ObjectCreationRejection::RenameCreatorChanged,
            )));
        }
        origin.destination = destination;
        origin.destination_activity = activity;
        Ok(())
    }
}

// Prepared while the native resource is exclusive. No post-return allocation
// or lookup by application identity is needed to update its local knowledge.
pub(super) struct PreparedAttributeMutation {
    inner: std::sync::Weak<Inner>,
    resource: ResourceIdentity,
    activity: Arc<crate::registry::Activity>,
    rename: PreparedRename,
    invalidate_visibility: bool,
}
impl Reservation {
    pub(super) fn prepare_attribute_mutation(
        &self,
        session: &Session,
        identity: &crate::managed::NativeIdentity,
        destination: Option<&Destination>,
        invalidate_visibility: bool,
    ) -> Result<PreparedAttributeMutation> {
        prepare_attribute_mutation_in(
            &self.inner,
            &self.keys,
            &self.activities,
            session,
            identity,
            destination,
            invalidate_visibility,
        )
    }
}
impl PreparedAttributeMutation {
    pub(super) fn finish(self) -> Result<()> {
        if matches!(&self.rename, PreparedRename::Unchanged) && !self.invalidate_visibility {
            return Ok(());
        }
        let inner =
            self.inner
                .upgrade()
                .ok_or(Error::Rejected(crate::RejectionReason::ObjectCreation(
                    crate::ObjectCreationRejection::AttributeMutationModuleReleased,
                )))?;
        let mut guard = inner.reservations.lock().map_err(|_| Error::Poisoned)?;
        let catalog = &mut *guard;
        if catalog.broken {
            return Err(Error::Poisoned);
        }
        let native = self.resource.native();
        let activity = catalog
            .resource_activities
            .get(&native)
            .and_then(|entry| entry.activity.upgrade())
            .ok_or(Error::Rejected(crate::RejectionReason::ObjectCreation(
                crate::ObjectCreationRejection::AttributeMutationActivityUnavailableAfterReturn,
            )))?;
        if !Arc::ptr_eq(&activity, &self.activity) {
            return Err(Error::Rejected(crate::RejectionReason::ObjectCreation(
                crate::ObjectCreationRejection::AttributeMutationActivityChangedAfterReturn,
            )));
        }
        // Validate every fallible condition before changing either cache. The
        // same catalogue lock then covers the complete transfer of knowledge.
        if let PreparedRename::Known {
            inner,
            resource,
            creator,
            ..
        } = &self.rename
        {
            if !std::sync::Weak::ptr_eq(inner, &self.inner) || *resource != self.resource {
                return Err(Error::Rejected(crate::RejectionReason::ObjectCreation(
                    crate::ObjectCreationRejection::AttributeMutationPreparedOriginOwner,
                )));
            }
            let origin = catalog.origins.get(&native).ok_or(Error::Rejected(
                crate::RejectionReason::ObjectCreation(
                    crate::ObjectCreationRejection::AttributeMutationCreatorLostAfterReturn,
                ),
            ))?;
            if !std::sync::Weak::ptr_eq(&Arc::downgrade(&origin.creator), creator) {
                return Err(Error::Rejected(crate::RejectionReason::ObjectCreation(
                    crate::ObjectCreationRejection::AttributeMutationCreatorChangedAfterReturn,
                )));
            }
        }
        if let PreparedRename::Known {
            destination,
            activity,
            ..
        } = self.rename
        {
            let origin = catalog
                .origins
                .get_mut(&native)
                .expect("validated creator record");
            origin.destination = destination;
            origin.destination_activity = activity;
        }
        if self.invalidate_visibility {
            // Unknown is an actual invalidation of prior knowledge here. Using
            // remember_visibility would incorrectly retain an old public value.
            if let Some(origin) = catalog.origins.get_mut(&native) {
                origin.visibility = Some(crate::Observation::NotRequested);
            }
            catalog
                .resource_activities
                .get_mut(&native)
                .expect("validated resource activity")
                .visibility = Some(crate::Observation::NotRequested);
        }
        Ok(())
    }
}

// A creation may have both pending and published catalogue metadata while its
// output is being admitted. Prepay that peak payload with the resource lifetime;
// native-object deletion is not inferred from dropping a public reference.
fn creation_metadata_bytes() -> Result<usize> {
    let metadata = std::mem::size_of::<Origin>()
        .checked_add(std::mem::size_of::<PendingCreation>())
        .and_then(|n| n.checked_add(std::mem::size_of::<Destination>()))
        .and_then(|n| n.checked_add(std::mem::size_of::<NativeObjectIdentity>()))
        .and_then(|n| n.checked_add(std::mem::size_of::<ResourceActivity>()))
        .ok_or(Error::Rejected(crate::RejectionReason::ObjectCreation(
            crate::ObjectCreationRejection::CreationMetadataStorageAccounting,
        )))?;
    Ok(metadata)
}

impl DurableReservation {
    pub(crate) fn forget_object(
        &self,
        session: &Session,
        resource: ResourceIdentity,
        activity: &Arc<crate::registry::Activity>,
    ) -> Result<()> {
        let inner =
            self.inner
                .upgrade()
                .ok_or(Error::Rejected(crate::RejectionReason::ObjectCreation(
                    crate::ObjectCreationRejection::MutationModuleReleased,
                )))?;
        forget_object_in(&inner, session, resource, activity)
    }
}
fn forget_object_in(
    inner: &Arc<Inner>,
    session: &Session,
    resource: ResourceIdentity,
    activity: &Arc<crate::registry::Activity>,
) -> Result<()> {
    if !Arc::ptr_eq(inner, &session.inner)
        || resource.session != session.uid
        || resource.slot != session.entry.slot
        || resource.generation != session.snapshot.generation
    {
        return Err(Error::Rejected(crate::RejectionReason::ObjectCreation(
            crate::ObjectCreationRejection::ForeignForgottenResource,
        )));
    }
    let expected = Arc::downgrade(activity);
    let mut catalog = inner.reservations.lock().map_err(|_| Error::Poisoned)?;
    if catalog.broken {
        return Err(Error::Poisoned);
    }
    // Native creation may reuse the number after Destroy returns, before this
    // local publication. Retire only the object whose writer we still hold.
    // Compare weak identity without upgrading/dropping an Activity under lock.
    if catalog
        .origins
        .get(&resource.native())
        .is_some_and(|origin| Arc::ptr_eq(&origin.resource_activity, activity))
    {
        catalog.origins.remove(&resource.native());
    }
    if catalog
        .resource_activities
        .get(&resource.native())
        .is_some_and(|current| std::sync::Weak::ptr_eq(&current.activity, &expected))
    {
        catalog.resource_activities.remove(&resource.native());
    }
    Ok(())
}

impl DurableReservation {
    pub(super) fn prepare_attribute_mutation(
        &self,
        session: &Session,
        identity: &crate::managed::NativeIdentity,
        destination: Option<&Destination>,
        invalidate_visibility: bool,
    ) -> Result<PreparedAttributeMutation> {
        let inner =
            self.inner
                .upgrade()
                .ok_or(Error::Rejected(crate::RejectionReason::ObjectCreation(
                    crate::ObjectCreationRejection::MutationModuleReleased,
                )))?;
        prepare_attribute_mutation_in(
            &inner,
            &self.keys,
            &self._activities,
            session,
            identity,
            destination,
            invalidate_visibility,
        )
    }
}
fn prepare_attribute_mutation_in(
    inner: &Arc<Inner>,
    keys: &[Destination],
    activities: &[Arc<crate::registry::Activity>],
    session: &Session,
    identity: &crate::managed::NativeIdentity,
    destination: Option<&Destination>,
    invalidate_visibility: bool,
) -> Result<PreparedAttributeMutation> {
    let resource = identity.resource();
    if !Arc::ptr_eq(inner, &session.inner)
        || resource.session != session.uid
        || resource.slot != session.entry.slot
        || resource.generation != session.snapshot.generation
    {
        return Err(Error::Rejected(crate::RejectionReason::ObjectCreation(
            crate::ObjectCreationRejection::AttributeMutationMetadataOwner,
        )));
    }
    let catalog = inner.reservations.lock().map_err(|_| Error::Poisoned)?;
    if catalog.broken {
        return Err(Error::Poisoned);
    }
    let tracked = catalog
        .resource_activities
        .get(&resource.native())
        .and_then(|entry| entry.activity.upgrade())
        .ok_or(Error::Rejected(crate::RejectionReason::ObjectCreation(
            crate::ObjectCreationRejection::AttributeMutationActivityUnavailable,
        )))?;
    if !Arc::ptr_eq(&tracked, identity.activity()?) {
        return Err(Error::Rejected(crate::RejectionReason::ObjectCreation(
            crate::ObjectCreationRejection::AttributeMutationActivityChanged,
        )));
    }
    let rename = match (destination, identity.creator()) {
        (Some(destination), ObjectCreator::Known(creator)) => {
            let origin = catalog
                .origins
                .get(&resource.native())
                .ok_or(Error::Rejected(crate::RejectionReason::ObjectCreation(
                    crate::ObjectCreationRejection::AttributeMutationCreatorUnavailable,
                )))?;
            if !std::sync::Weak::ptr_eq(&Arc::downgrade(&origin.creator), creator) {
                return Err(Error::Rejected(crate::RejectionReason::ObjectCreation(
                    crate::ObjectCreationRejection::AttributeMutationCreatorChanged,
                )));
            }
            let position =
                keys.iter()
                    .position(|key| key == destination)
                    .ok_or(Error::Rejected(crate::RejectionReason::ObjectCreation(
                        crate::ObjectCreationRejection::AttributeMutationDestinationReservation,
                    )))?;
            // Compare neither requested values nor an omitted observation to
            // the actual creation record. A generic identity change needs a
            // conservative destination even if the old reference omitted ID.
            PreparedRename::Known {
                inner: Arc::downgrade(inner),
                resource,
                creator: creator.clone(),
                destination: destination.try_clone()?,
                activity: Arc::clone(&activities[position]),
            }
        }
        _ => PreparedRename::Unchanged,
    };
    Ok(PreparedAttributeMutation {
        inner: Arc::downgrade(inner),
        resource,
        activity: tracked,
        rename,
        invalidate_visibility,
    })
}

impl DurableReservation {
    pub(super) fn prepare_rename(
        &self,
        session: &Session,
        id: &ManagedIdentity,
        destination: &Destination,
    ) -> Result<PreparedRename> {
        let inner =
            self.inner
                .upgrade()
                .ok_or(Error::Rejected(crate::RejectionReason::ObjectCreation(
                    crate::ObjectCreationRejection::MutationModuleReleased,
                )))?;
        prepare_rename_in(
            &inner,
            &self.keys,
            &self._activities,
            session,
            id,
            destination,
        )
    }
}
fn prepare_rename_in(
    inner: &Arc<Inner>,
    keys: &[Destination],
    activities: &[Arc<crate::registry::Activity>],
    session: &Session,
    id: &ManagedIdentity,
    destination: &Destination,
) -> Result<PreparedRename> {
    if destination.matches_identity(session, id)
        || id
            .properties
            .observation(crate::ObjectBooleanAttribute::Token)
            == crate::Observation::Observed(true)
    {
        return Ok(PreparedRename::Unchanged);
    }
    let ObjectCreator::Known(creator) = &id.creator else {
        return Ok(PreparedRename::Unchanged);
    };
    let catalog = inner.reservations.lock().map_err(|_| Error::Poisoned)?;
    if catalog.broken {
        return Err(Error::Poisoned);
    }
    let position = keys
        .iter()
        .position(|key| key == destination)
        .ok_or(Error::Rejected(crate::RejectionReason::ObjectCreation(
            crate::ObjectCreationRejection::RenameDestinationReservation,
        )))?;
    let origin = catalog
        .origins
        .get(&id.resource().native())
        .ok_or(Error::Rejected(crate::RejectionReason::ObjectCreation(
            crate::ObjectCreationRejection::RenameCreatorUnavailable,
        )))?;
    if !std::sync::Weak::ptr_eq(&Arc::downgrade(&origin.creator), creator) {
        return Err(Error::Rejected(crate::RejectionReason::ObjectCreation(
            crate::ObjectCreationRejection::RenameCreatorChanged,
        )));
    }
    Ok(PreparedRename::Known {
        inner: Arc::downgrade(inner),
        resource: id.resource(),
        creator: creator.clone(),
        destination: destination.try_clone()?,
        activity: Arc::clone(&activities[position]),
    })
}

mod binding;
pub(super) use binding::check_creation_for_cleanup;
pub(crate) use binding::check_creator;
pub(crate) use binding::forget_created_handle;
pub(crate) use binding::forget_creator;
pub(crate) use binding::forget_private_origins;
pub(crate) use binding::object_creator;
