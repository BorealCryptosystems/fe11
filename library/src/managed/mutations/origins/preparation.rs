// SPDX-License-Identifier: Apache-2.0
//! All known creation bookkeeping is prepared before session/object guards.
use super::{CreationTicket, PendingSlots, PreparedCreation, PublicationSlots, Reservation};
use crate::{
    managed::mutations::Destination, registry::Activity, symmetric::memory::Credit, Error, Result,
    Session,
};
use std::{mem::size_of, sync::Arc};

/// A ticket is staged before possession and transferred only when its native
/// owner is assembled. Taking a staged ticket performs no allocation or split.
pub(in crate::managed::mutations) enum CreationPreparation {
    Storage(CreationStorage),
    Ticket(PreparedCreation),
}

pub(in crate::managed::mutations) struct CreationStorage {
    publication: PublicationSlots,
    keys: Vec<Destination>,
    activities: Vec<Arc<Activity>>,
    selected: Vec<Arc<Activity>>,
    resources: Vec<Arc<Activity>>,
    slots: PendingSlots,
    activity_credit: Credit,
    credit: Credit,
}
/// Unpublished vectors with no Activity, insertion slot or credit of their own.
/// Their actual capacities join the enclosing reservation's single admission.
pub(in crate::managed::mutations) struct CreationAllocation {
    keys: Vec<Destination>,
    activities: Vec<Arc<Activity>>,
    selected: Vec<Arc<Activity>>,
    resources: Vec<Arc<Activity>>,
    key_count: usize,
    outputs: usize,
}

impl CreationAllocation {
    fn bytes(
        keys: usize,
        activities: usize,
        selected: usize,
        resources: usize,
        outputs: usize,
    ) -> Result<usize> {
        let activity = Activity::allocation_bytes(super::creation_metadata_bytes()?)?;
        let fixed = outputs
            .checked_mul(activity)
            .and_then(|bytes| bytes.checked_add(size_of::<CreationPreparation>()))
            .ok_or(Error::Rejected(crate::RejectionReason::ObjectCreation(
                crate::ObjectCreationRejection::CreationMetadataStorageAccounting,
            )))?;
        [
            (keys, size_of::<Destination>()),
            (activities, size_of::<Arc<Activity>>()),
            (selected, size_of::<Arc<Activity>>()),
            (resources, size_of::<Arc<Activity>>()),
        ]
        .into_iter()
        .try_fold(fixed, |sum, (count, width)| {
            count
                .checked_mul(width)
                .and_then(|bytes| sum.checked_add(bytes))
                .ok_or(Error::Rejected(crate::RejectionReason::ObjectCreation(
                    crate::ObjectCreationRejection::CreationMetadataStorageAccounting,
                )))
        })
    }

    pub(in crate::managed::mutations) fn requested_bytes(
        keys: usize,
        outputs: usize,
    ) -> Result<usize> {
        if outputs == 0 {
            return Ok(0);
        }
        Self::bytes(keys, keys, keys, outputs, outputs)
    }

    pub(in crate::managed::mutations) fn allocate(
        keys: usize,
        outputs: usize,
    ) -> Result<Option<Self>> {
        if outputs == 0 {
            return Ok(None);
        }
        Self::requested_bytes(keys, outputs)?;
        let mut storage = Self {
            keys: Vec::new(),
            activities: Vec::new(),
            selected: Vec::new(),
            resources: Vec::new(),
            key_count: keys,
            outputs,
        };
        storage.keys.try_reserve_exact(keys).map_err(|_| {
            Error::Rejected(crate::RejectionReason::ObjectCreation(
                crate::ObjectCreationRejection::CoordinationCopyAllocation,
            ))
        })?;
        storage.activities.try_reserve_exact(keys).map_err(|_| {
            Error::Rejected(crate::RejectionReason::ObjectCreation(
                crate::ObjectCreationRejection::CoordinationCopyAllocation,
            ))
        })?;
        storage.selected.try_reserve_exact(keys).map_err(|_| {
            Error::Rejected(crate::RejectionReason::ObjectCreation(
                crate::ObjectCreationRejection::CreationActivityAllocation,
            ))
        })?;
        storage.resources.try_reserve_exact(outputs).map_err(|_| {
            Error::Rejected(crate::RejectionReason::ObjectCreation(
                crate::ObjectCreationRejection::CreationActivityAllocation,
            ))
        })?;
        Ok(Some(storage))
    }

    pub(in crate::managed::mutations) fn allocated_bytes(&self) -> Result<usize> {
        Self::bytes(
            self.keys.capacity(),
            self.activities.capacity(),
            self.selected.capacity(),
            self.resources.capacity(),
            self.outputs,
        )
    }

    /// This only splits the complete preparation's prepaid credit. There is no
    /// resource wait once stable Activities or catalogue slots exist.
    pub(in crate::managed::mutations) fn bind(
        mut self,
        session: &Session,
        prepaid: &mut Credit,
    ) -> Result<CreationPreparation> {
        let mut credit = prepaid.split(self.allocated_bytes()?)?;
        let activity_bytes = Activity::allocation_bytes(super::creation_metadata_bytes()?)?;
        for _ in 0..self.outputs {
            self.resources.push(Arc::new(Activity::from_credit(
                credit.split(activity_bytes)?,
            )));
        }
        // Split all private metadata credit while this candidate is still
        // unguarded. Ticket selection later transfers it without a new split.
        let activity_bytes = self
            .activities
            .capacity()
            .checked_mul(size_of::<Arc<Activity>>())
            .and_then(|bytes| bytes.checked_add(size_of::<CreationPreparation>()))
            .ok_or(Error::Rejected(crate::RejectionReason::ObjectCreation(
                crate::ObjectCreationRejection::CreationMetadataStorageAccounting,
            )))?;
        let activity_credit = credit.split(activity_bytes)?;
        let slots = PendingSlots::new(&session.inner, self.key_count)?;
        let publication = PublicationSlots::new(&session.inner, self.outputs)?;
        Ok(CreationPreparation::Storage(CreationStorage {
            publication,
            keys: self.keys,
            activities: self.activities,
            selected: self.selected,
            resources: self.resources,
            slots,
            activity_credit,
            credit,
        }))
    }
}

impl Reservation {
    /// Resolve the creation subset before session/object possession. Copy can
    /// reserve both source and destination while creating only at destination.
    /// Other callers select all destinations, independently of output count.
    pub(in crate::managed::mutations) fn prepare_creation_before_access(
        &mut self,
        session: &Session,
        destination: Option<super::super::reservation_preparation::DestinationRecipe<'_>>,
    ) -> Result<()> {
        let keys = match destination {
            Some(recipe) => {
                std::slice::from_ref(self.keys.iter().find(|key| recipe.matches(key)).ok_or(
                    Error::Rejected(crate::RejectionReason::ObjectCreation(
                        crate::ObjectCreationRejection::CreationDestination,
                    )),
                )?)
            }
            None => self.keys.as_slice(),
        };
        let prepared = self.prepare_selected_creation(session, keys)?;
        // Exclusive reservation ownership precedes its Arc publication and all
        // possession probes. No consumer can observe the transient empty slot.
        *self.creation.get_mut().map_err(|_| Error::Poisoned)? =
            Some(CreationPreparation::Ticket(prepared));
        Ok(())
    }

    pub(crate) fn prepare_creation_ticket(&self, session: &Session) -> Result<PreparedCreation> {
        self.prepare_selected_creation(session, &self.keys)
    }
    pub(crate) fn creation(&self, session: &Session) -> Result<CreationTicket> {
        self.prepare_creation_ticket(session)?.begin()
    }
    pub(in crate::managed::mutations) fn prepare_creation_at(
        &self,
        session: &Session,
        key: &Destination,
    ) -> Result<PreparedCreation> {
        self.prepare_selected_creation(session, std::slice::from_ref(key))
    }
    fn prepare_selected_creation(
        &self,
        session: &Session,
        keys: &[Destination],
    ) -> Result<PreparedCreation> {
        if !Arc::ptr_eq(&self.inner, &session.inner)
            || keys.is_empty()
            || keys.iter().any(|key| !self.keys.contains(key))
        {
            return Err(Error::Rejected(crate::RejectionReason::ObjectCreation(
                crate::ObjectCreationRejection::ForeignCreationReservation,
            )));
        }
        // Keep the candidate inside its reservation until every fallible step
        // succeeds. A caller may still hold session access: destroying private
        // resources here on refusal would precede release of that access.
        let mut preparation = self.creation.lock().map_err(|_| Error::Poisoned)?;
        let candidate =
            preparation
                .as_mut()
                .ok_or(Error::Rejected(crate::RejectionReason::ObjectCreation(
                    crate::ObjectCreationRejection::CreationPreparationAlreadyConsumed,
                )))?;
        let storage = match candidate {
            CreationPreparation::Ticket(prepared) => {
                let PreparedCreation::Ready { ticket, .. } = prepared else {
                    return Err(Error::Rejected(crate::RejectionReason::ObjectCreation(
                        crate::ObjectCreationRejection::CreationPreparationAlreadyConsumed,
                    )));
                };
                if ticket.keys != keys || !ticket.creator.ptr_eq(&Arc::downgrade(&session.entry)) {
                    return Err(Error::Rejected(crate::RejectionReason::ObjectCreation(
                        crate::ObjectCreationRejection::ForeignCreationReservation,
                    )));
                }
                let Some(CreationPreparation::Ticket(prepared)) = preparation.take() else {
                    unreachable!("validated staged creation ticket");
                };
                return Ok(prepared);
            }
            CreationPreparation::Storage(storage) => storage,
        };
        if keys.len() > storage.keys.capacity()
            || keys.len() > storage.activities.capacity()
            || keys.len() > storage.selected.capacity()
            || keys.len() > storage.resources.len()
        {
            return Err(Error::Rejected(crate::RejectionReason::ObjectCreation(
                crate::ObjectCreationRejection::CreationDestination,
            )));
        }
        for key in keys {
            let position = self
                .keys
                .iter()
                .position(|candidate| candidate == key)
                .ok_or(Error::Rejected(crate::RejectionReason::ObjectCreation(
                    crate::ObjectCreationRejection::CreationDestination,
                )))?;
            if position >= self.activities.len() {
                return Err(Error::Rejected(crate::RejectionReason::ObjectCreation(
                    crate::ObjectCreationRejection::CreationDestination,
                )));
            }
        }
        storage.slots.limit(keys.len())?;
        let mut close = self.close.lock().map_err(|_| Error::Poisoned)?;
        let count = if keys.len() == 1 {
            close.remaining()
        } else {
            keys.len()
        };
        if count < keys.len() {
            return Err(Error::Rejected(crate::RejectionReason::ObjectCleanup(
                crate::ObjectCleanupRejection::CreatorParticipantReservationExhausted,
            )));
        }
        let close = close.split(count)?;

        // From here onward only infallible moves and Arc clones remain. Both
        // reservation keys and activities are immutable; the validated mapping
        // cannot change while transferring the uniquely held preparation.
        let Some(CreationPreparation::Storage(mut storage)) = preparation.take() else {
            unreachable!("validated creation storage");
        };
        drop(preparation);
        for (index, key) in keys.iter().enumerate() {
            let position = self
                .keys
                .iter()
                .position(|candidate| candidate == key)
                .expect("validated creation destination");
            storage.keys.push(key.clone());
            storage.activities.push(self.activities[position].clone());
            storage.selected.push(storage.resources[index].clone());
        }
        Ok(PreparedCreation::Ready {
            ticket: CreationTicket {
                publication: storage.publication,
                inner: Arc::downgrade(&session.inner),
                keys: storage.keys,
                creator: Arc::downgrade(&session.entry),
                authentication: session.snapshot.authentication_stamp(),
                _resources: storage.selected,
                group_resources: storage.resources,
                _metadata: storage.credit,
            },
            activities: storage.activities,
            slots: storage.slots,
            close,
            _metadata: storage.activity_credit,
        })
    }
}
