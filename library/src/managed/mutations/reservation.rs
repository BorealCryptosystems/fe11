// SPDX-License-Identifier: Apache-2.0
//! Transfer mutation reservations into retained operation ownership.
//! Durable reservations use weak module links and release catalog claims on abandonment.

use super::*;

impl Drop for DurableReservation {
    fn drop(&mut self) {
        if let Some(inner) = self.inner.upgrade() {
            let wake = {
                let mut catalog = inner.reservations.lock().unwrap_or_else(|p| p.into_inner());
                catalog.release(&self.keys);
                catalog.scan_wake()
            };
            wake.notify();
        }
    }
}

impl Reservation {
    // The caller keeps its original guard; the retained frame receives a weak
    // counted guard so Inner's session ledger cannot retain Inner recursively.
    pub(crate) fn retain_for_operation(
        &self,
        inner: &Arc<Inner>,
        entry: &crate::module::SessionEntry,
        prepared: &mut Option<PreparedRetention>,
    ) -> Result<(DurableReservation, Vec<crate::registry::WritePermit>)> {
        let candidate =
            prepared
                .as_mut()
                .ok_or(Error::Rejected(crate::RejectionReason::ObjectMutation(
                    crate::ObjectMutationRejection::OperationRetentionAbsent,
                )))?;
        if !Arc::ptr_eq(&self.inner, inner)
            || self
                .keys
                .iter()
                .any(|key| key.slot != entry.slot || key.generation != entry.generation)
        {
            return Err(Error::Rejected(crate::RejectionReason::ObjectMutation(
                crate::ObjectMutationRejection::ForeignOperationReservation,
            )));
        }
        if candidate.keys != self.keys
            || candidate.activities.len() != self.activities.len()
            || !candidate
                .activities
                .iter()
                .zip(&self.activities)
                .all(|(prepared, source)| Arc::ptr_eq(prepared, source))
        {
            return Err(Error::Rejected(crate::RejectionReason::ObjectMutation(
                crate::ObjectMutationRejection::ForeignOperationReservation,
            )));
        }
        if candidate.writers.len() != self.activities.len()
            || !candidate
                .writers
                .iter()
                .zip(&self.activities)
                .all(|(writer, activity)| writer.owns_activity(activity))
        {
            return Err(Error::Rejected(crate::RejectionReason::ObjectMutation(
                crate::ObjectMutationRejection::ForeignOperationReservation,
            )));
        }
        for writer in &mut candidate.writers {
            writer.bind_owner(entry.credit.uid())?;
        }
        let mut catalog = self
            .inner
            .reservations
            .lock()
            .map_err(|_| Error::Poisoned)?;
        if catalog.broken {
            return Err(Error::Poisoned);
        }
        let uid = entry.credit.uid();
        for key in &self.keys {
            if !catalog.occupied.contains(key) {
                return Err(Error::Rejected(crate::RejectionReason::ObjectMutation(
                    crate::ObjectMutationRejection::OperationDestinationChanged,
                )));
            }
            if let Some((owner, count)) = catalog.owned.get(key) {
                if *owner != uid {
                    return Err(Error::Rejected(crate::RejectionReason::ObjectMutation(
                        crate::ObjectMutationRejection::ForeignOperationDestination,
                    )));
                }
                count.checked_add(1).ok_or(Error::Rejected(
                    crate::RejectionReason::ObjectMutation(
                        crate::ObjectMutationRejection::OperationDestinationCount,
                    ),
                ))?;
            }
        }
        catalog.owned.try_reserve(self.keys.len()).map_err(|_| {
            Error::Rejected(crate::RejectionReason::ObjectMutation(
                crate::ObjectMutationRejection::OperationDestinationAllocation,
            ))
        })?;
        for key in &self.keys {
            match catalog.owned.get_mut(key) {
                Some((_, count)) => *count += 1,
                None => {
                    catalog.owned.insert(key.clone(), (uid, 2));
                }
            }
        }
        drop(catalog);
        // Every fallible check precedes taking the candidate. Partial writer
        // attribution stays with its caller on error and is released after access.
        let PreparedRetention {
            keys,
            activities,
            writers,
            metadata,
        } = prepared.take().expect("retention checked before transfer");
        Ok((
            DurableReservation {
                inner: Arc::downgrade(&self.inner),
                keys,
                _activities: activities,
                _metadata: Some(metadata),
            },
            writers,
        ))
    }

    pub(super) fn check_operation_session(&self, session: &Session) -> Result<()> {
        if !Arc::ptr_eq(&self.inner, &session.inner)
            || self.keys.iter().any(|k| {
                k.slot != session.entry.slot || k.generation != session.snapshot.generation
            })
        {
            return Err(Error::Rejected(crate::RejectionReason::ObjectMutation(
                crate::ObjectMutationRejection::ForeignOperationReservation,
            )));
        }
        Ok(())
    }

    /// Keep partial writers in the candidate on contention/error. The caller
    /// releases session guards before discarding this vector or trying again.
    pub(crate) fn try_operation_permits_retained(
        &self,
        session: &Session,
        objects: &mut Vec<crate::registry::WritePermit>,
    ) -> Result<Option<Arc<crate::registry::Activity>>> {
        self.check_operation_session(session)?;
        if !objects.is_empty() || objects.capacity() < self.activities.len() {
            return Err(Error::Rejected(crate::RejectionReason::ObjectMutation(
                crate::ObjectMutationRejection::OperationDestinationAllocation,
            )));
        }
        let policy = crate::admission_wait::current();
        for activity in &self.activities {
            match policy.try_once(|| {
                let permit = activity.write_for_operation_admitted(
                    session.uid,
                    &crate::ResourceAdmission::Immediate,
                )?;
                // Capacity was checked above. Retain ownership before the
                // outer policy's final deadline/cancellation check can fail.
                objects.push(permit);
                Ok(())
            }) {
                Ok(()) => (),
                Err(Error::Busy(crate::BusyReason::ObjectMutation(
                    crate::ObjectMutationBusy::ObjectActivity,
                ))) => {
                    return Ok(Some(activity.clone()));
                }
                Err(error) => {
                    return Err(error);
                }
            }
        }
        Ok(None)
    }

    /// Transfer only after every fallible catalogue check and allocation has
    /// succeeded. On error, the caller still owns this reservation and all its
    /// writers, so an enclosing candidate can release session guards first.
    /// On success, both inputs are empty and the returned owners preserve the
    /// same destination identities and exact writer permits, without reacquiring.
    pub(crate) fn transfer_to_operation(
        &mut self,
        session: &Session,
        objects: &mut Vec<crate::registry::WritePermit>,
    ) -> Result<(DurableReservation, Vec<crate::registry::WritePermit>)> {
        self.check_operation_session(session)?;
        if objects.len() != self.activities.len()
            || !objects
                .iter()
                .zip(&self.activities)
                .all(|(permit, activity)| permit.owns_activity(activity))
        {
            return Err(Error::Rejected(crate::RejectionReason::ObjectMutation(
                crate::ObjectMutationRejection::ForeignOperationReservation,
            )));
        }
        let mut catalog = self
            .inner
            .reservations
            .lock()
            .map_err(|_| Error::Poisoned)?;
        if catalog.broken {
            return Err(Error::Poisoned);
        }
        if self
            .keys
            .iter()
            .any(|k| !catalog.occupied.contains(k) || catalog.owned.contains_key(k))
        {
            return Err(Error::Rejected(crate::RejectionReason::ObjectMutation(
                crate::ObjectMutationRejection::OperationDestinationChanged,
            )));
        }
        catalog.owned.try_reserve(self.keys.len()).map_err(|_| {
            Error::Rejected(crate::RejectionReason::ObjectMutation(
                crate::ObjectMutationRejection::OperationDestinationAllocation,
            ))
        })?;
        for key in &self.keys {
            catalog.owned.insert(key.clone(), (session.uid, 1));
        }
        drop(catalog);
        Ok((
            DurableReservation {
                inner: Arc::downgrade(&self.inner),
                keys: std::mem::take(&mut self.keys),
                _activities: std::mem::take(&mut self.activities),
                _metadata: self.metadata.take(),
            },
            std::mem::take(objects),
        ))
    }

    pub(super) fn new(session: &Session, keys: &[DestinationRecipe<'_>]) -> Result<Self> {
        let count = keys.len();
        Self::with_creation_capacity(session, keys, count)
    }

    pub(super) fn with_creation_capacity(
        session: &Session,
        keys: &[DestinationRecipe<'_>],
        count: usize,
    ) -> Result<Self> {
        reservation_preparation::prepare(session, keys, count)
    }

    // Recover an already admitted owner by value, independently of sorting.
    // Cloning shares its immutable bytes and performs no new admission.
    pub(super) fn destination(&self, recipe: &DestinationRecipe<'_>) -> Result<Destination> {
        self.keys
            .iter()
            .find(|key| recipe.matches(key))
            .cloned()
            .ok_or(Error::Rejected(crate::RejectionReason::ObjectMutation(
                crate::ObjectMutationRejection::DestinationOutsideReservation,
            )))
    }
}

impl Drop for Reservation {
    fn drop(&mut self) {
        // A successful by-value transfer already moved every destination and
        // metadata credit to DurableReservation. The emptied shell must not
        // reenter the catalogue or notify a waiter under the caller's guards.
        if self.keys.is_empty() {
            return;
        }
        let wake = {
            let mut catalog = self
                .inner
                .reservations
                .lock()
                .unwrap_or_else(|p| p.into_inner());
            catalog.release(&self.keys);
            catalog.scan_wake()
        };
        wake.notify();
    }
}
