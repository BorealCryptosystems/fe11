// SPDX-License-Identifier: Apache-2.0
//! Proof retained by a resident metadata/content reader.
//!
//! A reader of an existing reference owns an object permit. A reader following
//! selection owns the same catalogue exclusion as its enclosing search, without
//! introducing a second object-activity admission. The inventory variant shares
//! its real parent owner so an unexpectedly retained child preserves the scan.
use crate::{registry::ReadPermit, symmetric::memory::Credit, Error, Result, Session};
use std::{mem::size_of, sync::Arc};

struct Selection {
    _guard: crate::managed::OwnedSelectionGuard,
    _credit: Credit,
}
enum Owner {
    Object(ReadPermit),
    Selection(Arc<Selection>),
    Mutation(Arc<MutationProtection>),
    Inventory(crate::managed::InventoryGuard),
}
pub(crate) struct ObservationProtection(Owner);
impl ObservationProtection {
    pub(crate) fn object(reader: ReadPermit) -> Self {
        Self(Owner::Object(reader))
    }
    pub(crate) fn inventory(
        session: &Session,
        inventory: &crate::managed::InventoryGuard,
    ) -> Result<Self> {
        if !inventory.belongs_to(&session.inner, session.uid) {
            return Err(Error::Rejected(crate::RejectionReason::SessionLifecycle(
                crate::SessionLifecycleRejection::ForeignInventoryProtection,
            )));
        }
        Ok(Self(Owner::Inventory(inventory.clone())))
    }
    /// Identifies the enclosing inventory for byte-quota diagnostics only.
    /// This borrows the retained protection without granting new authority.
    pub(crate) fn is_inventory(&self) -> bool {
        matches!(&self.0, Owner::Inventory(_))
    }
    pub(crate) fn selection_bytes() -> usize {
        size_of::<Selection>() + 2 * size_of::<usize>()
    }
    pub(crate) fn selection(
        session: &Session,
        guard: crate::managed::OwnedSelectionGuard,
        prepaid: &mut Credit,
    ) -> Result<Self> {
        Self::selection_retained(session, &mut Some(guard), prepaid)
    }

    /// Keep exclusion with the enclosing candidate until credit transfer succeeds.
    pub(crate) fn selection_retained(
        session: &Session,
        guard: &mut Option<crate::managed::OwnedSelectionGuard>,
        prepaid: &mut Credit,
    ) -> Result<Self> {
        let selected =
            guard
                .as_ref()
                .ok_or(Error::Rejected(crate::RejectionReason::SessionLifecycle(
                    crate::SessionLifecycleRejection::ObservationSelectionAbsent,
                )))?;
        if !selected.belongs_to(&session.inner, session.uid) {
            return Err(Error::Rejected(crate::RejectionReason::SessionLifecycle(
                crate::SessionLifecycleRejection::ForeignObservationSelection,
            )));
        }
        let credit = prepaid.split(Self::selection_bytes())?;
        Ok(Self(Owner::Selection(Arc::new(Selection {
            _guard: guard.take().expect("validated observation selection"),
            _credit: credit,
        }))))
    }
    pub(crate) fn duplicate(&self) -> Result<Self> {
        match &self.0 {
            Owner::Object(reader) => reader.duplicate().map(Self::object),
            Owner::Selection(owner) => Ok(Self(Owner::Selection(owner.clone()))),
            Owner::Mutation(owner) => Ok(Self(Owner::Mutation(owner.clone()))),
            Owner::Inventory(owner) => Ok(Self(Owner::Inventory(owner.clone()))),
        }
    }
    pub(crate) fn mutation(owner: &Arc<MutationProtection>) -> Self {
        Self(Owner::Mutation(owner.clone()))
    }
}

/// Original resource roles and destination writers, moved out of possession.
/// No module/session lock or strong module owner is part of this proof.
pub(crate) struct MutationProtection {
    objects: super::ObjectProtections,
    uid: u64,
    _credit: Credit,
}
impl MutationProtection {
    pub(crate) fn allocation_bytes() -> usize {
        size_of::<Self>() + 2 * size_of::<usize>()
    }
    pub(crate) fn take(
        session: &Session,
        access: &super::SessionAccess<'_>,
        prepaid: &mut Credit,
    ) -> Result<Arc<Self>> {
        if !access.owns_session(session) {
            return Err(Error::Rejected(crate::RejectionReason::SessionLifecycle(
                crate::SessionLifecycleRejection::ForeignMutationPossession,
            )));
        }
        let mut objects = access.object_protections()?;
        // Source roles may be explicitly empty for creation/generation. An
        // admitted empty plan is still required; an unprepared access cannot
        // manufacture mutation authority from destination exclusion alone.
        if (objects.resources.is_none() && objects.source_free.is_none())
            || objects.creation.is_none()
        {
            return Err(Error::Rejected(crate::RejectionReason::SessionLifecycle(
                crate::SessionLifecycleRejection::MutationProtectionAbsent,
            )));
        }
        // Keep credit with the caller until every fallible protection check
        // has succeeded. Only the infallible ownership transfer follows.
        let credit = prepaid.split(Self::allocation_bytes())?;
        Ok(Arc::new(Self {
            objects: std::mem::take(&mut *objects),
            uid: session.uid,
            _credit: credit,
        }))
    }
    pub(crate) fn destination_reservation(
        &self,
        session: &Session,
    ) -> Result<&crate::managed::DurableReservation> {
        if self.uid != session.uid {
            return Err(Error::Rejected(crate::RejectionReason::SessionLifecycle(
                crate::SessionLifecycleRejection::ForeignMutationProtection,
            )));
        }
        Ok(&self
            .objects
            .creation
            .as_ref()
            .ok_or(Error::Rejected(crate::RejectionReason::SessionLifecycle(
                crate::SessionLifecycleRejection::MutationProtectionAbsent,
            )))?
            ._reservation)
    }
    pub(crate) fn forget_object(
        &self,
        session: &Session,
        resource: crate::managed::ResourceIdentity,
        activity: &Arc<crate::registry::Activity>,
    ) -> Result<()> {
        if self.uid != session.uid {
            return Err(Error::Rejected(crate::RejectionReason::SessionLifecycle(
                crate::SessionLifecycleRejection::ForeignMutationProtection,
            )));
        }
        self.objects
            .creation
            .as_ref()
            .ok_or(Error::Rejected(crate::RejectionReason::SessionLifecycle(
                crate::SessionLifecycleRejection::MutationProtectionAbsent,
            )))?
            ._reservation
            .forget_object(session, resource, activity)
    }
}
