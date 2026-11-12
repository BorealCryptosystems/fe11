// SPDX-License-Identifier: Apache-2.0
//! All known derivation observation graphs are admitted before possession.
use super::*;
use crate::destination_controls::DestinationIdentity;

fn add(a: usize, b: usize) -> Result<usize> {
    a.checked_add(b)
        .ok_or(Error::Rejected(crate::RejectionReason::KeyDerivation(
            crate::KeyDerivationRejection::DerivationObservationGraphSize,
        )))
}
pub(in crate::crypto::derivation) struct Initial {
    cleanup: crate::error::CleanupStorage,
    parent: Option<observation::Initial>,
    destination: DestinationInitial,
    child: Option<ReadStorage>,
    output: output_observation::Initial,
    reference: SelectedInitial,
    parent_control: ParentControl,
    child_selection: HistoryObservationPlan,
}
impl Initial {
    pub(in crate::crypto::derivation) fn fixed_bytes() -> Result<usize> {
        add(
            add(
                Prepared::allocation_bytes(),
                std::mem::size_of::<DerivationOwner>(),
            )?,
            MutationProtection::allocation_bytes()
                + crate::managed::NativeIdentity::allocation_bytes(),
        )
    }
    pub(in crate::crypto::derivation) fn requested(
        parent: ParentSelection,
        child: &HistoryObservationPlan,
        output: output_observation::Spec<'_>,
        admission: &crate::ObjectAdmission,
        id: &[u8],
        label: &[u8],
    ) -> Result<usize> {
        let identity = DestinationIdentity::KeyOrCertificate {
            class: ManagedClass::SecretKey,
            id,
            label,
        };
        let mut bytes = add(
            observation::Initial::requested(parent.shape())?,
            DestinationInitial::requested(&admission.destination, &identity)?,
        )?;
        if child.field_iter().next().is_some() {
            bytes = add(bytes, ReadStorage::requested(Recipe::History(*child))?)?;
        }
        bytes = add(bytes, output_observation::Initial::requested(output)?)?;
        bytes = add(bytes, crate::error::CleanupStorage::requested(1)?)?;
        add(
            bytes,
            SelectedInitial::requested(ManagedClass::SecretKey, admission)?,
        )
    }
    pub(in crate::crypto::derivation) fn allocate(
        parent: ParentSelection,
        child: &HistoryObservationPlan,
        output: output_observation::Spec<'_>,
        admission: &crate::ObjectAdmission,
        id: &[u8],
        label: &[u8],
    ) -> Result<Self> {
        let identity = DestinationIdentity::KeyOrCertificate {
            class: ManagedClass::SecretKey,
            id,
            label,
        };
        Ok(Self {
            parent: Some(observation::Initial::allocate(parent.shape())?),
            cleanup: crate::error::CleanupStorage::allocate(1)?,
            destination: DestinationInitial::allocate(&admission.destination, &identity)?,
            child: if child.field_iter().next().is_some() {
                Some(ReadStorage::allocate(Recipe::History(*child))?)
            } else {
                None
            },
            output: output_observation::Initial::allocate(output)?,
            reference: SelectedInitial::allocate(ManagedClass::SecretKey, admission)?,
            parent_control: parent.owned(),
            child_selection: child.clone(),
        })
    }
    pub(in crate::crypto::derivation) fn allocated_bytes(&self) -> Result<usize> {
        let mut bytes = add(
            self.parent
                .as_ref()
                .ok_or(Error::Rejected(crate::RejectionReason::KeyDerivation(
                    crate::KeyDerivationRejection::ParentObservationPreparationAbsent,
                )))?
                .allocated_bytes()?,
            self.destination.allocated_bytes()?,
        )?;
        bytes = add(
            bytes,
            self.child
                .as_ref()
                .map(ReadStorage::allocated_bytes)
                .transpose()?
                .unwrap_or(0),
        )?;
        bytes = add(bytes, self.output.allocated_bytes()?)?;
        bytes = add(bytes, self.cleanup.allocated_bytes()?)?;
        add(bytes, self.reference.allocated_bytes()?)
    }
    pub(in crate::crypto::derivation) fn publish<'a>(
        mut self,
        session: &Session,
        access: SessionAccess<'a>,
        call: DeriveCall,
        reservation: &crate::managed::Reservation,
        parent_handle: CK_OBJECT_HANDLE,
        admission: crate::ObjectAdmission,
        mut permit: crate::registry::Reservation<crate::managed::NativeIdentity>,
        epoch: u64,
        registry: Prepared,
        mut prepaid: Credit,
    ) -> Result<(
        Arc<crate::session::recovery::observations::Coordination>,
        SessionAccess<'a>,
        crate::error::PreparedCleanupStorage,
    )> {
        // These results outlive the later-declared local access on refusal.
        // The parent graph and registry use retained transfers until commit.
        let cleanup;
        let creation;
        let protection;
        let parent;
        let owner_credit;
        let publication;
        let mut registry = Some(registry);
        let access = access;
        cleanup = crate::error::PreparedCleanupStorage::bind(self.cleanup, &mut prepaid)?;
        creation = reservation.prepare_creation_ticket(session)?;
        protection = MutationProtection::take(session, &access, &mut prepaid)?;
        parent = observation::Initial::bind_mutation_retained(
            &mut self.parent,
            parent_handle,
            epoch,
            &protection,
            &mut prepaid,
        )?;
        owner_credit = prepaid.split(std::mem::size_of::<DerivationOwner>())?;
        publication =
            crate::managed::SinglePublication::prepare(session, epoch, &mut permit, &mut prepaid)?;
        let owner = DerivationOwner {
            publication,
            phase: Phase::Parent(Box::new(parent)),
            native: Native::Prepared { call, creation },
            destination: Some(self.destination),
            child: self.child,
            child_selection: self.child_selection,
            output: Some(self.output),
            reference: Some(self.reference),
            permit: Some(permit),
            admission,
            parent_control: self.parent_control,
            epoch,
            protection,
            prepaid,
            _credit: owner_credit,
        };
        registry = Some(
            registry
                .take()
                .expect("derivation registry preparation")
                .bind_derivation(owner),
        );
        let coordination = session
            .entry
            .recovery
            .observations
            .publish_retained(&mut registry)?;
        Ok((coordination, access, cleanup))
    }
}
