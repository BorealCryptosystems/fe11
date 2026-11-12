// SPDX-License-Identifier: Apache-2.0
//! Admit all known sibling graphs before retaining session possession.
use super::*;

#[derive(Clone, Copy)]
pub(in crate::managed::mutations) struct Spec<'a> {
    pub(in crate::managed::mutations) class: ManagedClass,
    pub(in crate::managed::mutations) attributes: &'a [crate::AttributeInput<'a>],
    pub(in crate::managed::mutations) destination: &'a DestinationPlan,
    pub(in crate::managed::mutations) admission: Option<&'a ObjectAdmission>,
    pub(in crate::managed::mutations) content: Option<&'a ContentObservation>,
    pub(in crate::managed::mutations) stage: &'static str,
}
impl<'a> Spec<'a> {
    pub(in crate::managed::mutations) fn new(
        class: ManagedClass,
        request: &'a crate::GenerationTemplate<'a>,
        stage: &'static str,
    ) -> Self {
        Self {
            class,
            attributes: request.attributes,
            destination: &request.destination,
            admission: request.observation.as_ref().map(|value| &value.admission),
            content: request.observation.as_ref().map(|value| &value.content),
            stage,
        }
    }
}
fn add(a: usize, b: usize) -> Result<usize> {
    a.checked_add(b)
        .ok_or(Error::Rejected(crate::RejectionReason::ObjectPublication(
            crate::ObjectPublicationRejection::NativeOutputGraphSize,
        )))
}
fn content_plan(content: &ContentObservation) -> Option<ContentReadPlan> {
    match content {
        ContentObservation::NotRequested => None,
        ContentObservation::Observe(read) => Some(*read),
    }
}
pub(in crate::managed::mutations) struct Initial {
    diagnostic: crate::error::CompletionStorage,
    cleanup: crate::error::CleanupStorage,
    slots: Vec<Slot>,
    publication: Vec<crate::NativeObjectRef>,
}
impl Initial {
    fn fixed_bytes() -> Result<usize> {
        add(
            add(
                std::mem::size_of::<OutputsOwner>(),
                Prepared::allocation_bytes(),
            )?,
            add(
                MutationProtection::allocation_bytes(),
                crate::error::CompletionStorage::allocation_bytes(),
            )?,
        )
    }
    pub(in crate::managed::mutations) fn requested<'a>(
        specs: impl IntoIterator<Item = Spec<'a>>,
    ) -> Result<usize> {
        let mut bytes = Self::fixed_bytes()?;
        let mut count = 0usize;
        for spec in specs {
            count = count.checked_add(1).ok_or(Error::Rejected(
                crate::RejectionReason::ObjectPublication(
                    crate::ObjectPublicationRejection::OutputCleanupCount,
                ),
            ))?;
            let identity = InputIdentity::new(spec.class, spec.attributes, None);
            bytes = add(bytes, std::mem::size_of::<Slot>())?;
            bytes = add(bytes, crate::managed::NativeIdentity::allocation_bytes())?;
            bytes = add(bytes, std::mem::size_of::<crate::NativeObjectRef>())?;
            bytes = add(
                bytes,
                DestinationInitial::requested(spec.destination, &identity.identity())?,
            )?;
            bytes = add(
                bytes,
                spec.admission
                    .map(|admission| SelectedInitial::requested(spec.class, admission))
                    .transpose()?
                    .unwrap_or(0),
            )?;
        }
        add(bytes, crate::error::CleanupStorage::requested(count)?)
    }
    pub(in crate::managed::mutations) fn allocate<'a>(
        specs: impl IntoIterator<Item = Spec<'a>>,
    ) -> Result<Self> {
        let specs = specs.into_iter();
        let mut slots = Vec::new();
        slots.try_reserve_exact(specs.size_hint().0).map_err(|_| {
            Error::Rejected(crate::RejectionReason::ObjectPublication(
                crate::ObjectPublicationRejection::NativeOutputSlotAllocation,
            ))
        })?;
        for spec in specs {
            let identity = InputIdentity::new(spec.class, spec.attributes, None);
            slots.push(Slot {
                native: None,
                state: SlotState::Prepared {
                    destination: DestinationInitial::allocate(
                        spec.destination,
                        &identity.identity(),
                    )?,
                    selected: spec
                        .admission
                        .map(|admission| SelectedInitial::allocate(spec.class, admission))
                        .transpose()?,
                },
                class: spec.class,
                admission: spec.admission.cloned(),
                destination: spec.destination.clone(),
                content: ContentObservation::NotRequested,
                content_plan: spec.content.and_then(content_plan),
                stage: spec.stage,
                handle: CK_INVALID_HANDLE,
            });
        }
        if slots.is_empty() {
            return Err(Error::Rejected(crate::RejectionReason::ObjectPublication(
                crate::ObjectPublicationRejection::NativeOutputListEmpty,
            )));
        }
        let mut publication = Vec::new();
        publication.try_reserve_exact(slots.len()).map_err(|_| {
            Error::Rejected(crate::RejectionReason::ObjectPublication(
                crate::ObjectPublicationRejection::NativePublicationAllocation,
            ))
        })?;
        let cleanup = crate::error::CleanupStorage::allocate(slots.len())?;
        Ok(Self {
            cleanup,
            slots,
            publication,
            diagnostic: crate::error::CompletionStorage::allocate()?,
        })
    }
    pub(in crate::managed::mutations) fn allocated_bytes(&self) -> Result<usize> {
        let mut bytes = add(
            add(Self::fixed_bytes()?, self.cleanup.allocated_bytes()?)?,
            self.slots
                .capacity()
                .checked_mul(std::mem::size_of::<Slot>())
                .ok_or(Error::Rejected(crate::RejectionReason::ObjectPublication(
                    crate::ObjectPublicationRejection::NativeOutputSlotSize,
                )))?,
        )?;
        for slot in &self.slots {
            bytes = add(bytes, crate::managed::NativeIdentity::allocation_bytes())?;

            let SlotState::Prepared {
                destination,
                selected,
            } = &slot.state
            else {
                return Err(Error::Rejected(crate::RejectionReason::ObjectPublication(
                    crate::ObjectPublicationRejection::NativeOutputPreparationState,
                )));
            };
            bytes = add(
                add(bytes, destination.allocated_bytes()?)?,
                selected
                    .as_ref()
                    .map(SelectedInitial::allocated_bytes)
                    .transpose()?
                    .unwrap_or(0),
            )?;
        }
        add(
            bytes,
            self.publication
                .capacity()
                .checked_mul(std::mem::size_of::<crate::NativeObjectRef>())
                .ok_or(Error::Rejected(crate::RejectionReason::ObjectPublication(
                    crate::ObjectPublicationRejection::NativePublicationAccounting,
                )))?,
        )
    }
    pub(in crate::managed::mutations) fn publish<'a>(
        mut self,
        session: &Session,
        access: SessionAccess<'a>,
        call: PreparedCall,
        reservation: &crate::managed::Reservation,
        mut permit: crate::registry::Reservation<crate::managed::NativeIdentity>,
        contents: impl IntoIterator<Item = ContentObservation>,
        order: Order,
        epoch: u64,
        registry: Prepared,
        mut prepaid: Credit,
    ) -> Result<(
        Arc<crate::session::recovery::observations::Coordination>,
        SessionAccess<'a>,
        crate::error::PreparedCompletionStorage,
        crate::error::PreparedCleanupStorage,
    )> {
        // Declare all private results before moving access into this scope.
        // On refusal, access leaves first; partially initialized output slots
        // remain in self and the prepared registry retains any complete owner.
        let mut contents = contents.into_iter();
        let diagnostic;
        let cleanup;
        let publication;
        let publication_credit;
        let creation;
        let protection;
        let owner_credit;
        let mut registry = Some(registry);
        let access = access;
        diagnostic =
            crate::error::PreparedCompletionStorage::from_storage(self.diagnostic, &mut prepaid)?;
        cleanup = crate::error::PreparedCleanupStorage::bind(self.cleanup, &mut prepaid)?;
        for slot in &mut self.slots {
            slot.native = Some(crate::managed::NativeIdentity::prepare_creation(
                session,
                epoch,
                &mut permit,
                &mut prepaid,
            )?);
            slot.content = contents.next().ok_or(Error::Rejected(
                crate::RejectionReason::ObjectPublication(
                    crate::ObjectPublicationRejection::NativeOutputContentLayout,
                ),
            ))?;
        }
        if contents.next().is_some() {
            return Err(Error::Rejected(crate::RejectionReason::ObjectPublication(
                crate::ObjectPublicationRejection::NativeOutputContentLayout,
            )));
        }
        publication = self.publication;
        let publication_bytes = publication
            .capacity()
            .checked_mul(std::mem::size_of::<crate::NativeObjectRef>())
            .ok_or(Error::Rejected(crate::RejectionReason::ObjectPublication(
                crate::ObjectPublicationRejection::NativePublicationAccounting,
            )))?;
        publication_credit = prepaid.split(publication_bytes)?;
        creation = reservation.prepare_creation_ticket(session)?;
        protection = MutationProtection::take(session, &access, &mut prepaid)?;
        let bytes = add(
            std::mem::size_of::<OutputsOwner>(),
            self.slots
                .capacity()
                .checked_mul(std::mem::size_of::<Slot>())
                .ok_or(Error::Rejected(crate::RejectionReason::ObjectPublication(
                    crate::ObjectPublicationRejection::NativeOutputSlotSize,
                )))?,
        )?;
        owner_credit = prepaid.split(bytes)?;
        let owner = OutputsOwner {
            publication: Publication::Prepared(publication),
            publication_credit: Some(publication_credit),
            phase: Phase::DestinationReady(0),
            native: Native::Prepared { call, creation },
            slots: self.slots,
            permit: Some(permit),
            order,
            epoch,
            protection,
            prepaid,
            _credit: owner_credit,
        };
        registry = Some(
            registry
                .take()
                .expect("output registry preparation")
                .bind_outputs(owner),
        );
        let coordination = session
            .entry
            .recovery
            .observations
            .publish_retained(&mut registry)?;
        Ok((coordination, access, diagnostic, cleanup))
    }
}
