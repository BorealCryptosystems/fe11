// SPDX-License-Identifier: Apache-2.0
//! Label mutation preserves its own observation and republication order.
use super::*;
use crate::{
    attribute_values::InputTemplate,
    attributes::owned::resident::{LegacyOwner, ReadStorage, Recipe, ValueNeed},
    destination_controls::resident::{DestinationOwner, Initial as DestinationInitial},
    managed::discovery::{self, preparation::SelectedInitial, DiscoveryOwner},
    reference_controls::resident::{
        self as reference, preparation::Initial as ReferenceInitial, ReferenceOwner,
    },
    session::{
        observation_protection::{MutationProtection, ObservationProtection},
        recovery::observations::{context, Prepared, Waiting},
        SessionAccess,
    },
    symmetric::memory::Credit,
};
use search::{SearchCandidate, SearchNeed, SearchPreparation, SearchWithdrawal};

enum Phase {
    Reference(Box<ReferenceOwner>),
    NeedDestination(crate::ObjectReferenceReport),
    Destination {
        reference: crate::ObjectReferenceReport,
        read: Box<DestinationOwner>,
    },
    Before {
        reference: crate::ObjectReferenceReport,
        destination: crate::DestinationReport,
        read: LegacyOwner,
    },
    Ready {
        destination: crate::DestinationReport,
        before: crate::ObjectMutationReport,
    },
    After {
        destination: crate::DestinationReport,
        before: crate::ObjectMutationReport,
        read: LegacyOwner,
    },
    Admission {
        destination: crate::DestinationReport,
        mutation: crate::ObjectMutationReport,
        read: Box<DiscoveryOwner>,
    },
    Stopped,
}
#[derive(Clone, Copy)]
enum Effect {
    BeforeDispatch,
    InFlight,
    Returned {
        code: CK_RV,
        storage_returned: bool,
        local_failure: bool,
    },
}
impl Effect {
    fn pending(self) -> bool {
        matches!(
            self,
            Self::InFlight
                | Self::Returned {
                    storage_returned: false,
                    ..
                }
        )
    }
    fn succeeded(self) -> bool {
        matches!(self, Self::Returned { code: CKR_OK, .. })
    }
}
struct FutureStorage {
    template: Option<generic::PreparedSetInput>,
    class: Option<attributes::ClassReadStorage>,
    destination: Option<DestinationInitial>,
    before: Option<ReadStorage>,
    after: Option<ReadStorage>,
    admission: Option<SelectedInitial>,
    prepaid: Credit,
}
#[derive(Clone, Copy, PartialEq, Eq)]
enum Need {
    Reference(reference::Need),
    StartDestination,
    Search(SearchNeed),
    Metadata(ValueNeed),
    Admission(discovery::Need),
}
pub(crate) struct LabelOwner {
    phase: Phase,
    effect: Effect,
    selection: crate::ObjectMutationPlan,
    admission: crate::ObjectAdmission,
    content: crate::ContentObservation,
    permit: Option<crate::registry::Reservation<crate::managed::NativeIdentity>>,

    future: FutureStorage,
    destination: Destination,
    protection: Arc<MutationProtection>,
    epoch: u64,
    _credit: Credit,
}
impl LabelOwner {
    pub(crate) fn pending(&self) -> bool {
        self.effect.pending()
            || match &self.phase {
                Phase::Reference(read) => read.pending(),
                Phase::Destination { read, .. } => read.pending(),
                Phase::Before { read, .. } | Phase::After { read, .. } => read.pending(),
                Phase::Admission { read, .. } => read.pending(),
                _ => false,
            }
    }
    pub(crate) fn search_claimed(&self) -> bool {
        match &self.phase {
            Phase::Reference(read) => read.search_claimed(),
            Phase::Destination { read, .. } => read.search_claimed(),
            _ => false,
        }
    }
    fn complete(&self) -> bool {
        matches!(&self.phase, Phase::Admission { read, .. } if read.complete())
    }
    fn check(
        &self,
        session: &Session,
        access: &SessionAccess<'_>,
        object: &ManagedObjectRef,
    ) -> Result<()> {
        context(session, Some(self.epoch), self.epoch)?;
        if self.effect.succeeded() {
            session.entry(access).map(|_| ())
        } else {
            session.managed_handle(access, object).map(|_| ())
        }
    }
    fn need(&mut self) -> Result<Option<Need>> {
        Ok(match &mut self.phase {
            Phase::Reference(read) => read.need()?.map(Need::Reference),
            Phase::NeedDestination(_) => Some(Need::StartDestination),
            Phase::Destination { read, .. } => read.need()?.map(Need::Search),
            Phase::Before { read, .. } | Phase::After { read, .. } => {
                read.need().map(Need::Metadata)
            }
            Phase::Admission { read, .. } => read.need()?.map(Need::Admission),
            _ => None,
        })
    }
    fn bind_read(
        &mut self,
        storage: ReadStorage,
        before: bool,
        handle: CK_OBJECT_HANDLE,
    ) -> Result<LegacyOwner> {
        let plan = if before {
            &self.selection.before
        } else {
            &self.selection.after
        };
        storage.bind_with_protection(
            &mut self.future.prepaid,
            Recipe::Mutation(plan),
            handle,
            Some(self.epoch),
            ObservationProtection::mutation(&self.protection),
        )
    }
    fn before(
        &mut self,
        reference: crate::ObjectReferenceReport,
        destination: crate::DestinationReport,
        values: crate::attributes::owned::resident::AttributeSnapshot,
    ) -> Result<Phase> {
        let before =
            crate::ObjectMutationReport::from_before(self.selection.clone(), reference, values)?;
        Ok(Phase::Ready {
            destination,
            before,
        })
    }
    fn admit(
        &mut self,
        object: &ManagedObjectRef,
        destination: crate::DestinationReport,
        mutation: crate::ObjectMutationReport,
    ) -> Result<Phase> {
        let initial = self.future.admission.take().ok_or(Error::Rejected(
            crate::RejectionReason::ObjectMutation(
                crate::ObjectMutationRejection::LabelAdmissionPreparationAbsent,
            ),
        ))?;
        let permit =
            self.permit
                .take()
                .ok_or(Error::Rejected(crate::RejectionReason::ObjectMutation(
                    crate::ObjectMutationRejection::LabelPublicationQuotaTransferred,
                )))?;
        let content = std::mem::replace(&mut self.content, crate::ContentObservation::NotRequested);
        let read = initial.bind(
            object.identity.class,
            object.handle,
            self.admission.clone(),
            content,
            "set destination content",
            permit,
            self.epoch,
            ObservationProtection::mutation(&self.protection),
            &mut self.future.prepaid,
        )?;
        Ok(Phase::Admission {
            destination,
            mutation,
            read: Box::new(read),
        })
    }
    fn advance(
        &mut self,
        session: &Session,
        access: &SessionAccess<'_>,
        object: &ManagedObjectRef,
    ) -> Result<()> {
        self.check(session, access, object)?;
        loop {
            match &mut self.phase {
                Phase::Reference(read) => {
                    read.advance(session, access, object.handle)?;
                    if !read.complete() {
                        return Ok(());
                    }
                }
                Phase::Destination { read, .. } => {
                    read.advance(session, access)?;
                    if !read.complete() {
                        return Ok(());
                    }
                }
                Phase::Before { read, .. } | Phase::After { read, .. } => {
                    read.advance(session, access, object.handle)?;
                    if !read.complete() {
                        return Ok(());
                    }
                }
                Phase::Admission { read, .. } => {
                    read.advance(session, access)?;
                    return Ok(());
                }
                Phase::NeedDestination(_) => return Ok(()),
                Phase::Stopped => {
                    return Err(Error::Rejected(crate::RejectionReason::ObjectMutation(
                        crate::ObjectMutationRejection::LabelMutationStopped,
                    )))
                }
                Phase::Ready { .. } => {}
            }
            self.phase = match std::mem::replace(&mut self.phase, Phase::Stopped) {
                Phase::Reference(read) => Phase::NeedDestination(read.result(session, access)?),
                Phase::Destination { reference, read } => {
                    let destination = read.result(session, access)?;
                    if let Some(storage) = self.future.before.take() {
                        Phase::Before {
                            reference,
                            destination,
                            read: self.bind_read(storage, true, object.handle)?,
                        }
                    } else {
                        self.before(reference, destination, Default::default())?
                    }
                }
                Phase::Before {
                    reference,
                    destination,
                    read,
                } => {
                    let values = self
                        .selection
                        .before
                        .observed_values(read.public_result(session, access)?)?;
                    self.before(reference, destination, values)?
                }
                Phase::Ready {
                    destination,
                    before,
                } => {
                    self.dispatch(session, access, object, &destination)?;
                    if let Some(storage) = self.future.after.take() {
                        Phase::After {
                            destination,
                            before,
                            read: self.bind_read(storage, false, object.handle)?,
                        }
                    } else {
                        self.admit(
                            object,
                            destination,
                            before.finish_observed(Default::default())?,
                        )?
                    }
                }
                Phase::After {
                    destination,
                    before,
                    read,
                } => {
                    let values = self
                        .selection
                        .after
                        .observed_values(read.public_result(session, access)?)?;
                    self.admit(object, destination, before.finish_observed(values)?)?
                }
                _ => {
                    return Err(Error::Rejected(crate::RejectionReason::ObjectMutation(
                        crate::ObjectMutationRejection::LabelMutationCompletionPhase,
                    )))
                }
            };
        }
    }
    fn dispatch(
        &mut self,
        session: &Session,
        access: &SessionAccess<'_>,
        object: &ManagedObjectRef,
        destination: &crate::DestinationReport,
    ) -> Result<()> {
        session.managed_handle(access, object)?;
        let generic::PreparedSetInput {
            template,
            targets: revocation,
        } = self.future.template.take().ok_or(Error::Rejected(
            crate::RejectionReason::ObjectMutation(
                crate::ObjectMutationRejection::LabelAlreadyDispatched,
            ),
        ))?;
        let mut frame = crate::native::frame::NativeFrame::session(access.clone(), template)?;
        let class_storage = self
            .future
            .class
            .take()
            .ok_or(Error::Rejected(crate::RejectionReason::ObjectMutation(
                crate::ObjectMutationRejection::LabelClassPreparationAbsent,
            )))?
            .with_protection(ObservationProtection::mutation(&self.protection));
        // Establish GetAttributeValue availability before Set: do not mutate
        // when the required class post-observation is already known unavailable.
        // Its frame is prepared now; the class read runs after the label change.
        let class_read =
            attributes::PreparedClassRead::from_storage(access, session, class_storage)?;

        let rename = self
            .protection
            .destination_reservation(session)?
            .prepare_rename(session, &object.identity, &self.destination)?;
        destination.check_context(session)?;
        self.effect = Effect::InFlight;
        let returned = match generic::call_set(&mut frame, session, object.handle, revocation) {
            Ok(returned) => returned,
            Err(error) => {
                self.effect = Effect::BeforeDispatch;
                return Err(error);
            }
        };
        self.effect = Effect::Returned {
            code: returned.code,
            storage_returned: returned.storage_returned(),
            local_failure: returned.inputs_changed(),
        };
        let result = session.mutation_result(
            access,
            crate::native_return::MutationCall::Set,
            returned.code,
        );
        if returned.inputs_changed() {
            return Err(Error::Rejected(crate::RejectionReason::ObjectMutation(
                crate::ObjectMutationRejection::AttributeMutationInputChanged,
            )));
        }
        result?;
        drop(frame);

        session.entry(access)?;
        if let Err(error) = rename.finish() {
            session.poison(access);
            return Err(error);
        }
        // Unknown completion retains the duplicated exclusive proof in this
        // fixed native frame, independently of the outer owner's disposition.
        class_read.check(session, object.handle, object.class().raw())
    }
    fn finish_search(&mut self, session: &Session, access: &SessionAccess<'_>) -> Result<()> {
        match &mut self.phase {
            Phase::Reference(read) => read.finish_search(session, access),
            Phase::Destination { read, .. } => read.finish_search(session, access),
            _ => Ok(()),
        }
    }
    fn result(
        self,
        session: &Session,
        access: &SessionAccess<'_>,
        source: &ManagedObjectRef,
    ) -> Result<ManagedObjectRef> {
        let Phase::Admission {
            destination,
            mutation,
            read,
        } = self.phase
        else {
            return Err(Error::Rejected(crate::RejectionReason::ObjectMutation(
                crate::ObjectMutationRejection::LabelMutationIncomplete,
            )));
        };
        let mut reference = read.result(session, access)?;
        destination.check_context(session)?;
        reference.mutation_report = Some(mutation);
        reference.destination_report = Some(destination);
        source
            .identity
            .access
            .result(session, access, Ok(reference))
    }
}
mod runner;
pub(super) use runner::set;
