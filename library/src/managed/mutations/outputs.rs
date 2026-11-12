// SPDX-License-Identifier: Apache-2.0
//! Native creation outputs share coordination, not cryptographic policy.
//!
//! Destinations are observed in caller order before the sole native effect.
//! Registered outputs and auxiliary buffers stay resident while each requested
//! reference/content read obtains storage outside possession. Pair generation
//! deliberately publishes both references before either content observation.
use super::input_identity::InputIdentity;
use crate::{
    destination_controls::resident::{DestinationOwner, Initial as DestinationInitial},
    managed::{
        discovery::{self, preparation::SelectedInitial, DiscoveryOwner},
        search,
    },
    session::{
        observation_protection::{MutationProtection, ObservationProtection},
        recovery::observations::{context, Prepared, Waiting},
        SessionAccess,
    },
    symmetric::memory::Credit,
    ContentObservation, ContentReadPlan, DestinationPlan, DestinationReport, Error, ManagedClass,
    ObjectAdmission, Result, Session,
};
use fe11_sys::{CK_INVALID_HANDLE, CK_OBJECT_HANDLE};
use std::sync::Arc;
mod native;
pub(in crate::managed) use native::Output;
pub(super) use native::PreparedCall;
mod preparation;
pub(super) use preparation::{Initial, Spec};
mod runner;
pub(super) use runner::run;

#[derive(Clone, Copy)]
pub(super) enum Order {
    EachReferenceThenContent,
    AllReferencesThenContent,
}
enum SlotState {
    Prepared {
        destination: DestinationInitial,
        selected: Option<SelectedInitial>,
    },
    Destination {
        read: Box<DestinationOwner>,
        selected: Option<SelectedInitial>,
    },
    Ready {
        report: DestinationReport,
        selected: Option<SelectedInitial>,
    },
    Admission {
        report: DestinationReport,
        read: Box<DiscoveryOwner>,
    },
    Observed {
        report: DestinationReport,
        read: Box<DiscoveryOwner>,
    },
    Absent,
    Unobserved,
    Taken,
}
struct Slot {
    native: Option<Arc<crate::managed::NativeIdentity>>,
    state: SlotState,
    class: ManagedClass,
    admission: Option<ObjectAdmission>,
    destination: DestinationPlan,
    content: ContentObservation,
    content_plan: Option<ContentReadPlan>,
    stage: &'static str,
    handle: CK_OBJECT_HANDLE,
}
enum Phase {
    DestinationReady(usize),
    Destination(usize),
    NativeReady,
    InFlight,
    AdmissionReady(usize),
    Admission(usize),
    ContentReady(usize),
    Content(usize),
    Complete,
    Stopped,
}
enum Native {
    Prepared {
        call: PreparedCall,
        creation: crate::managed::PreparedCreation,
    },
    InFlight,
    Created {
        output: Output,
        creation: crate::managed::CreationTicket,
    },
    // Final construction may move auxiliary output, but cleanup still retains
    // the creation ticket and the immutable handle recorded in every slot.
    Taken {
        _creation: crate::managed::CreationTicket,
    },
    Stopped,
}
#[derive(Clone, Copy, PartialEq, Eq)]
enum Need {
    Destination(usize),
    Native,
    Search(search::SearchNeed),
    Admission(usize, discovery::Need),
}
enum Publication {
    Prepared(Vec<crate::NativeObjectRef>),
    Registered(Vec<crate::NativeObjectRef>),
    Taken,
}
pub(crate) struct OutputsOwner {
    publication: Publication,
    publication_credit: Option<Credit>,
    phase: Phase,
    native: Native,
    slots: Vec<Slot>,
    permit: Option<crate::registry::Reservation<crate::managed::NativeIdentity>>,
    order: Order,
    epoch: u64,
    protection: Arc<MutationProtection>,
    prepaid: Credit,
    _credit: Credit,
}
impl OutputsOwner {
    fn registered(&self) -> bool {
        matches!(self.publication, Publication::Registered(_))
    }

    fn take_native_objects(&mut self, session: &Session) -> Result<Vec<crate::NativeObjectRef>> {
        let Publication::Registered(mut objects) =
            std::mem::replace(&mut self.publication, Publication::Taken)
        else {
            return Err(Error::Rejected(crate::RejectionReason::ObjectPublication(
                crate::ObjectPublicationRejection::NativeObjectsNotRegistered,
            )));
        };
        // Remove the empty vector from the resident owner before inserting any
        // Inner-owning reference: recovery must never keep Inner alive itself.
        for (index, slot) in self.slots.iter().enumerate() {
            if slot.handle != CK_INVALID_HANDLE {
                let identity = slot.native.as_ref().ok_or(Error::Rejected(
                    crate::RejectionReason::ObjectPublication(
                        crate::ObjectPublicationRejection::NativeObjectLifetimeAbsent,
                    ),
                ))?;
                if objects.len() == objects.capacity() {
                    return Err(Error::Rejected(crate::RejectionReason::ObjectPublication(
                        crate::ObjectPublicationRejection::NativePublicationCapacity,
                    )));
                }
                objects.push(crate::NativeObjectRef {
                    inner: session.inner.clone(),
                    identity: identity.clone(),
                    output_slot: Some(index),
                });
            }
        }
        Ok(objects)
    }

    pub(crate) fn pending(&self) -> bool {
        if matches!(self.phase, Phase::InFlight) {
            return true;
        }
        self.slots.iter().any(|slot| match &slot.state {
            SlotState::Destination { read, .. } => read.pending(),
            SlotState::Admission { read, .. } | SlotState::Observed { read, .. } => read.pending(),
            _ => false,
        })
    }
    pub(crate) fn search_claimed(&self) -> bool {
        self.slots.iter().any(|slot| matches!(&slot.state, SlotState::Destination { read, .. } if read.search_claimed()))
    }
    /// A search has its own checked Final. Do not let one slot's active search
    /// hide an unfinished metadata or native-output loan in another slot.
    fn non_search_pending(&self) -> bool {
        matches!(self.phase, Phase::InFlight)
            || self.slots.iter().any(|slot| match &slot.state {
                SlotState::Destination { read, .. } => read.pending() && !read.search_claimed(),
                SlotState::Admission { read, .. } | SlotState::Observed { read, .. } => {
                    read.pending()
                }
                _ => false,
            })
    }
    fn complete(&self) -> bool {
        matches!(self.phase, Phase::Complete)
    }
    fn need(&mut self) -> Result<Option<Need>> {
        match self.phase {
            Phase::DestinationReady(index) => Ok(Some(Need::Destination(index))),
            Phase::Destination(index) => match &mut self.slots[index].state {
                SlotState::Destination { read, .. } => Ok(read.need()?.map(Need::Search)),
                _ => Err(Error::Rejected(crate::RejectionReason::ObjectPublication(
                    crate::ObjectPublicationRejection::NativeOutputDestinationState,
                ))),
            },
            Phase::NativeReady => Ok(Some(Need::Native)),
            Phase::Admission(index) | Phase::Content(index) => match &mut self.slots[index].state {
                SlotState::Admission { read, .. } => {
                    Ok(read.need()?.map(|need| Need::Admission(index, need)))
                }
                _ => Err(Error::Rejected(crate::RejectionReason::ObjectPublication(
                    crate::ObjectPublicationRejection::NativeOutputAdmissionState,
                ))),
            },
            _ => Ok(None),
        }
    }
    fn activate_destination(
        &mut self,
        session: &Session,
        access: &SessionAccess<'_>,
        index: usize,
    ) -> Result<()> {
        if !matches!(self.phase, Phase::DestinationReady(i) if i == index) {
            return Err(Error::Rejected(crate::RejectionReason::ObjectPublication(
                crate::ObjectPublicationRejection::NativeOutputDestinationPhase,
            )));
        }
        let slot = &mut self.slots[index];
        let SlotState::Prepared { destination, .. } = &mut slot.state else {
            return Err(Error::Rejected(crate::RejectionReason::ObjectPublication(
                crate::ObjectPublicationRejection::NativeOutputDestinationPreparation,
            )));
        };
        let mut protection = Some(ObservationProtection::mutation(&self.protection));
        let read = destination.bind_retained(
            session,
            access,
            &slot.destination,
            None,
            self.epoch,
            &mut protection,
            &mut self.prepaid,
        )?;
        let SlotState::Prepared { selected, .. } =
            std::mem::replace(&mut slot.state, SlotState::Taken)
        else {
            unreachable!("validated output destination phase")
        };
        slot.state = SlotState::Destination {
            read: Box::new(read),
            selected,
        };
        self.phase = Phase::Destination(index);
        Ok(())
    }
    fn advance(&mut self, session: &Session, access: &SessionAccess<'_>) -> Result<()> {
        context(session, Some(self.epoch), self.epoch)?;
        session.entry(access)?;
        loop {
            match self.phase {
                Phase::Destination(index) => {
                    let slot = &mut self.slots[index];
                    let SlotState::Destination { read, .. } = &mut slot.state else {
                        return Err(Error::Rejected(crate::RejectionReason::ObjectPublication(
                            crate::ObjectPublicationRejection::NativeDestinationOwner,
                        )));
                    };
                    read.advance(session, access)?;
                    if !read.complete() {
                        return Ok(());
                    }
                    let SlotState::Destination { read, selected } =
                        std::mem::replace(&mut slot.state, SlotState::Taken)
                    else {
                        unreachable!()
                    };
                    let report = read.result(session, access)?;
                    report.check_context(session)?;
                    slot.state = SlotState::Ready { report, selected };
                    self.phase = if index + 1 < self.slots.len() {
                        Phase::DestinationReady(index + 1)
                    } else {
                        Phase::NativeReady
                    };
                }
                Phase::AdmissionReady(index) => {
                    if index == self.slots.len() {
                        self.phase = match self.order {
                            Order::EachReferenceThenContent => Phase::Complete,
                            Order::AllReferencesThenContent => Phase::ContentReady(0),
                        };
                        continue;
                    }
                    let slot = &mut self.slots[index];
                    if slot.handle == CK_INVALID_HANDLE {
                        slot.state = SlotState::Absent;
                        self.phase = Phase::AdmissionReady(index + 1);
                        continue;
                    }
                    if slot.admission.is_none() {
                        slot.state = SlotState::Unobserved;
                        self.phase = Phase::AdmissionReady(index + 1);
                        continue;
                    }
                    let SlotState::Ready { report, selected } =
                        std::mem::replace(&mut slot.state, SlotState::Taken)
                    else {
                        return Err(Error::Rejected(crate::RejectionReason::ObjectPublication(
                            crate::ObjectPublicationRejection::NativeOutputReferencePreparation,
                        )));
                    };
                    let permit = self.permit.take().ok_or(Error::Rejected(
                        crate::RejectionReason::ObjectPublication(
                            crate::ObjectPublicationRejection::NativeOutputQuotaAbsent,
                        ),
                    ))?;
                    let content = match self.order {
                        Order::EachReferenceThenContent => {
                            std::mem::replace(&mut slot.content, ContentObservation::NotRequested)
                        }
                        Order::AllReferencesThenContent => ContentObservation::NotRequested,
                    };
                    let read = selected
                        .ok_or(Error::Rejected(crate::RejectionReason::ObjectPublication(crate::ObjectPublicationRejection::RequestedObservationPreparationAbsent)))?
                        .bind(
                            slot.class,
                            slot.handle,
                            slot.admission
                                .clone()
                                .ok_or(Error::Rejected(crate::RejectionReason::ObjectPublication(crate::ObjectPublicationRejection::RequestedObservationSelectionAbsent)))?,
                            content,
                            slot.stage,
                            permit,
                            self.epoch,
                            ObservationProtection::mutation(&self.protection),
                            &mut self.prepaid,
                        )?;
                    let read = read.retain_native(
                        slot.native
                            .as_ref()
                            .ok_or(Error::Rejected(crate::RejectionReason::ObjectPublication(
                                crate::ObjectPublicationRejection::NativeOutputLifetimeAbsent,
                            )))?
                            .clone(),
                    );
                    slot.state = SlotState::Admission {
                        report,
                        read: Box::new(read),
                    };
                    self.phase = Phase::Admission(index);
                }
                Phase::Admission(index) | Phase::Content(index) => {
                    let content_pass = matches!(self.phase, Phase::Content(_));
                    let slot = &mut self.slots[index];
                    let SlotState::Admission { read, .. } = &mut slot.state else {
                        return Err(Error::Rejected(crate::RejectionReason::ObjectPublication(
                            crate::ObjectPublicationRejection::NativeOutputReferenceOwner,
                        )));
                    };
                    read.advance(session, access)?;
                    if !read.complete() {
                        return Ok(());
                    }
                    if !content_pass {
                        self.permit = Some(read.take_permit()?);
                    }
                    let SlotState::Admission { read, report } =
                        std::mem::replace(&mut slot.state, SlotState::Taken)
                    else {
                        unreachable!()
                    };
                    slot.state = SlotState::Observed { report, read };
                    self.phase = if content_pass {
                        Phase::ContentReady(index + 1)
                    } else {
                        Phase::AdmissionReady(index + 1)
                    };
                }
                Phase::ContentReady(index) => {
                    if index == self.slots.len() {
                        self.phase = Phase::Complete;
                        continue;
                    }
                    let slot = &mut self.slots[index];
                    if matches!(slot.state, SlotState::Absent | SlotState::Unobserved) {
                        self.phase = Phase::ContentReady(index + 1);
                        continue;
                    }
                    let SlotState::Observed { report, mut read } =
                        std::mem::replace(&mut slot.state, SlotState::Taken)
                    else {
                        return Err(Error::Rejected(crate::RejectionReason::ObjectPublication(
                            crate::ObjectPublicationRejection::NativeOutputContentOwner,
                        )));
                    };
                    read.resume_content(
                        std::mem::replace(&mut slot.content, ContentObservation::NotRequested),
                        slot.stage,
                    )?;
                    slot.state = SlotState::Admission { report, read };
                    self.phase = Phase::Content(index);
                }
                Phase::DestinationReady(_) | Phase::NativeReady | Phase::Complete => return Ok(()),
                _ => {
                    return Err(Error::Rejected(crate::RejectionReason::ObjectPublication(
                        crate::ObjectPublicationRejection::NativeOutputOperationStopped,
                    )))
                }
            }
        }
    }
    fn dispatch(
        &mut self,
        access: &SessionAccess<'_>,
    ) -> Result<(PreparedCall, crate::managed::PreparedCreation)> {
        if !matches!(self.phase, Phase::NativeReady) {
            return Err(Error::Rejected(crate::RejectionReason::ObjectPublication(
                crate::ObjectPublicationRejection::NativeOutputDispatchPhase,
            )));
        }
        for slot in &self.slots {
            if !matches!(slot.state, SlotState::Ready { .. }) {
                return Err(Error::Rejected(crate::RejectionReason::ObjectPublication(
                    crate::ObjectPublicationRejection::NativeOutputDestinationIncomplete,
                )));
            }
        }
        access.retain_observation_protection(ObservationProtection::mutation(&self.protection))?;
        let Native::Prepared { call, creation } =
            std::mem::replace(&mut self.native, Native::InFlight)
        else {
            return Err(Error::Rejected(crate::RejectionReason::ObjectPublication(
                crate::ObjectPublicationRejection::NativeCreationAlreadyDispatched,
            )));
        };
        self.phase = Phase::InFlight;
        Ok((call, creation))
    }
    fn returned(
        &mut self,
        output: Output,
        creation: crate::managed::CreationTicket,
        session: &Session,
        access: &SessionAccess<'_>,
        cleanup: &mut crate::error::CleanupStorage,
    ) -> Result<()> {
        if !matches!(self.phase, Phase::InFlight) {
            return Err(Error::Rejected(crate::RejectionReason::ObjectPublication(
                crate::ObjectPublicationRejection::NativeOutputReturnPhase,
            )));
        }
        self.native = Native::Created { output, creation };
        self.phase = Phase::Stopped;
        let Native::Created { output, .. } = &mut self.native else {
            unreachable!()
        };
        for (index, slot) in self.slots.iter_mut().enumerate() {
            slot.handle = output.slot_handle(index)?;
        }
        output.check_output_integrity()?;
        // Publish every returned object before starting optional attribute reads.
        let permit = self.permit.as_mut().ok_or(Error::Rejected(
            crate::RejectionReason::ObjectPublication(
                crate::ObjectPublicationRejection::NativeOutputQuotaAbsent,
            ),
        ))?;
        for slot in &mut self.slots {
            if slot.handle != CK_INVALID_HANDLE {
                crate::managed::NativeIdentity::publish_created(
                    slot.native.as_mut().ok_or(Error::Rejected(
                        crate::RejectionReason::ObjectPublication(
                            crate::ObjectPublicationRejection::NativeOutputPreparationAbsent,
                        ),
                    ))?,
                    session,
                    access,
                    slot.handle,
                    permit,
                )?;
            }
        }
        let Publication::Prepared(storage) =
            std::mem::replace(&mut self.publication, Publication::Taken)
        else {
            return Err(Error::Rejected(crate::RejectionReason::ObjectPublication(
                crate::ObjectPublicationRejection::NativeOutputPublicationState,
            )));
        };
        self.publication = Publication::Registered(storage);
        // A lost authentication/session context invalidates use of the outputs,
        // but must not turn a completed creation into implicit destruction.
        session.mutation_context(access, |cause| cleanup.mark_remaining(cause))?;
        self.phase = Phase::AdmissionReady(0);
        Ok(())
    }
    fn failed_dispatch(&mut self) {
        self.phase = Phase::Stopped;
        self.native = Native::Stopped;
    }
    fn finish_search(&mut self, session: &Session, access: &SessionAccess<'_>) -> Result<()> {
        for slot in &mut self.slots {
            if let SlotState::Destination { read, .. } = &mut slot.state {
                read.finish_search(session, access)?;
            }
        }
        Ok(())
    }
    fn cleanup(
        &mut self,
        session: &Session,
        access: &SessionAccess<'_>,
        mut cause: Error,
        storage: &mut crate::error::CleanupStorage,
    ) -> Error {
        if !matches!(self.native, Native::Created { .. } | Native::Taken { .. }) {
            return cause;
        }
        for slot in self.slots.iter().rev() {
            if slot.handle != CK_INVALID_HANDLE {
                cause = crate::managed::cleanup_prepared(
                    session,
                    access,
                    session.entry.handle,
                    slot.handle,
                    cause,
                    storage,
                );
            }
        }
        self.native = Native::Stopped;
        cause
    }
    pub(super) fn take_reference(
        &mut self,
        session: &Session,
        access: &SessionAccess<'_>,
        index: usize,
    ) -> Result<Option<crate::NativeObjectView>> {
        if !self.complete() {
            return Err(Error::Rejected(crate::RejectionReason::ObjectPublication(
                crate::ObjectPublicationRejection::NativeOutputsIncomplete,
            )));
        }
        let slot = self.slots.get_mut(index).ok_or(Error::Rejected(
            crate::RejectionReason::ObjectPublication(
                crate::ObjectPublicationRejection::NativeOutputReferenceIndex,
            ),
        ))?;
        match std::mem::replace(&mut slot.state, SlotState::Taken) {
            SlotState::Absent => Ok(None),
            SlotState::Unobserved => Ok(Some(crate::NativeObjectView::unobserved(
                crate::NativeObjectRef {
                    inner: session.inner.clone(),
                    identity: slot
                        .native
                        .as_ref()
                        .ok_or(Error::Rejected(crate::RejectionReason::ObjectPublication(
                            crate::ObjectPublicationRejection::UnobservedNativeIdentityAbsent,
                        )))?
                        .clone(),
                    output_slot: Some(index),
                },
            ))),
            SlotState::Observed { read, report } => {
                let mut reference = read.result(session, access)?;
                report.check_context(session)?;
                reference.destination_report = Some(report);
                reference.identity.access.result(
                    session,
                    access,
                    Ok(Some(crate::NativeObjectView::described(reference))),
                )
            }
            _ => Err(Error::Rejected(crate::RejectionReason::ObjectPublication(
                crate::ObjectPublicationRejection::NativeOutputReferenceUnavailable,
            ))),
        }
    }
    // Terminal publication is synchronous and cannot request resources. Move
    // auxiliary data out before constructing public references, so no Inner
    // ownership can enter its own recovery registry, even on error or unwind.
    pub(super) fn take_vector_output(
        &mut self,
        session: &Session,
        access: &SessionAccess<'_>,
    ) -> Result<Output> {
        let mut output = self.take_output()?;
        let assembled = (|| {
            for index in 0..self.slots.len() {
                let Some(reference) = self.take_reference(session, access, index)? else {
                    continue;
                };
                match &mut output {
                    Output::Tls { data, publication } => {
                        let role = *data.roles().get(index).ok_or(Error::Rejected(
                            crate::RejectionReason::ObjectPublication(
                                crate::ObjectPublicationRejection::TlsPublicationRole,
                            ),
                        ))?;
                        if publication.keys.len() == publication.keys.capacity() {
                            return Err(Error::Rejected(
                                crate::RejectionReason::ObjectPublication(
                                    crate::ObjectPublicationRejection::TlsPublicationCapacity,
                                ),
                            ));
                        }
                        publication.keys.push((role, reference));
                    }
                    Output::Sp800 { publication, .. } => {
                        if publication.keys.len() == publication.keys.capacity() {
                            return Err(Error::Rejected(
                                crate::RejectionReason::ObjectPublication(
                                    crate::ObjectPublicationRejection::Sp800PublicationCapacity,
                                ),
                            ));
                        }
                        publication.keys.push(reference);
                    }
                    _ => {
                        return Err(Error::Rejected(crate::RejectionReason::ObjectPublication(
                            crate::ObjectPublicationRejection::NativeOutputVectorKind,
                        )))
                    }
                }
            }
            Ok(())
        })();
        if let Err(error) = assembled {
            // Do not place Inner-owning typed references back in the resident
            // registry. Generic native owners remain available independently.
            match &mut output {
                Output::Tls { publication, .. } => publication.keys.clear(),
                Output::Sp800 { publication, .. } => publication.keys.clear(),
                _ => {}
            }
            let Native::Taken {
                _creation: creation,
            } = std::mem::replace(&mut self.native, Native::Stopped)
            else {
                return Err(Error::Rejected(crate::RejectionReason::ObjectPublication(
                    crate::ObjectPublicationRejection::NativeOutputRestorationState,
                )));
            };
            self.native = Native::Created { output, creation };
            return Err(error);
        }
        Ok(output)
    }
    pub(super) fn take_output(&mut self) -> Result<Output> {
        let Native::Created { output, creation } =
            std::mem::replace(&mut self.native, Native::Stopped)
        else {
            return Err(Error::Rejected(crate::RejectionReason::ObjectPublication(
                crate::ObjectPublicationRejection::NativeAuxiliaryOutputAbsent,
            )));
        };
        self.native = Native::Taken {
            _creation: creation,
        };
        Ok(output)
    }
}
