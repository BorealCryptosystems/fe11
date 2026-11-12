// SPDX-License-Identifier: Apache-2.0
//! Copy observations retain the distinct output and its creation proof.
//! A resource wait never repeats Copy or releases the original source reader.
use super::{dispatch_resident, CopyCall, CreatedCopy, PreparedCopyDiagnostics};
use crate::managed::mutations::*;
use crate::{
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
    Class {
        destination: crate::DestinationReport,
        before: crate::ObjectMutationReport,
        read: LegacyOwner,
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
// Only Created owns a cleanup-eligible output. Stopped includes native
// refusals and unknown returns, whose original frame/ticket retains custody.
enum NativeCopy {
    Prepared {
        call: CopyCall,
        creation: crate::managed::PreparedCreation,
    },
    Created(CreatedCopy),
    Stopped,
}
struct FutureStorage {
    class: Option<ReadStorage>,
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
pub(crate) struct CopyOwner {
    publication: crate::managed::SinglePublication,
    phase: Phase,
    native: NativeCopy,
    selection: crate::ObjectMutationPlan,
    admission: crate::ObjectAdmission,
    content: crate::ContentObservation,
    permit: Option<crate::registry::Reservation<crate::managed::NativeIdentity>>,

    future: FutureStorage,
    class: ManagedClass,
    protection: Arc<MutationProtection>,
    epoch: u64,
    _credit: Credit,
}
impl CopyOwner {
    pub(crate) fn pending(&self) -> bool {
        match &self.phase {
            Phase::Reference(read) => read.pending(),
            Phase::Destination { read, .. } => read.pending(),
            Phase::Before { read, .. } | Phase::Class { read, .. } | Phase::After { read, .. } => {
                read.pending()
            }
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
        session.managed_handle(access, object).map(|_| ())
    }
    fn need(&mut self) -> Result<Option<Need>> {
        Ok(match &mut self.phase {
            Phase::Reference(read) => read.need()?.map(Need::Reference),
            Phase::NeedDestination(_) => Some(Need::StartDestination),
            Phase::Destination { read, .. } => read.need()?.map(Need::Search),
            Phase::Before { read, .. } | Phase::Class { read, .. } | Phase::After { read, .. } => {
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
        destination: crate::DestinationReport,
        mutation: crate::ObjectMutationReport,
    ) -> Result<Phase> {
        let initial = self.future.admission.take().ok_or(Error::Rejected(
            crate::RejectionReason::ObjectCopy(
                crate::ObjectCopyRejection::CopyAdmissionPreparationAbsent,
            ),
        ))?;
        let permit =
            self.permit
                .take()
                .ok_or(Error::Rejected(crate::RejectionReason::ObjectCopy(
                    crate::ObjectCopyRejection::CopyPublicationQuotaTransferred,
                )))?;
        let content = std::mem::replace(&mut self.content, crate::ContentObservation::NotRequested);
        let handle = self.created()?;
        let read = initial.bind(
            self.class,
            handle,
            self.admission.clone(),
            content,
            "copy destination content",
            permit,
            self.epoch,
            ObservationProtection::mutation(&self.protection),
            &mut self.future.prepaid,
        )?;
        let read = read.retain_native(
            self.publication
                .identity()
                .ok_or(Error::Rejected(crate::RejectionReason::ObjectCopy(
                    crate::ObjectCopyRejection::CopyNativeLifetimeAbsent,
                )))?
                .clone(),
        );
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
        diagnostics: &mut PreparedCopyDiagnostics,
        receipt: &mut Option<crate::error::CompletionDiagnostic>,
        cleanup: &mut crate::error::CleanupStorage,
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
                Phase::Before { read, .. } => {
                    read.advance(session, access, object.handle)?;
                    if !read.complete() {
                        return Ok(());
                    }
                }
                Phase::Class { read, .. } | Phase::After { read, .. } => {
                    let NativeCopy::Created(created) = &self.native else {
                        return Err(Error::Rejected(crate::RejectionReason::ObjectCopy(
                            crate::ObjectCopyRejection::CopyOutputAbsent,
                        )));
                    };
                    read.advance(session, access, created.handle)?;
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
                    return Err(Error::Rejected(crate::RejectionReason::ObjectCopy(
                        crate::ObjectCopyRejection::CopyStopped,
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
                    self.dispatch(session, access, object, &destination, diagnostics, receipt)?;
                    session.mutation_context(access, |cause| cleanup.mark_remaining(cause))?;
                    if let Some(storage) = self.future.class.take() {
                        let handle = self.created()?;
                        let read = storage.bind_with_protection(
                            &mut self.future.prepaid,
                            class_recipe(&self.admission),
                            handle,
                            Some(self.epoch),
                            ObservationProtection::mutation(&self.protection),
                        )?;
                        Phase::Class {
                            destination,
                            before,
                            read,
                        }
                    } else {
                        self.after(destination, before)?
                    }
                }
                Phase::Class {
                    destination,
                    before,
                    read,
                } => {
                    read.required_result(session, access)?
                        .integer(fe11_sys::CKA_CLASS, self.class.raw())?;
                    self.after(destination, before)?
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
                    self.admit(destination, before.finish_observed(values)?)?
                }
                _ => {
                    return Err(Error::Rejected(crate::RejectionReason::ObjectCopy(
                        crate::ObjectCopyRejection::CopyCompletionPhase,
                    )))
                }
            };
        }
    }
    fn created(&self) -> Result<CK_OBJECT_HANDLE> {
        match &self.native {
            NativeCopy::Created(created) => Ok(created.handle),
            _ => Err(Error::Rejected(crate::RejectionReason::ObjectCopy(
                crate::ObjectCopyRejection::CopyOutputAbsent,
            ))),
        }
    }
    fn after(
        &mut self,
        destination: crate::DestinationReport,
        before: crate::ObjectMutationReport,
    ) -> Result<Phase> {
        if let Some(storage) = self.future.after.take() {
            Ok(Phase::After {
                destination,
                before,
                read: self.bind_read(storage, false, self.created()?)?,
            })
        } else {
            self.admit(destination, before.finish_observed(Default::default())?)
        }
    }
    fn dispatch(
        &mut self,
        session: &Session,
        access: &SessionAccess<'_>,
        object: &ManagedObjectRef,
        destination: &crate::DestinationReport,
        diagnostics: &mut PreparedCopyDiagnostics,
        receipt: &mut Option<crate::error::CompletionDiagnostic>,
    ) -> Result<()> {
        session.managed_handle(access, object)?;
        destination.check_context(session)?;
        let NativeCopy::Prepared { call, mut creation } =
            std::mem::replace(&mut self.native, NativeCopy::Stopped)
        else {
            return Err(Error::Rejected(crate::RejectionReason::ObjectCopy(
                crate::ObjectCopyRejection::CopyAlreadyDispatched,
            )));
        };
        let completed = dispatch_resident(
            session,
            access,
            object,
            call,
            &mut creation,
            diagnostics.take()?,
        )?;
        let (created, diagnostic) = completed.into_parts();
        self.native = NativeCopy::Created(created);
        // Publish the receipt to the caller before fallible bookkeeping. It
        // must not remain in a resident owner when that caller unwinds.
        *receipt = Some(diagnostic);
        self.publication.publish(
            session,
            access,
            self.created()?,
            self.permit
                .as_mut()
                .ok_or(Error::Rejected(crate::RejectionReason::ObjectCopy(
                    crate::ObjectCopyRejection::CopyPublicationQuotaAbsent,
                )))?,
        )
    }
    // Called once on a failing continuation, while its original proof is still
    // resident. No output from a refused/unknown/aliased Copy is eligible here.
    fn cleanup(
        &mut self,
        session: &Session,
        access: &SessionAccess<'_>,
        cause: Error,
        storage: &mut crate::error::CleanupStorage,
    ) -> Error {
        match std::mem::replace(&mut self.native, NativeCopy::Stopped) {
            NativeCopy::Created(created) => cleanup_prepared(
                session,
                access,
                session.entry.handle,
                created.handle,
                cause,
                storage,
            ),
            previous => {
                self.native = previous;
                cause
            }
        }
    }
    fn finish_search(&mut self, session: &Session, access: &SessionAccess<'_>) -> Result<()> {
        match &mut self.phase {
            Phase::Reference(read) => read.finish_search(session, access),
            Phase::Destination { read, .. } => read.finish_search(session, access),
            _ => Ok(()),
        }
    }
    fn result(
        &mut self,
        session: &Session,
        access: &SessionAccess<'_>,
        source: &ManagedObjectRef,
    ) -> Result<ManagedObjectRef> {
        let Phase::Admission {
            destination,
            mutation,
            read,
        } = std::mem::replace(&mut self.phase, Phase::Stopped)
        else {
            return Err(Error::Rejected(crate::RejectionReason::ObjectCopy(
                crate::ObjectCopyRejection::CopyIncomplete,
            )));
        };
        let mut reference = read.result(session, access)?;
        destination.check_context(session)?;
        reference.mutation_report = Some(mutation);
        reference.destination_report = Some(destination);
        let reference = source
            .identity
            .access
            .result(session, access, Ok(reference))?;
        Ok(reference)
    }
}
fn class_recipe(admission: &crate::ObjectAdmission) -> Recipe<'static> {
    Recipe::Required {
        fields: &[fe11_sys::CKA_CLASS],
        maximum: admission.metadata.maximum_bytes,
    }
}
mod preparation;
mod runner;
pub(in crate::managed::mutations) use preparation::{public, typed};
