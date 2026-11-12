// SPDX-License-Identifier: Apache-2.0
//! One generic setter, retaining its writers through all selected observations.
use super::*;
use crate::{
    attributes::owned::resident::{LegacyOwner, ReadStorage, Recipe, ValueNeed},
    content_controls::{
        fingerprint_observation::resident as fingerprint, owned::resident::ContentOwner,
    },
    destination_controls::resident::{DestinationOwner, Initial as DestinationInitial},
    managed::{
        mutations::input_identity::InputIdentity,
        search::{SearchCandidate, SearchNeed, SearchPreparation, SearchWithdrawal},
    },
    reference_controls::resident::{
        self as reference, preparation::Initial as ReferenceInitial, ReferenceOwner,
    },
    session::{
        observation_protection::{MutationProtection, ObservationProtection},
        recovery::observations::{context, Prepared, Waiting},
    },
    symmetric::memory::Credit,
    ContentObservation, ContentReadPlan,
};

enum Phase {
    Destination(Box<DestinationOwner>),
    NeedReference(crate::DestinationReport),
    Reference {
        destination: crate::DestinationReport,
        read: Box<ReferenceOwner>,
    },
    Before {
        destination: crate::DestinationReport,
        reference: crate::ObjectReferenceReport,
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
    NeedContent {
        destination: crate::DestinationReport,
        mutation: crate::ObjectMutationReport,
    },
    Value {
        destination: crate::DestinationReport,
        mutation: crate::ObjectMutationReport,
        read: ContentOwner,
    },
    Fingerprint {
        destination: crate::DestinationReport,
        mutation: crate::ObjectMutationReport,
        read: Box<fingerprint::FingerprintOwner>,
    },
    Complete(AttributeMutationReport),
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
        matches!(
            self,
            Self::Returned {
                code: fe11_sys::CKR_OK,
                ..
            }
        )
    }
}
enum ContentStorage {
    None,
    Value(usize),
    Fingerprint {
        read: crate::AttributeReadPlan,
        header: ReadStorage,
    },
}
// Independent future preparations coexist with the active phase. None means
// this one-use storage has transferred to its child, not a second state flag.
struct FutureStorage {
    input: Option<PreparedSetInput>,
    reference: Option<ReferenceInitial>,
    before: Option<ReadStorage>,
    after: Option<ReadStorage>,
    content: ContentStorage,
    prepaid: Credit,
}
#[derive(Clone, Copy, PartialEq, Eq)]
enum Need {
    Search(SearchNeed),
    StartReference,
    Reference(reference::Need),
    Metadata(ValueNeed),
    Value(usize),
    Fingerprint(fingerprint::Need),
}
pub(crate) struct SetAttributesOwner {
    phase: Phase,
    effect: Effect,
    failures: crate::error::PreparedFailurePair,
    selection: crate::ObjectMutationPlan,
    before_content: Option<ContentObservation>,
    after_content: ContentObservation,

    future: FutureStorage,
    destination: Destination,
    identity_changes: bool,
    visibility_changes: bool,
    protection: Arc<MutationProtection>,
    epoch: u64,
    _credit: Credit,
}
impl SetAttributesOwner {
    pub(crate) fn pending(&self) -> bool {
        self.effect.pending()
            || match &self.phase {
                Phase::Destination(read) => read.pending(),
                Phase::Reference { read, .. } => read.pending(),
                Phase::Before { read, .. } | Phase::After { read, .. } => read.pending(),
                Phase::Value { read, .. } => read.pending(),
                Phase::Fingerprint { read, .. } => read.pending(),
                _ => false,
            }
    }
    pub(crate) fn search_claimed(&self) -> bool {
        match &self.phase {
            Phase::Destination(read) => read.search_claimed(),
            Phase::Reference { read, .. } => read.search_claimed(),
            _ => false,
        }
    }
    fn check(
        &self,
        session: &Session,
        access: &SessionAccess<'_>,
        object: &ManagedObjectRef,
    ) -> Result<()> {
        context(session, Some(self.epoch), self.epoch)?;
        if self.effect.succeeded() {
            // Set already revoked the old aliases. Post-success observations
            // retain the original context, not the revoked reference predicate.
            session.entry(access).map(|_| ())
        } else {
            session.managed_handle(access, object).map(|_| ())
        }
    }
    fn need(&mut self) -> Result<Option<Need>> {
        Ok(match &mut self.phase {
            Phase::Destination(read) => read.need()?.map(Need::Search),
            Phase::NeedReference(_) => Some(Need::StartReference),
            Phase::Reference { read, .. } => read.need()?.map(Need::Reference),
            Phase::Before { read, .. } | Phase::After { read, .. } => {
                read.need().map(Need::Metadata)
            }
            Phase::Value { read, .. } => read.need().map(Need::Value),
            Phase::Fingerprint { read, .. } => read.need().map(Need::Fingerprint),
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
    fn advance(
        &mut self,
        session: &Session,
        access: &SessionAccess<'_>,
        object: &ManagedObjectRef,
    ) -> Result<()> {
        self.check(session, access, object)?;
        let handle = object.handle;
        loop {
            match &mut self.phase {
                Phase::Destination(read) => {
                    read.advance(session, access)?;
                    if !read.complete() {
                        return Ok(());
                    }
                }
                Phase::Reference { read, .. } => {
                    read.advance(session, access, handle)?;
                    if !read.complete() {
                        return Ok(());
                    }
                }
                Phase::Before { read, .. } | Phase::After { read, .. } => {
                    read.advance(session, access, handle)?;
                    if !read.complete() {
                        return Ok(());
                    }
                }
                Phase::Value { read, .. } => {
                    read.advance(session, access, handle)?;
                    if !read.complete() {
                        return Ok(());
                    }
                }
                Phase::Fingerprint { read, .. } => {
                    read.advance(session, access, handle)?;
                    if !read.complete() {
                        return Ok(());
                    }
                }
                Phase::NeedReference(_) | Phase::Complete(_) => return Ok(()),
                Phase::Stopped => {
                    return Err(Error::Rejected(crate::RejectionReason::ObjectMutation(
                        crate::ObjectMutationRejection::AttributeMutationStopped,
                    )))
                }
                _ => {}
            }
            self.phase = match std::mem::replace(&mut self.phase, Phase::Stopped) {
                Phase::Destination(read) => Phase::NeedReference(read.result(session, access)?),
                Phase::Reference { destination, read } => {
                    let reference = read.result(session, access)?;
                    if let Some(storage) = self.future.before.take() {
                        Phase::Before {
                            destination,
                            reference,
                            read: self.bind_read(storage, true, handle)?,
                        }
                    } else {
                        self.before(destination, reference, Default::default())?
                    }
                }
                Phase::Before {
                    destination,
                    reference,
                    read,
                } => {
                    let values = self
                        .selection
                        .before
                        .observed_values(read.public_result(session, access)?)?;
                    self.before(destination, reference, values)?
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
                            read: self.bind_read(storage, false, handle)?,
                        }
                    } else {
                        Phase::NeedContent {
                            destination,
                            mutation: before.finish_observed(Default::default())?,
                        }
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
                    Phase::NeedContent {
                        destination,
                        mutation: before.finish_observed(values)?,
                    }
                }
                Phase::NeedContent {
                    destination,
                    mutation,
                } => match std::mem::replace(&mut self.future.content, ContentStorage::None) {
                    ContentStorage::None => {
                        let check = std::mem::replace(
                            &mut self.after_content,
                            ContentObservation::NotRequested,
                        );
                        let content = check.observe_with(|_| {
                            Err(Error::Rejected(crate::RejectionReason::ObjectMutation(
                                crate::ObjectMutationRejection::UnselectedMutationContent,
                            )))
                        })?;
                        Phase::Complete(AttributeMutationReport {
                            mutation,
                            content,
                            destination,
                        })
                    }
                    ContentStorage::Value(maximum) => Phase::Value {
                        destination,
                        mutation,
                        read: ContentOwner::prepaid_protected(
                            &mut self.future.prepaid,
                            handle,
                            maximum,
                            Some(self.epoch),
                            ObservationProtection::mutation(&self.protection),
                        )?,
                    },
                    ContentStorage::Fingerprint { read, header } => {
                        let header = header.bind_with_protection(
                            &mut self.future.prepaid,
                            fingerprint_recipe(read),
                            handle,
                            Some(self.epoch),
                            ObservationProtection::mutation(&self.protection),
                        )?;
                        let read = Box::new(fingerprint::FingerprintOwner::bind_protected(
                            header,
                            read,
                            handle,
                            Some(self.epoch),
                            ObservationProtection::mutation(&self.protection),
                            &mut self.future.prepaid,
                        )?);
                        Phase::Fingerprint {
                            destination,
                            mutation,
                            read,
                        }
                    }
                },
                Phase::Value {
                    destination,
                    mutation,
                    read,
                } => {
                    let check = std::mem::replace(
                        &mut self.after_content,
                        ContentObservation::NotRequested,
                    );
                    let content =
                        read.result(session, access, |value| check.observe_with(|_| Ok(value)))?;
                    Phase::Complete(AttributeMutationReport {
                        mutation,
                        content,
                        destination,
                    })
                }
                Phase::Fingerprint {
                    destination,
                    mutation,
                    read,
                } => {
                    let check = std::mem::replace(
                        &mut self.after_content,
                        ContentObservation::NotRequested,
                    );
                    let content =
                        read.result(session, access, |value| check.observe_with(|_| Ok(value)))?;
                    Phase::Complete(AttributeMutationReport {
                        mutation,
                        content,
                        destination,
                    })
                }
                _ => {
                    return Err(Error::Rejected(crate::RejectionReason::ObjectMutation(
                        crate::ObjectMutationRejection::AttributeMutationCompletionPhase,
                    )))
                }
            };
        }
    }
    fn before(
        &mut self,
        destination: crate::DestinationReport,
        reference: crate::ObjectReferenceReport,
        values: crate::attributes::owned::resident::AttributeSnapshot,
    ) -> Result<Phase> {
        let before =
            crate::ObjectMutationReport::from_before(self.selection.clone(), reference, values)?;
        Ok(Phase::Ready {
            destination,
            before,
        })
    }
    fn dispatch(
        &mut self,
        session: &Session,
        access: &SessionAccess<'_>,
        object: &ManagedObjectRef,
        destination: &crate::DestinationReport,
    ) -> Result<()> {
        session.managed_handle(access, object)?;
        let metadata = self
            .protection
            .destination_reservation(session)?
            .prepare_attribute_mutation(
                session,
                &object.identity,
                self.identity_changes.then_some(&self.destination),
                self.visibility_changes,
            )?;
        let PreparedSetInput { template, targets } = self.future.input.take().ok_or(
            Error::Rejected(crate::RejectionReason::ObjectMutation(
                crate::ObjectMutationRejection::AttributeMutationAlreadyDispatched,
            )),
        )?;
        let mut frame = NativeFrame::session(access.clone(), template)?;
        destination.check_context(session)?;
        self.effect = Effect::InFlight;
        let returned = match call_set(&mut frame, session, object.handle, targets) {
            Ok(returned) => returned,
            Err(error) => {
                // call_set errors precede native dispatch. Actual native returns
                // always carry SetReturn and their ownership classification.
                self.effect = Effect::BeforeDispatch;
                return Err(error);
            }
        };
        let storage_returned = matches!(returned.integrity, InputIntegrity::Unchanged);
        self.effect = Effect::Returned {
            code: returned.code,
            storage_returned,
            local_failure: false,
        };
        let bookkeeping = if !returned.inputs_changed()
            && MutationCall::Set.definite_object_refusal(returned.code)
        {
            Ok(())
        } else {
            metadata.finish()
        };
        if bookkeeping.is_err() {
            session.poison(access);
        }
        let native = session.mutation_result(access, MutationCall::Set, returned.code);
        let local = if returned.inputs_changed() {
            let alteration = Error::Rejected(crate::RejectionReason::ObjectMutation(
                crate::ObjectMutationRejection::AttributeMutationInputChanged,
            ));
            Err(match bookkeeping {
                Ok(()) => alteration,
                Err(cause) => self.failures.finish(alteration, cause),
            })
        } else {
            bookkeeping
        };
        if let Err(error) = local {
            self.effect = Effect::Returned {
                code: returned.code,
                storage_returned,
                local_failure: true,
            };
            return Err(error);
        }
        native?;
        drop(frame);
        Ok(())
    }
    fn finish_search(&mut self, session: &Session, access: &SessionAccess<'_>) -> Result<()> {
        match &mut self.phase {
            Phase::Destination(read) => read.finish_search(session, access),
            Phase::Reference { read, .. } => read.finish_search(session, access),
            _ => Ok(()),
        }
    }
    fn result(
        self,
        session: &Session,
        access: &SessionAccess<'_>,
    ) -> Result<AttributeMutationReport> {
        let Phase::Complete(report) = self.phase else {
            return Err(Error::Rejected(crate::RejectionReason::ObjectMutation(
                crate::ObjectMutationRejection::AttributeMutationIncomplete,
            )));
        };
        report.destination.check_context(session)?;
        session.metadata_result(access, Some(self.epoch), Ok(report))
    }
}
fn fingerprint_recipe(read: crate::AttributeReadPlan) -> Recipe<'static> {
    Recipe::Fingerprint {
        fields: &[
            crate::attributes::FingerprintAttribute::Class,
            crate::attributes::FingerprintAttribute::KeyType,
        ],
        plan: read,
    }
}
mod runner;
pub(super) use runner::set;

/// Keep direct setters that cannot discover a dynamic observation allocation
/// on their existing path, without a synthetic resident byte admission.
pub(super) fn required(
    object: &ManagedObjectRef,
    input: &[crate::AttributeInput<'_>],
    selection: &crate::ObjectMutationPlan,
    content: &crate::ContentMutationPlan,
) -> Result<bool> {
    let identity = InputIdentity::new(object.identity.class, input, Some(&object.identity));
    Ok(ReferenceInitial::requires_preparation(
        &selection.source,
        object,
        reference::content_plan(&content.before),
    )? || !selection.before.attributes.is_empty()
        || !selection.after.attributes.is_empty()
        || reference::content_plan(&content.after).is_some()
        || identity
            .identity()
            .query_allocation_bytes(&selection.destination)?
            != 0)
}
