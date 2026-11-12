// SPDX-License-Identifier: Apache-2.0
//! Parent, native derivation and child evidence form one resident operation.
//!
//! A completed parent or child observation never leaves this owner while new
//! metadata storage is admitted. The first child snapshot remains distinct
//! from the output owner's requested attributes. Neither snapshot is a policy.
use super::{observation, operations::DeriveCall, output_observation, *};
use crate::{
    attributes::owned::resident::{LegacyOwner, ReadStorage, Recipe, ValueNeed},
    destination_controls::resident::{DestinationOwner, Initial as DestinationInitial},
    managed::{
        discovery::{self, preparation::SelectedInitial, DiscoveryOwner},
        search,
    },
    native::creation::CreatedObject,
    session::{
        observation_protection::{MutationProtection, ObservationProtection},
        recovery::observations::{context, Prepared, Waiting},
        SessionAccess,
    },
    symmetric::memory::Credit,
    ManagedClass, Session,
};
use std::sync::Arc;

#[derive(Clone, Copy)]
pub(super) enum ParentSelection {
    Ordinary {
        shape: observation::Spec,
        path: DerivationPath,
    },
    Introduced {
        shape: observation::Spec,
        kdf: EcdhKdf,
    },
}
impl ParentSelection {
    fn shape(self) -> observation::Spec {
        match self {
            Self::Ordinary { shape, .. } | Self::Introduced { shape, .. } => shape,
        }
    }
    fn owned(self) -> ParentControl {
        match self {
            Self::Ordinary { path, .. } => ParentControl::Ordinary { path },
            Self::Introduced { kdf, .. } => ParentControl::Introduced { kdf },
        }
    }
}
enum ParentControl {
    Ordinary { path: DerivationPath },
    Introduced { kdf: EcdhKdf },
}
pub(super) enum Provenance {
    Ordinary(DerivationProvenance),
    Introduced(IntroducedDerivationProvenance),
}
pub(super) struct Evidence {
    pub(super) provenance: Provenance,

    pub(super) output: output_observation::Evidence,
}
struct ParentEvidence {
    snapshot: BaseProtection,
}
struct ChildEvidence {
    provenance: Provenance,
}
enum Phase {
    Parent(Box<observation::Owner>),
    DestinationReady(ParentEvidence),
    Destination {
        parent: ParentEvidence,
        read: Box<DestinationOwner>,
    },
    Ready {
        parent: ParentEvidence,
        destination: crate::DestinationReport,
    },
    InFlight {
        parent: ParentEvidence,
        destination: crate::DestinationReport,
    },
    Child {
        parent: ParentEvidence,
        destination: crate::DestinationReport,
        read: Option<LegacyOwner>,
    },
    Output {
        evidence: ChildEvidence,
        destination: crate::DestinationReport,
        read: Box<output_observation::Owner>,
    },

    Admission {
        evidence: Evidence,
        destination: crate::DestinationReport,
        read: Box<DiscoveryOwner>,
    },
    Stopped,
}
enum Native {
    Prepared {
        call: DeriveCall,
        creation: crate::managed::PreparedCreation,
    },
    Created(CreatedObject),
    Stopped,
}
#[derive(Clone, Copy, PartialEq, Eq)]
enum Need {
    Destination,
    Native,
    Search(search::SearchNeed),
    Metadata(ValueNeed),
    Admission(discovery::Need),
}
pub(super) struct Dispatch {
    pub(super) call: DeriveCall,
    pub(super) creation: crate::managed::PreparedCreation,
}
pub(crate) struct DerivationOwner {
    publication: crate::managed::SinglePublication,
    phase: Phase,
    native: Native,
    destination: Option<DestinationInitial>,
    child: Option<ReadStorage>,
    child_selection: HistoryObservationPlan,
    output: Option<output_observation::Initial>,
    reference: Option<SelectedInitial>,
    permit: Option<crate::registry::Reservation<crate::managed::NativeIdentity>>,
    admission: crate::ObjectAdmission,
    parent_control: ParentControl,
    epoch: u64,
    protection: Arc<MutationProtection>,
    prepaid: Credit,
    _credit: Credit,
}
impl DerivationOwner {
    pub(crate) fn pending(&self) -> bool {
        match &self.phase {
            Phase::Parent(read) => read.pending(),
            Phase::Destination { read, .. } => read.pending(),
            Phase::Child { read, .. } => read.as_ref().is_some_and(LegacyOwner::pending),
            Phase::Output { read, .. } => read.pending(),
            Phase::Admission { read, .. } => read.pending(),
            Phase::InFlight { .. } => true,
            _ => false,
        }
    }
    pub(crate) fn search_claimed(&self) -> bool {
        matches!(&self.phase, Phase::Destination { read, .. } if read.search_claimed())
    }
    fn complete(&self) -> bool {
        matches!(&self.phase, Phase::Admission { read, .. } if read.complete())
    }
    fn need(&mut self) -> Result<Option<Need>> {
        Ok(match &mut self.phase {
            Phase::Parent(read) => read.need().map(Need::Metadata),
            Phase::Destination { read, .. } => read.need()?.map(Need::Search),
            Phase::Child { read, .. } => read
                .as_ref()
                .and_then(LegacyOwner::need)
                .map(Need::Metadata),
            Phase::Output { read, .. } => read.need().map(Need::Metadata),
            Phase::Admission { read, .. } => read.need()?.map(Need::Admission),
            Phase::DestinationReady(_) => Some(Need::Destination),
            Phase::Ready { .. } => Some(Need::Native),
            _ => None,
        })
    }
    fn created(&self) -> Result<CK_OBJECT_HANDLE> {
        match &self.native {
            Native::Created(created) => Ok(created.handle),
            _ => Err(Error::Rejected(crate::RejectionReason::KeyDerivation(
                crate::KeyDerivationRejection::DerivedObjectAbsent,
            ))),
        }
    }

    fn child_report(&self, parent: ParentEvidence, child: BaseProtection) -> ChildEvidence {
        let provenance = match &self.parent_control {
            ParentControl::Ordinary { path } => {
                Provenance::Ordinary(DerivationProvenance::new(*path, parent.snapshot, child))
            }
            ParentControl::Introduced { kdf } => Provenance::Introduced(
                IntroducedDerivationProvenance::new(*kdf, parent.snapshot, child),
            ),
        };
        ChildEvidence { provenance }
    }

    fn admit(
        &mut self,
        destination: crate::DestinationReport,
        evidence: ChildEvidence,
        output: output_observation::Evidence,
    ) -> Result<Phase> {
        let reference =
            self.reference
                .take()
                .ok_or(Error::Rejected(crate::RejectionReason::KeyDerivation(
                    crate::KeyDerivationRejection::DerivedReferencePreparationAbsent,
                )))?;
        let permit =
            self.permit
                .take()
                .ok_or(Error::Rejected(crate::RejectionReason::KeyDerivation(
                    crate::KeyDerivationRejection::DerivedReferenceQuotaTransferred,
                )))?;
        let read = reference.bind(
            ManagedClass::SecretKey,
            self.created()?,
            self.admission.clone(),
            crate::ContentObservation::NotRequested,
            "derived content",
            permit,
            self.epoch,
            ObservationProtection::mutation(&self.protection),
            &mut self.prepaid,
        )?;
        let read = read.retain_native(
            self.publication
                .identity()
                .ok_or(Error::Rejected(crate::RejectionReason::KeyDerivation(
                    crate::KeyDerivationRejection::DerivationNativeLifetimeAbsent,
                )))?
                .clone(),
        );
        Ok(Phase::Admission {
            destination,
            read: Box::new(read),
            evidence: Evidence {
                provenance: evidence.provenance,
                output,
            },
        })
    }
    fn advance(&mut self, session: &Session, access: &SessionAccess<'_>) -> Result<()> {
        context(session, Some(self.epoch), self.epoch)?;
        session.entry(access)?;
        loop {
            let created = if matches!(self.phase, Phase::Child { .. }) {
                Some(self.created()?)
            } else {
                None
            };
            match &mut self.phase {
                Phase::Parent(read) => {
                    read.advance(session, access)?;
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
                Phase::Child {
                    read: Some(read), ..
                } => {
                    read.advance(session, access, created.expect("child phase handle"))?;
                    if !read.complete() {
                        return Ok(());
                    }
                }
                Phase::Child { read: None, .. } => {}
                Phase::Output { read, .. } => {
                    read.advance(session, access)?;
                    if !read.complete() {
                        return Ok(());
                    }
                }
                Phase::Admission { read, .. } => {
                    read.advance(session, access)?;
                    return Ok(());
                }
                Phase::Ready { .. } | Phase::DestinationReady(_) => return Ok(()),
                _ => {
                    return Err(Error::Rejected(crate::RejectionReason::KeyDerivation(
                        crate::KeyDerivationRejection::DerivationObservationStopped,
                    )))
                }
            }
            self.phase = match std::mem::replace(&mut self.phase, Phase::Stopped) {
                Phase::Parent(read) => {
                    let snapshot = read.result()?;
                    let parent = ParentEvidence { snapshot };
                    Phase::DestinationReady(parent)
                }
                Phase::Destination { parent, read } => {
                    let destination = read.result(session, access)?;
                    destination.check_context(session)?;
                    Phase::Ready {
                        parent,
                        destination,
                    }
                }
                Phase::Child {
                    parent,
                    destination,
                    read,
                } => {
                    let child = match read {
                        Some(read) => read.history_result(session, access, self.child_selection)?,
                        None => history::snapshot(
                            self.child_selection,
                            &crate::attributes::ObservedAttributes::empty(),
                        ),
                    };
                    let evidence = self.child_report(parent, child);
                    let read = self
                        .output
                        .take()
                        .ok_or(Error::Rejected(crate::RejectionReason::KeyDerivation(
                            crate::KeyDerivationRejection::DerivedOutputPreparationAbsent,
                        )))?
                        .bind(
                            self.created()?,
                            self.epoch,
                            ObservationProtection::mutation(&self.protection),
                            &mut self.prepaid,
                        )?;
                    Phase::Output {
                        evidence,
                        destination,
                        read: Box::new(read),
                    }
                }
                Phase::Output {
                    evidence,
                    destination,
                    read,
                } => {
                    let output = read.result()?;
                    self.admit(destination, evidence, output)?
                }
                _ => {
                    return Err(Error::Rejected(crate::RejectionReason::KeyDerivation(
                        crate::KeyDerivationRejection::DerivationCompletionPhase,
                    )))
                }
            };
        }
    }
    fn activate_destination(
        &mut self,
        session: &Session,
        access: &SessionAccess<'_>,
    ) -> Result<()> {
        if !matches!(self.phase, Phase::DestinationReady(_)) {
            return Err(Error::Rejected(crate::RejectionReason::KeyDerivation(
                crate::KeyDerivationRejection::DerivationDestinationPhase,
            )));
        };
        let initial = self.destination.as_mut().ok_or(Error::Rejected(
            crate::RejectionReason::KeyDerivation(
                crate::KeyDerivationRejection::DerivationDestinationAbsent,
            ),
        ))?;
        let mut protection = Some(ObservationProtection::mutation(&self.protection));
        let read = initial.bind_retained(
            session,
            access,
            &self.admission.destination,
            None,
            self.epoch,
            &mut protection,
            &mut self.prepaid,
        )?;
        drop(self.destination.take());
        let Phase::DestinationReady(parent) = std::mem::replace(&mut self.phase, Phase::Stopped)
        else {
            unreachable!("validated derivation destination phase")
        };
        self.phase = Phase::Destination {
            parent,
            read: Box::new(read),
        };
        Ok(())
    }
    fn take_dispatch(&mut self, access: &SessionAccess<'_>) -> Result<Dispatch> {
        access.retain_observation_protection(ObservationProtection::mutation(&self.protection))?;
        let Phase::Ready {
            parent,
            destination,
        } = std::mem::replace(&mut self.phase, Phase::Stopped)
        else {
            return Err(Error::Rejected(crate::RejectionReason::KeyDerivation(
                crate::KeyDerivationRejection::DerivationDispatchPhase,
            )));
        };
        let Native::Prepared { call, creation } =
            std::mem::replace(&mut self.native, Native::Stopped)
        else {
            return Err(Error::Rejected(crate::RejectionReason::KeyDerivation(
                crate::KeyDerivationRejection::DerivationCallAbsent,
            )));
        };
        self.phase = Phase::InFlight {
            parent,
            destination,
        };
        Ok(Dispatch { call, creation })
    }
    fn returned(
        &mut self,
        result: Result<CreatedObject>,
        session: &Session,
        access: &SessionAccess<'_>,
        cleanup: &mut crate::error::CleanupStorage,
    ) -> Result<()> {
        let Phase::InFlight {
            parent,
            destination,
        } = std::mem::replace(&mut self.phase, Phase::Stopped)
        else {
            return Err(Error::Rejected(crate::RejectionReason::KeyDerivation(
                crate::KeyDerivationRejection::DerivationReturnPhase,
            )));
        };
        self.native = Native::Created(result?);
        let handle = self.created()?;
        self.publication.publish(
            session,
            access,
            handle,
            self.permit
                .as_mut()
                .ok_or(Error::Rejected(crate::RejectionReason::KeyDerivation(
                    crate::KeyDerivationRejection::DerivationPublicationQuotaAbsent,
                )))?,
        )?;
        session.mutation_context(access, |cause| cleanup.mark_remaining(cause))?;
        let handle = self.created()?;
        let read = self
            .child
            .take()
            .map(|storage| {
                storage.bind_with_protection(
                    &mut self.prepaid,
                    Recipe::History(self.child_selection),
                    handle,
                    Some(self.epoch),
                    ObservationProtection::mutation(&self.protection),
                )
            })
            .transpose()?;
        self.phase = Phase::Child {
            parent,
            destination,
            read,
        };
        Ok(())
    }
    fn finish_search(&mut self, session: &Session, access: &SessionAccess<'_>) -> Result<()> {
        match &mut self.phase {
            Phase::Destination { read, .. } => read.finish_search(session, access),
            _ => Ok(()),
        }
    }
    fn cleanup(
        &mut self,
        session: &Session,
        access: &SessionAccess<'_>,
        cause: Error,
        storage: &mut crate::error::CleanupStorage,
    ) -> Error {
        match std::mem::replace(&mut self.native, Native::Stopped) {
            Native::Created(created) => crate::managed::cleanup_prepared(
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
    fn result(
        &mut self,
        session: &Session,
        access: &SessionAccess<'_>,
    ) -> Result<(ManagedObjectRef, Evidence)> {
        let Phase::Admission {
            read,
            destination,
            evidence,
        } = std::mem::replace(&mut self.phase, Phase::Stopped)
        else {
            return Err(Error::Rejected(crate::RejectionReason::KeyDerivation(
                crate::KeyDerivationRejection::DerivationIncomplete,
            )));
        };
        let mut reference = read.result(session, access)?;
        destination.check_context(session)?;
        reference.destination_report = Some(destination);
        let reference = reference
            .identity
            .access
            .result(session, access, Ok(reference))?;
        Ok((reference, evidence))
    }
}

mod preparation;
pub(super) use preparation::Initial;
mod runner;
pub(super) use runner::run;
