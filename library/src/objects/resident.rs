// SPDX-License-Identifier: Apache-2.0
//! Resident generation/selection for the original ObjectRef RSA interface.
use super::*;
use crate::{
    attributes::owned::resident::{LegacyOwner, ReadStorage, Recipe, ValueNeed},
    destination_controls::resident::{DestinationOwner, Initial as DestinationInitial},
    managed::search::{self, SearchCollection, SearchOwner, SearchStorage},
    native::generation::PairGeneration,
    session::{
        observation_protection::{MutationProtection, ObservationProtection},
        recovery::observations::{context, Prepared, Waiting},
        SessionAccess,
    },
    symmetric::memory::Credit,
};
mod preparation;
mod runner;
pub(super) use runner::{find, generate};

/// Both leaves remain charged at the public generation boundary, including
/// errors composed after the resident owner has been retired.
pub(super) type GenerationDiagnostics = Option<(
    crate::error::PreparedCompletionStorage,
    crate::error::PreparedCompletionStorage,
)>;

enum Request {
    Generate(KeySpec),
    Find { selector: ObjectSelector },
}
impl Request {
    fn id(&self) -> &[u8] {
        match self {
            Self::Generate(spec) => &spec.id,
            Self::Find { selector, .. } => &selector.id,
        }
    }
    fn admission(&self, class: ObjectClass) -> &crate::ObjectAdmission {
        match self {
            Self::Generate(spec) => {
                if class == ObjectClass::PublicKey {
                    &spec.public_admission
                } else {
                    &spec.private_admission
                }
            }
            Self::Find { selector, .. } => &selector.admission,
        }
    }
    fn selected_class(&self) -> ObjectClass {
        match self {
            Self::Generate(_) => ObjectClass::PublicKey,
            Self::Find { selector, .. } => selector.class,
        }
    }
    fn maximum(&self) -> [usize; 2] {
        [
            self.admission(ObjectClass::PublicKey)
                .metadata
                .maximum_bytes,
            self.admission(ObjectClass::PrivateKey)
                .metadata
                .maximum_bytes,
        ]
    }
}
struct Generation {
    call: Box<PairGeneration>,
    creation: crate::managed::PreparedCreation,
}
enum Phase {
    PublicDestinationReady {
        public: DestinationInitial,
        private: DestinationInitial,
        generation: Generation,
    },
    PublicDestination {
        read: Box<DestinationOwner>,
        private: DestinationInitial,
        generation: Generation,
    },
    PrivateDestinationReady {
        public: crate::DestinationReport,
        private: DestinationInitial,
        generation: Generation,
    },
    PrivateDestination {
        public: crate::DestinationReport,
        read: Box<DestinationOwner>,
        generation: Generation,
    },
    NativeReady {
        reports: [crate::DestinationReport; 2],
        generation: Generation,
    },
    InFlight {
        reports: [crate::DestinationReport; 2],
    },
    PublicSearchReady {
        public: Option<SearchStorage>,
        private: Option<SearchStorage>,
    },
    PublicSearch {
        read: SearchOwner,
        private: Option<SearchStorage>,
    },
    PrivateSearchReady {
        public: SearchCollection,
        private: Option<SearchStorage>,
    },
    PrivateSearch {
        public: SearchCollection,
        read: SearchOwner,
    },
    Pair {
        origin: Origin,
        read: Box<super::pair_observation::Owner>,
    },
    Properties {
        origin: Origin,
        evidence: Evidence,
        before: Published,
        class: ObjectClass,
        read: LegacyOwner,
    },
    Complete {
        origin: Origin,
        evidence: Evidence,
        identities: Identities,
    },
    Stopped,
}
enum Origin {
    Generated {
        reports: [crate::DestinationReport; 2],
        handles: [CK_OBJECT_HANDLE; 2],
    },
    Selected {
        reports: [crate::ObjectSearchReport; 2],
        handles: [CK_OBJECT_HANDLE; 2],
    },
}
impl Origin {
    fn handles(&self) -> [CK_OBJECT_HANDLE; 2] {
        match self {
            Self::Generated { handles, .. } | Self::Selected { handles, .. } => *handles,
        }
    }
}
struct Evidence {
    fingerprint: PublicKeyFingerprint,
    modulus_bits: [usize; 2],
    public_der: Option<crate::crypto::integer_key::PublicDer>,
}
enum Published {
    None,
    Public(Arc<ObjectIdentity>),
}
enum Identities {
    Pair {
        public: Arc<ObjectIdentity>,
        private: Arc<ObjectIdentity>,
    },
    Selected(Arc<ObjectIdentity>),
}
#[derive(Clone, Copy, PartialEq, Eq)]
enum Need {
    Activate,
    Native,
    Search(search::SearchNeed),
    Pair(super::pair_observation::Need),
    Properties(ValueNeed),
}
enum NativePublication {
    Prepared([Arc<crate::managed::NativeIdentity>; 2]),
    Published([Arc<crate::managed::NativeIdentity>; 2]),
}
impl NativePublication {
    fn identity(&self, slot: usize) -> Option<&Arc<crate::managed::NativeIdentity>> {
        match self {
            Self::Published(identities) => identities.get(slot),
            Self::Prepared(_) => None,
        }
    }
}
pub(crate) struct Owner {
    publication: Option<NativePublication>,
    retained_creation: Option<crate::managed::CreationTicket>,
    phase: Phase,
    request: Request,
    pair: Option<super::pair_observation::Initial>,
    properties: [Option<ReadStorage>; 2],
    permit: crate::registry::Reservation<crate::managed::NativeIdentity>,
    protection: ObservationProtection,
    epoch: u64,
    prepaid: Credit,
    _credit: Credit,
}
pub(super) enum ResultValue {
    Pair(KeyPair),
    Reference(ObjectRef),
}
fn index(class: ObjectClass) -> usize {
    if class == ObjectClass::PublicKey {
        0
    } else {
        1
    }
}
impl Owner {
    pub(crate) fn pending(&self) -> bool {
        match &self.phase {
            Phase::InFlight { .. } => true,
            Phase::PublicDestination { read, .. } | Phase::PrivateDestination { read, .. } => {
                read.pending()
            }
            Phase::PublicSearch { read, .. } | Phase::PrivateSearch { read, .. } => read.pending(),
            Phase::Pair { read, .. } => read.pending(),
            Phase::Properties { read, .. } => read.pending(),
            _ => false,
        }
    }
    pub(crate) fn search_claimed(&self) -> bool {
        match &self.phase {
            Phase::PublicDestination { read, .. } | Phase::PrivateDestination { read, .. } => {
                read.search_claimed()
            }
            Phase::PublicSearch { read, .. } | Phase::PrivateSearch { read, .. } => read.claimed(),
            _ => false,
        }
    }
    fn activation_search(&self) -> bool {
        match &self.phase {
            Phase::PublicDestinationReady { public, .. } => public.has_search(),
            Phase::PrivateDestinationReady { private, .. } => private.has_search(),
            Phase::PublicSearchReady { .. } | Phase::PrivateSearchReady { .. } => true,
            _ => false,
        }
    }
    fn need(&mut self) -> Result<Option<Need>> {
        Ok(match &mut self.phase {
            Phase::PublicDestinationReady { .. }
            | Phase::PrivateDestinationReady { .. }
            | Phase::PublicSearchReady { .. }
            | Phase::PrivateSearchReady { .. } => Some(Need::Activate),
            Phase::NativeReady { .. } => Some(Need::Native),
            Phase::PublicDestination { read, .. } | Phase::PrivateDestination { read, .. } => {
                read.need()?.map(Need::Search)
            }
            Phase::PublicSearch { read, .. } | Phase::PrivateSearch { read, .. } => {
                read.need()?.map(Need::Search)
            }
            Phase::Pair { read, .. } => read.need().map(Need::Pair),
            Phase::Properties { read, .. } => read.need().map(Need::Properties),
            _ => None,
        })
    }
    fn activate(&mut self, session: &Session, access: &SessionAccess<'_>) -> Result<()> {
        // Bind through the current phase. Its graph remains resident on any
        // refusal; remove the old phase only after the fallible work succeeds.
        match &mut self.phase {
            Phase::PublicDestinationReady { public, .. } => {
                let mut protection = Some(self.protection.duplicate()?);
                let read = public.bind_retained(
                    session,
                    access,
                    &self.request.admission(ObjectClass::PublicKey).destination,
                    None,
                    self.epoch,
                    &mut protection,
                    &mut self.prepaid,
                )?;
                let Phase::PublicDestinationReady {
                    private,
                    generation,
                    ..
                } = std::mem::replace(&mut self.phase, Phase::Stopped)
                else {
                    unreachable!("validated public destination phase")
                };
                self.phase = Phase::PublicDestination {
                    read: Box::new(read),
                    private,
                    generation,
                };
            }
            Phase::PrivateDestinationReady { private, .. } => {
                let mut protection = Some(self.protection.duplicate()?);
                let read = private.bind_retained(
                    session,
                    access,
                    &self.request.admission(ObjectClass::PrivateKey).destination,
                    None,
                    self.epoch,
                    &mut protection,
                    &mut self.prepaid,
                )?;
                let Phase::PrivateDestinationReady {
                    public, generation, ..
                } = std::mem::replace(&mut self.phase, Phase::Stopped)
                else {
                    unreachable!("validated private destination phase")
                };
                self.phase = Phase::PrivateDestination {
                    public,
                    read: Box::new(read),
                    generation,
                };
            }
            Phase::PublicSearchReady { public, .. } => {
                SearchOwner::check_functions(access)?;
                let read = SearchStorage::bind_retained(
                    public,
                    self.request.admission(ObjectClass::PublicKey).search,
                    self.epoch,
                    access,
                    &mut self.prepaid,
                )?;
                let Phase::PublicSearchReady { private, .. } =
                    std::mem::replace(&mut self.phase, Phase::Stopped)
                else {
                    unreachable!("validated public search phase")
                };
                self.phase = Phase::PublicSearch { read, private };
            }
            Phase::PrivateSearchReady { private, .. } => {
                let read = SearchStorage::bind_retained(
                    private,
                    self.request.admission(ObjectClass::PrivateKey).search,
                    self.epoch,
                    access,
                    &mut self.prepaid,
                )?;
                let Phase::PrivateSearchReady { public, .. } =
                    std::mem::replace(&mut self.phase, Phase::Stopped)
                else {
                    unreachable!("validated private search phase")
                };
                self.phase = Phase::PrivateSearch { public, read };
            }
            _ => {
                return Err(Error::Rejected(crate::RejectionReason::ObjectObservation(
                    crate::ObjectObservationRejection::RsaObjectActivationPhase,
                )))
            }
        }
        Ok(())
    }
    fn begin_pair(&mut self, origin: Origin) -> Result<Phase> {
        let read = self
            .pair
            .take()
            .ok_or(Error::Rejected(crate::RejectionReason::ObjectObservation(
                crate::ObjectObservationRejection::RsaPairPreparationAbsent,
            )))?
            .bind(
                origin.handles(),
                self.epoch,
                self.protection.duplicate()?,
                &mut self.prepaid,
            )?;
        Ok(Phase::Pair {
            origin,
            read: Box::new(read),
        })
    }
    fn begin_properties(
        &mut self,
        origin: Origin,
        evidence: Evidence,
        before: Published,
        class: ObjectClass,
    ) -> Result<Phase> {
        let storage = self.properties[index(class)].take().ok_or(Error::Rejected(
            crate::RejectionReason::ObjectObservation(
                crate::ObjectObservationRejection::RsaPropertyPreparationAbsent,
            ),
        ))?;
        let read = storage.bind_with_protection(
            &mut self.prepaid,
            Recipe::Controls(self.request.admission(class)),
            origin.handles()[index(class)],
            Some(self.epoch),
            self.protection.duplicate()?,
        )?;
        Ok(Phase::Properties {
            origin,
            evidence,
            before,
            class,
            read,
        })
    }
    fn advance(&mut self, session: &Session, access: &SessionAccess<'_>) -> Result<()> {
        context(session, Some(self.epoch), self.epoch)?;
        session.entry(access)?;
        loop {
            match &mut self.phase {
                Phase::PublicDestination { read, .. } | Phase::PrivateDestination { read, .. } => {
                    read.advance(session, access)?;
                    if !read.complete() {
                        return Ok(());
                    }
                }
                Phase::PublicSearch { read, .. } | Phase::PrivateSearch { read, .. } => {
                    read.advance(session, access)?;
                    if !read.complete() {
                        return Ok(());
                    }
                }
                Phase::Pair { read, .. } => {
                    read.advance(session, access)?;
                    if !read.complete() {
                        return Ok(());
                    }
                }
                Phase::Properties {
                    origin,
                    class,
                    read,
                    ..
                } => {
                    read.advance(session, access, origin.handles()[index(*class)])?;
                    if !read.complete() {
                        return Ok(());
                    }
                }
                Phase::Stopped | Phase::InFlight { .. } => {
                    return Err(Error::Rejected(crate::RejectionReason::ObjectObservation(
                        crate::ObjectObservationRejection::RsaObjectOperationStopped,
                    )))
                }
                _ => return Ok(()),
            }
            self.phase = match std::mem::replace(&mut self.phase, Phase::Stopped) {
                Phase::PublicDestination {
                    read,
                    private,
                    generation,
                } => Phase::PrivateDestinationReady {
                    public: read.result(session, access)?,
                    private,
                    generation,
                },
                Phase::PrivateDestination {
                    public,
                    read,
                    generation,
                } => Phase::NativeReady {
                    reports: [public, read.result(session, access)?],
                    generation,
                },
                Phase::PublicSearch { read, private } => Phase::PrivateSearchReady {
                    public: read.into_collection()?,
                    private,
                },
                Phase::PrivateSearch { public, read } => {
                    let private = read.into_collection()?;
                    let Request::Find { selector, .. } = &self.request else {
                        return Err(Error::Rejected(crate::RejectionReason::ObjectObservation(
                            crate::ObjectObservationRejection::RsaObjectSearchRequest,
                        )));
                    };
                    let (public_selection, private_selection) =
                        if selector.class == ObjectClass::PublicKey {
                            (&selector.admission.selection, &selector.companion_selection)
                        } else {
                            (&selector.companion_selection, &selector.admission.selection)
                        };
                    let (public_handle, public_report) = public_selection.select(&public)?;
                    let (private_handle, private_report) = private_selection.select(&private)?;
                    self.begin_pair(Origin::Selected {
                        reports: [public_report, private_report],
                        handles: [public_handle, private_handle],
                    })?
                }
                Phase::Pair { origin, read } => {
                    let observed = read.result()?;
                    let public_der = if matches!(self.request, Request::Generate(_)) {
                        Some(observed.public_der)
                    } else {
                        drop(observed.public_der);
                        None
                    };
                    let evidence = Evidence {
                        fingerprint: observed.fingerprint,
                        modulus_bits: observed.modulus_bits,
                        public_der,
                    };
                    self.begin_properties(
                        origin,
                        evidence,
                        Published::None,
                        self.request.selected_class(),
                    )?
                }
                Phase::Properties {
                    origin,
                    evidence,
                    before,
                    class,
                    read,
                } => {
                    let properties = read.object_observations_result(
                        session,
                        access,
                        self.request.admission(class),
                    )?;
                    let identity = session.publish_rsa_object_observation(
                        access,
                        origin.handles()[index(class)],
                        class,
                        self.request.id(),
                        evidence.modulus_bits[index(class)],
                        properties,
                        self.epoch,
                        &mut self.permit,
                        self.publication
                            .as_ref()
                            .and_then(|publication| publication.identity(index(class))),
                    )?;
                    match (&self.request, before) {
                        (Request::Generate(_), Published::None) => self.begin_properties(
                            origin,
                            evidence,
                            Published::Public(identity),
                            ObjectClass::PrivateKey,
                        )?,
                        (Request::Generate(_), Published::Public(public)) => Phase::Complete {
                            origin,
                            evidence,
                            identities: Identities::Pair {
                                public,
                                private: identity,
                            },
                        },
                        (Request::Find { .. }, Published::None) => Phase::Complete {
                            origin,
                            evidence,
                            identities: Identities::Selected(identity),
                        },
                        _ => {
                            return Err(Error::Rejected(crate::RejectionReason::ObjectObservation(
                                crate::ObjectObservationRejection::RsaObjectPublicationPhase,
                            )))
                        }
                    }
                }
                _ => {
                    return Err(Error::Rejected(crate::RejectionReason::ObjectObservation(
                        crate::ObjectObservationRejection::RsaObjectTransition,
                    )))
                }
            };
        }
    }
    fn dispatch(&mut self, session: &Session, access: &SessionAccess<'_>) -> Result<Generation> {
        let Phase::NativeReady {
            reports,
            generation,
        } = std::mem::replace(&mut self.phase, Phase::Stopped)
        else {
            return Err(Error::Rejected(crate::RejectionReason::ObjectObservation(
                crate::ObjectObservationRejection::RsaGenerationDispatchPhase,
            )));
        };
        reports[0].check_context(session)?;
        reports[1].check_context(session)?;
        access.retain_observation_protection(self.protection.duplicate()?)?;
        self.phase = Phase::InFlight { reports };
        Ok(generation)
    }
    fn returned(
        &mut self,
        handles: [CK_OBJECT_HANDLE; 2],
        creation: crate::managed::CreationTicket,
        session: &Session,
        access: &SessionAccess<'_>,
        mark_remaining: impl FnOnce(Error) -> Error,
    ) -> Result<()> {
        let Phase::InFlight { reports } = std::mem::replace(&mut self.phase, Phase::Stopped) else {
            return Err(Error::Rejected(crate::RejectionReason::ObjectObservation(
                crate::ObjectObservationRejection::RsaGenerationReturnPhase,
            )));
        };

        self.retained_creation = Some(creation);
        let Some(NativePublication::Prepared(identities)) = &mut self.publication else {
            return Err(Error::Rejected(crate::RejectionReason::ObjectObservation(
                crate::ObjectObservationRejection::RsaPublicationPreparationAbsent,
            )));
        };
        for (identity, handle) in identities.iter_mut().zip(handles) {
            crate::managed::NativeIdentity::publish_into(
                identity,
                &session.inner,
                &session.entry,
                handle,
                &mut self.permit,
                &access.objects,
            )?;
        }
        let Some(NativePublication::Prepared(identities)) = self.publication.take() else {
            unreachable!()
        };
        self.publication = Some(NativePublication::Published(identities));
        session.mutation_context(access, mark_remaining)?;
        self.phase = self.begin_pair(Origin::Generated { reports, handles })?;
        Ok(())
    }
    fn finish_search(&mut self, session: &Session, access: &SessionAccess<'_>) -> Result<()> {
        match &mut self.phase {
            Phase::PublicDestination { read, .. } | Phase::PrivateDestination { read, .. } => {
                read.finish_search(session, access)
            }
            Phase::PublicSearch { read, .. } | Phase::PrivateSearch { read, .. } => {
                read.finish(session, access)
            }
            _ => Ok(()),
        }
    }

    fn created_objects(&self, session: &Session) -> Option<crate::CreatedObjectSet> {
        let NativePublication::Published(identities) = self.publication.as_ref()? else {
            return None;
        };
        let reference = |index: usize| crate::NativeObjectRef {
            inner: session.inner.clone(),
            identity: identities[index].clone(),
            output_slot: Some(index),
        };
        Some(crate::CreatedObjectSet::pair([reference(0), reference(1)]))
    }
    fn result(&mut self, session: &Session) -> Result<ResultValue> {
        let Phase::Complete {
            origin,
            mut evidence,
            identities,
        } = std::mem::replace(&mut self.phase, Phase::Stopped)
        else {
            return Err(Error::Rejected(crate::RejectionReason::ObjectObservation(
                crate::ObjectObservationRejection::RsaObjectResultIncomplete,
            )));
        };
        let reference = |identity: Arc<ObjectIdentity>| ObjectRef {
            pair_search: None,
            destination_report: None,
            inner: session.inner.clone(),
            session: session.uid,
            handle: identity.handle,
            identity,
        };
        match (origin, identities) {
            (
                Origin::Generated {
                    reports: [public_report, private_report],
                    ..
                },
                Identities::Pair { public, private },
            ) => {
                public_report.check_context(session)?;
                private_report.check_context(session)?;
                let mut public = reference(public);
                let mut private = reference(private);
                public.destination_report = Some(public_report);
                private.destination_report = Some(private_report);
                let public_der = evidence
                    .public_der
                    .take()
                    .ok_or(Error::Rejected(crate::RejectionReason::ObjectObservation(
                        crate::ObjectObservationRejection::RsaPublicEncodingAbsent,
                    )))?
                    .into_bytes();
                Ok(ResultValue::Pair(KeyPair {
                    public,
                    private,
                    fingerprint: evidence.fingerprint,
                    public_der,
                }))
            }
            (Origin::Selected { reports, .. }, Identities::Selected(identity)) => {
                let mut reference = reference(identity);
                reference.pair_search = Some(reports);
                Ok(ResultValue::Reference(reference))
            }
            _ => Err(Error::Rejected(crate::RejectionReason::ObjectObservation(
                crate::ObjectObservationRejection::RsaObjectResultKind,
            ))),
        }
    }
}
