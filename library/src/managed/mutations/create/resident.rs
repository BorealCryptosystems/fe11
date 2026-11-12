// SPDX-License-Identifier: Apache-2.0
//! Destination observation and publication for a single native object creation.
use crate::managed::mutations::*;
use crate::{
    attributes::owned::resident::{LegacyOwner, ReadStorage, Recipe, ValueNeed},
    destination_controls::{
        resident::{DestinationOwner, Initial as DestinationInitial},
        DestinationIdentity,
    },
    managed::discovery::{self, preparation::SelectedInitial, DiscoveryOwner},
    native::creation::{CreatedObject, ObjectCreation},
    session::{
        observation_protection::{MutationProtection, ObservationProtection},
        recovery::observations::{context, Prepared, Waiting},
        SessionAccess,
    },
    symmetric::memory::Credit,
};
use search::{SearchCandidate, SearchNeed, SearchPreparation, SearchWithdrawal};

enum Phase {
    Destination(Box<DestinationOwner>),
    ReadyUnwrap(crate::DestinationReport),
    UnwrapInFlight(crate::DestinationReport),
    ReadyKem(crate::DestinationReport),
    KemInFlight(crate::DestinationReport),
    Derived {
        destination: crate::DestinationReport,
        read: Box<crate::crypto::derivation::output_observation::Owner>,
    },
    Public {
        destination: crate::DestinationReport,
        read: Box<crate::crypto::public_import::observation::Owner>,
        publication: Option<crate::crypto::public_import::publication::Prepared>,
    },
    Private {
        destination: crate::DestinationReport,
        read: Box<private::observation::Owner>,
        public: crate::crypto::integer_key::PublicDer,
    },
    Class {
        destination: crate::DestinationReport,
        read: LegacyOwner,
    },
    Admission {
        destination: crate::DestinationReport,
        read: Box<DiscoveryOwner>,
        evidence: Evidence,
    },
    Stopped,
}
enum PostCreation {
    Derived(crate::crypto::derivation::output_observation::Initial),
    None,
    Class(ReadStorage),
    Public {
        read: crate::crypto::public_import::observation::Initial,
        publication: Option<crate::crypto::public_import::publication::Prepared>,
    },
    Private {
        read: private::observation::Initial,
        public: crate::crypto::integer_key::PublicDer,
    },
}
pub(super) enum Evidence {
    Derived {
        key: crate::crypto::derivation::output_observation::Evidence,
    },
    None,
    Public {
        mechanisms: crate::MechanismObservationReport,
        publication: Option<crate::crypto::public_import::publication::Prepared>,
    },
    Private {
        key: private::observation::Evidence,
        public: crate::crypto::integer_key::PublicDer,
    },
}
enum PreparedCall {
    Create(ObjectCreation),
    Unwrap(crate::transport::UnwrapCall),
    Kem(crate::crypto::kem::KemCall),
}
enum NativeCreation {
    Prepared {
        call: ObjectCreation,
        creation: PreparedCreation,
    },
    PreparedUnwrap {
        call: crate::transport::UnwrapCall,
        creation: PreparedCreation,
    },
    PreparedKem {
        call: crate::crypto::kem::KemCall,
        creation: PreparedCreation,
    },
    CreatedKem(crate::crypto::kem::CompletedKem),
    Created(CreatedObject),
    Stopped,
}
pub(crate) struct KemDispatch {
    pub(crate) call: crate::crypto::kem::KemCall,
    pub(crate) creation: crate::managed::PreparedCreation,
}
pub(crate) struct UnwrapDispatch {
    pub(crate) call: crate::transport::UnwrapCall,
    pub(crate) creation: crate::managed::PreparedCreation,
}
pub(crate) struct CreationOwner {
    publication: crate::managed::SinglePublication,
    ciphertext: Option<crate::symmetric::memory::Buffer>,
    phase: Phase,
    native: NativeCreation,
    post: PostCreation,
    selected: Option<SelectedInitial>,
    permit: Option<crate::registry::Reservation<crate::managed::NativeIdentity>>,
    class: ManagedClass,
    admission: crate::ObjectAdmission,
    content: crate::ContentObservation,
    protection: Arc<MutationProtection>,
    epoch: u64,
    prepaid: Credit,
    _credit: Credit,
}
#[derive(Clone, Copy, PartialEq, Eq)]
enum Need {
    Unwrap,
    Kem,
    Search(SearchNeed),
    Metadata(ValueNeed),
    Admission(discovery::Need),
}
impl CreationOwner {
    fn publish_native_object(
        &mut self,
        session: &Session,
        access: &SessionAccess<'_>,
    ) -> Result<()> {
        let handle = self.created()?;
        self.publication.publish(
            session,
            access,
            handle,
            self.permit
                .as_mut()
                .ok_or(Error::Rejected(crate::RejectionReason::ObjectCreation(
                    crate::ObjectCreationRejection::CreationPublicationQuotaAbsent,
                )))?,
        )
    }

    pub(crate) fn pending(&self) -> bool {
        match &self.phase {
            Phase::UnwrapInFlight(_) | Phase::KemInFlight(_) => true,
            Phase::ReadyKem(_) => false,
            Phase::Derived { read, .. } => read.pending(),
            Phase::ReadyUnwrap(_) => false,
            Phase::Destination(read) => read.pending(),
            Phase::Class { read, .. } => read.pending(),
            Phase::Public { read, .. } => read.pending(),
            Phase::Private { read, .. } => read.pending(),
            Phase::Admission { read, .. } => read.pending(),
            Phase::Stopped => false,
        }
    }
    pub(crate) fn search_claimed(&self) -> bool {
        matches!(&self.phase, Phase::Destination(read) if read.search_claimed())
    }
    fn complete(&self) -> bool {
        matches!(&self.phase, Phase::Admission { read, .. } if read.complete())
    }
    fn need(&mut self) -> Result<Option<Need>> {
        Ok(match &mut self.phase {
            Phase::ReadyKem(_) => Some(Need::Kem),
            Phase::KemInFlight(_) => None,
            Phase::Derived { read, .. } => read.need().map(Need::Metadata),
            Phase::ReadyUnwrap(_) => Some(Need::Unwrap),
            Phase::UnwrapInFlight(_) => None,
            Phase::Destination(read) => read.need()?.map(Need::Search),
            Phase::Class { read, .. } => read.need().map(Need::Metadata),
            Phase::Public { read, .. } => read.need().map(Need::Metadata),
            Phase::Private { read, .. } => read.need().map(Need::Metadata),
            Phase::Admission { read, .. } => read.need()?.map(Need::Admission),
            Phase::Stopped => None,
        })
    }
    fn take_kem(&mut self, access: &SessionAccess<'_>) -> Result<KemDispatch> {
        access.retain_observation_protection(ObservationProtection::mutation(&self.protection))?;
        let Phase::ReadyKem(destination) = std::mem::replace(&mut self.phase, Phase::Stopped)
        else {
            return Err(Error::Rejected(crate::RejectionReason::ObjectCreation(
                crate::ObjectCreationRejection::KemDispatchPhase,
            )));
        };
        let NativeCreation::PreparedKem { call, creation } =
            std::mem::replace(&mut self.native, NativeCreation::Stopped)
        else {
            return Err(Error::Rejected(crate::RejectionReason::ObjectCreation(
                crate::ObjectCreationRejection::KemCallAbsent,
            )));
        };
        self.phase = Phase::KemInFlight(destination);
        Ok(KemDispatch { call, creation })
    }
    fn kem_returned(
        &mut self,
        result: Result<crate::crypto::kem::CompletedKem>,
        session: &Session,
        access: &SessionAccess<'_>,
        cleanup: &mut crate::error::CleanupStorage,
    ) -> Result<()> {
        let Phase::KemInFlight(destination) = std::mem::replace(&mut self.phase, Phase::Stopped)
        else {
            return Err(Error::Rejected(crate::RejectionReason::ObjectCreation(
                crate::ObjectCreationRejection::KemCompletionPhase,
            )));
        };
        self.native = NativeCreation::CreatedKem(result?);
        // The native handle is established independently of the auxiliary
        // ciphertext length. Publish its ownership before reporting an
        // invalid ciphertext; only the caller may choose its destruction.
        self.publish_native_object(session, access)?;
        if let NativeCreation::CreatedKem(completed) = &self.native {
            if completed.length != completed.expected_length {
                return Err(Error::Rejected(crate::RejectionReason::ObjectCreation(
                    crate::ObjectCreationRejection::MlKemNativeCiphertextLength,
                )));
            }
        }
        session.mutation_context(access, |cause| cleanup.mark_remaining(cause))?;
        self.phase = self.begin_post(destination)?;
        Ok(())
    }
    fn take_unwrap(&mut self, access: &SessionAccess<'_>) -> Result<UnwrapDispatch> {
        access.retain_observation_protection(ObservationProtection::mutation(&self.protection))?;
        let Phase::ReadyUnwrap(destination) = std::mem::replace(&mut self.phase, Phase::Stopped)
        else {
            return Err(Error::Rejected(crate::RejectionReason::ObjectCreation(
                crate::ObjectCreationRejection::UnwrapDispatchPhase,
            )));
        };
        let NativeCreation::PreparedUnwrap { call, creation } =
            std::mem::replace(&mut self.native, NativeCreation::Stopped)
        else {
            return Err(Error::Rejected(crate::RejectionReason::ObjectCreation(
                crate::ObjectCreationRejection::UnwrapCallAbsent,
            )));
        };
        self.phase = Phase::UnwrapInFlight(destination);
        Ok(UnwrapDispatch { call, creation })
    }
    fn unwrap_returned(
        &mut self,
        result: Result<CreatedObject>,
        session: &Session,
        access: &SessionAccess<'_>,
        cleanup: &mut crate::error::CleanupStorage,
    ) -> Result<()> {
        let Phase::UnwrapInFlight(destination) = std::mem::replace(&mut self.phase, Phase::Stopped)
        else {
            return Err(Error::Rejected(crate::RejectionReason::ObjectCreation(
                crate::ObjectCreationRejection::UnwrapCompletionPhase,
            )));
        };
        self.native = NativeCreation::Created(result?);
        self.publish_native_object(session, access)?;
        session.mutation_context(access, |cause| cleanup.mark_remaining(cause))?;
        self.phase = self.begin_post(destination)?;
        Ok(())
    }

    fn created(&self) -> Result<CK_OBJECT_HANDLE> {
        match &self.native {
            NativeCreation::Created(created) => Ok(created.handle),
            NativeCreation::CreatedKem(completed) => Ok(completed.created.handle),
            _ => Err(Error::Rejected(crate::RejectionReason::ObjectCreation(
                crate::ObjectCreationRejection::CreatedObjectAbsent,
            ))),
        }
    }
    fn admit(
        &mut self,
        destination: crate::DestinationReport,
        evidence: Evidence,
    ) -> Result<Phase> {
        let initial =
            self.selected
                .take()
                .ok_or(Error::Rejected(crate::RejectionReason::ObjectCreation(
                    crate::ObjectCreationRejection::CreationAdmissionPreparationAbsent,
                )))?;
        let permit =
            self.permit
                .take()
                .ok_or(Error::Rejected(crate::RejectionReason::ObjectCreation(
                    crate::ObjectCreationRejection::CreationPublicationQuotaTransferred,
                )))?;
        let content = std::mem::replace(&mut self.content, crate::ContentObservation::NotRequested);
        let handle = self.created()?;
        let read = initial.bind(
            self.class,
            handle,
            self.admission.clone(),
            content,
            "created content",
            permit,
            self.epoch,
            ObservationProtection::mutation(&self.protection),
            &mut self.prepaid,
        )?;
        let read = read.retain_native(
            self.publication
                .identity()
                .ok_or(Error::Rejected(crate::RejectionReason::ObjectCreation(
                    crate::ObjectCreationRejection::CreationNativeLifetimeAbsent,
                )))?
                .clone(),
        );
        Ok(Phase::Admission {
            destination,
            read: Box::new(read),
            evidence,
        })
    }
    fn advance(
        &mut self,
        session: &Session,
        access: &SessionAccess<'_>,
        mut diagnostic: Option<&mut crate::error::PreparedCompletion>,
        receipt: &mut Option<crate::error::CompletionDiagnostic>,
        cleanup: &mut crate::error::CleanupStorage,
    ) -> Result<()> {
        context(session, Some(self.epoch), self.epoch)?;
        session.entry(access)?;
        loop {
            match &mut self.phase {
                Phase::Destination(read) => {
                    read.advance(session, access)?;
                    if !read.complete() {
                        return Ok(());
                    }
                }
                Phase::Class { read, .. } => {
                    let NativeCreation::Created(created) = &self.native else {
                        return Err(Error::Rejected(crate::RejectionReason::ObjectCreation(
                            crate::ObjectCreationRejection::CreatedObjectAbsent,
                        )));
                    };
                    read.advance(session, access, created.handle)?;
                    if !read.complete() {
                        return Ok(());
                    }
                }
                Phase::Derived { read, .. } => {
                    read.advance(session, access)?;
                    if !read.complete() {
                        return Ok(());
                    }
                }
                Phase::Public { read, .. } => {
                    read.advance(session, access)?;
                    if !read.complete() {
                        return Ok(());
                    }
                }
                Phase::Private { read, .. } => {
                    read.advance(session, access)?;
                    if !read.complete() {
                        return Ok(());
                    }
                }
                Phase::Admission { read, .. } => {
                    read.advance(session, access)?;
                    return Ok(());
                }
                Phase::ReadyUnwrap(_)
                | Phase::UnwrapInFlight(_)
                | Phase::ReadyKem(_)
                | Phase::KemInFlight(_) => return Ok(()),
                Phase::Stopped => {
                    return Err(Error::Rejected(crate::RejectionReason::ObjectCreation(
                        crate::ObjectCreationRejection::ObjectCreationStopped,
                    )))
                }
            }
            self.phase = match std::mem::replace(&mut self.phase, Phase::Stopped) {
                Phase::Destination(read) => {
                    let destination = read.result(session, access)?;
                    destination.check_context(session)?;
                    if matches!(&self.native, NativeCreation::PreparedKem { .. }) {
                        self.phase = Phase::ReadyKem(destination);
                        return Ok(());
                    }
                    if matches!(&self.native, NativeCreation::PreparedUnwrap { .. }) {
                        self.phase = Phase::ReadyUnwrap(destination);
                        return Ok(());
                    }
                    let NativeCreation::Prepared { call, mut creation } =
                        std::mem::replace(&mut self.native, NativeCreation::Stopped)
                    else {
                        return Err(Error::Rejected(crate::RejectionReason::ObjectCreation(
                            crate::ObjectCreationRejection::ObjectAlreadyCreated,
                        )));
                    };
                    let key_import = matches!(
                        self.post,
                        PostCreation::Public { .. } | PostCreation::Private { .. }
                    );

                    let completed = call.execute_resident(
                        session,
                        access,
                        &mut creation,
                        diagnostic
                            .as_mut()
                            .ok_or(Error::Rejected(crate::RejectionReason::ObjectCreation(
                                crate::ObjectCreationRejection::CreationDiagnosticAbsent,
                            )))?
                            .take()?,
                        || {},
                        cleanup,
                    )?;
                    let (created, completed) = completed.into_parts();
                    self.native = NativeCreation::Created(created);
                    // The synchronous runner keeps this receipt through publication
                    // and cleanup, even if the resident owner is retired.
                    *receipt = Some(completed);
                    self.publish_native_object(session, access)?;

                    let _ = key_import;
                    session.mutation_context(access, |cause| cleanup.mark_remaining(cause))?;
                    self.begin_post(destination)?
                }
                Phase::Derived { destination, read } => self.admit(
                    destination,
                    Evidence::Derived {
                        key: read.result()?,
                    },
                )?,
                Phase::Class { destination, read } => {
                    read.required_result(session, access)?
                        .integer(CKA_CLASS, self.class.raw())?;
                    self.admit(destination, Evidence::None)?
                }
                Phase::Public {
                    destination,
                    read,
                    publication,
                } => self.admit(
                    destination,
                    Evidence::Public {
                        mechanisms: read.result()?,
                        publication,
                    },
                )?,
                Phase::Private {
                    destination,
                    read,
                    public,
                } => self.admit(
                    destination,
                    Evidence::Private {
                        key: read.result()?,
                        public,
                    },
                )?,
                _ => {
                    return Err(Error::Rejected(crate::RejectionReason::ObjectCreation(
                        crate::ObjectCreationRejection::CreationCompletionPhase,
                    )))
                }
            };
        }
    }
    fn begin_post(&mut self, destination: crate::DestinationReport) -> Result<Phase> {
        Ok(
            match std::mem::replace(&mut self.post, PostCreation::None) {
                PostCreation::Derived(read) => {
                    let NativeCreation::CreatedKem(completed) =
                        std::mem::replace(&mut self.native, NativeCreation::Stopped)
                    else {
                        return Err(Error::Rejected(crate::RejectionReason::ObjectCreation(
                            crate::ObjectCreationRejection::KemNativeOutcomeAbsent,
                        )));
                    };
                    let crate::crypto::kem::CompletedKem {
                        created,
                        bytes,
                        length,
                        expected_length,
                    } = completed;
                    let handle = created.handle;
                    self.native = NativeCreation::Created(created);
                    if length != expected_length {
                        return Err(Error::Rejected(crate::RejectionReason::ObjectCreation(
                            crate::ObjectCreationRejection::MlKemNativeCiphertextLength,
                        )));
                    }
                    self.ciphertext = Some(bytes);
                    let read = read.bind(
                        handle,
                        self.epoch,
                        ObservationProtection::mutation(&self.protection),
                        &mut self.prepaid,
                    )?;
                    Phase::Derived {
                        destination,
                        read: Box::new(read),
                    }
                }
                PostCreation::Class(storage) => {
                    let handle = self.created()?;
                    let read = storage.bind_with_protection(
                        &mut self.prepaid,
                        class_recipe(&self.admission),
                        handle,
                        Some(self.epoch),
                        ObservationProtection::mutation(&self.protection),
                    )?;
                    Phase::Class { destination, read }
                }
                PostCreation::Public {
                    read: storage,
                    publication,
                } => Phase::Public {
                    destination,
                    publication,
                    read: Box::new(storage.bind(
                        self.created()?,
                        self.epoch,
                        ObservationProtection::mutation(&self.protection),
                        &mut self.prepaid,
                    )?),
                },
                PostCreation::Private { read, public } => Phase::Private {
                    destination,
                    read: Box::new(read.bind(
                        self.created()?,
                        self.epoch,
                        ObservationProtection::mutation(&self.protection),
                        &mut self.prepaid,
                    )?),
                    public,
                },
                PostCreation::None => self.admit(destination, Evidence::None)?,
            },
        )
    }
    fn cleanup(
        &mut self,
        session: &Session,
        access: &SessionAccess<'_>,
        cause: Error,
        storage: &mut crate::error::CleanupStorage,
    ) -> Error {
        match std::mem::replace(&mut self.native, NativeCreation::Stopped) {
            NativeCreation::Created(created) => cleanup_prepared(
                session,
                access,
                session.entry.handle,
                created.handle,
                cause,
                storage,
            ),
            NativeCreation::CreatedKem(completed) => cleanup_prepared(
                session,
                access,
                session.entry.handle,
                completed.created.handle,
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
            Phase::Destination(read) => read.finish_search(session, access),
            _ => Ok(()),
        }
    }
    fn result(
        &mut self,
        session: &Session,
        access: &SessionAccess<'_>,
    ) -> Result<(ManagedObjectRef, Evidence)> {
        let Phase::Admission {
            destination,
            read,
            evidence,
        } = std::mem::replace(&mut self.phase, Phase::Stopped)
        else {
            return Err(Error::Rejected(crate::RejectionReason::ObjectCreation(
                crate::ObjectCreationRejection::ObjectCreationIncomplete,
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
fn class_recipe(admission: &crate::ObjectAdmission) -> Recipe<'static> {
    Recipe::Required {
        fields: &[CKA_CLASS],
        maximum: admission.metadata.maximum_bytes,
    }
}

// Shared only by object creation roots. It carries no caller references after
// binding, no native result before dispatch and no independently acquired quota.
pub(in crate::managed::mutations) struct Initial {
    cleanup: crate::error::CleanupStorage,
    destination: DestinationInitial,
    post: PostCreation,
    selected: SelectedInitial,
}
impl Initial {
    pub(in crate::managed::mutations) fn fixed_bytes() -> Result<usize> {
        [
            Prepared::allocation_bytes(),
            std::mem::size_of::<CreationOwner>(),
            crate::managed::NativeIdentity::allocation_bytes(),
            MutationProtection::allocation_bytes(),
        ]
        .into_iter()
        .try_fold(0usize, |sum, bytes| {
            sum.checked_add(bytes)
                .ok_or(Error::Rejected(crate::RejectionReason::ObjectCreation(
                    crate::ObjectCreationRejection::CreationStorageSize,
                )))
        })
    }
    pub(in crate::managed::mutations) fn requested(
        class: ManagedClass,
        admission: &crate::ObjectAdmission,
        plan: &crate::DestinationPlan,
        identity: &DestinationIdentity<'_>,
        post_class: bool,
    ) -> Result<usize> {
        let mut bytes = DestinationInitial::requested(plan, identity)?;
        bytes = bytes
            .checked_add(SelectedInitial::requested(class, admission)?)
            .ok_or(Error::Rejected(crate::RejectionReason::ObjectCreation(
                crate::ObjectCreationRejection::CreationStorageSize,
            )))?;
        if post_class {
            bytes = bytes
                .checked_add(ReadStorage::requested(class_recipe(admission))?)
                .ok_or(Error::Rejected(crate::RejectionReason::ObjectCreation(
                    crate::ObjectCreationRejection::CreationStorageSize,
                )))?;
        }
        bytes
            .checked_add(crate::error::CleanupStorage::requested(1)?)
            .ok_or(Error::Rejected(crate::RejectionReason::ObjectCreation(
                crate::ObjectCreationRejection::CreationCleanupSize,
            )))
    }
    pub(in crate::managed::mutations) fn allocate(
        class: ManagedClass,
        admission: &crate::ObjectAdmission,
        plan: &crate::DestinationPlan,
        identity: &DestinationIdentity<'_>,
        post_class: bool,
    ) -> Result<Self> {
        Ok(Self {
            destination: DestinationInitial::allocate(plan, identity)?,
            post: if post_class {
                PostCreation::Class(ReadStorage::allocate(class_recipe(admission))?)
            } else {
                PostCreation::None
            },
            selected: SelectedInitial::allocate(class, admission)?,
            cleanup: crate::error::CleanupStorage::allocate(1)?,
        })
    }
    pub(in crate::managed::mutations) fn allocated_bytes(&self) -> Result<usize> {
        let class = match &self.post {
            PostCreation::None => 0,
            PostCreation::Derived(read) => read.allocated_bytes()?,
            PostCreation::Class(read) => read.allocated_bytes()?,
            PostCreation::Public { read, publication } => read
                .allocated_bytes()?
                .checked_add(
                    publication
                        .as_ref()
                        .map(|value| value.allocated_bytes())
                        .transpose()?
                        .unwrap_or(0),
                )
                .ok_or(Error::Rejected(crate::RejectionReason::ObjectCreation(
                    crate::ObjectCreationRejection::CreationStorageSize,
                )))?,
            PostCreation::Private { read, public, .. } => read
                .allocated_bytes()?
                .checked_add(public.allocated_bytes())
                .ok_or(Error::Rejected(crate::RejectionReason::ObjectCreation(
                    crate::ObjectCreationRejection::CreationStorageSize,
                )))?,
        };
        let selected = self
            .selected
            .allocated_bytes()?
            .checked_add(self.cleanup.allocated_bytes()?)
            .ok_or(Error::Rejected(crate::RejectionReason::ObjectCreation(
                crate::ObjectCreationRejection::CreationCleanupSize,
            )))?;
        self.destination
            .allocated_bytes()?
            .checked_add(class)
            .and_then(|bytes| bytes.checked_add(selected))
            .ok_or(Error::Rejected(crate::RejectionReason::ObjectCreation(
                crate::ObjectCreationRejection::CreationStorageSize,
            )))
    }
    pub(in crate::managed::mutations) fn publish<'a>(
        self,
        session: &Session,
        access: SessionAccess<'a>,
        call: ObjectCreation,
        reservation: &Reservation,
        class: ManagedClass,
        admission: crate::ObjectAdmission,
        content: crate::ContentObservation,
        plan: crate::DestinationPlan,
        permit: crate::registry::Reservation<crate::managed::NativeIdentity>,
        epoch: u64,
        registry: Prepared,
        prepaid: Credit,
    ) -> Result<(
        Arc<crate::session::recovery::observations::Coordination>,
        SessionAccess<'a>,
        crate::error::PreparedCleanupStorage,
    )> {
        self.publish_native(
            session,
            access,
            PreparedCall::Create(call),
            reservation,
            class,
            admission,
            content,
            plan,
            permit,
            epoch,
            registry,
            prepaid,
        )
    }
    fn publish_native<'a>(
        mut self,
        session: &Session,
        access: SessionAccess<'a>,
        call: PreparedCall,
        reservation: &Reservation,
        class: ManagedClass,
        admission: crate::ObjectAdmission,
        content: crate::ContentObservation,
        plan: crate::DestinationPlan,
        mut permit: crate::registry::Reservation<crate::managed::NativeIdentity>,
        epoch: u64,
        registry: Prepared,
        mut prepaid: Credit,
    ) -> Result<(
        Arc<crate::session::recovery::observations::Coordination>,
        SessionAccess<'a>,
        crate::error::PreparedCleanupStorage,
    )> {
        // Local drop order follows declaration order, even for bindings whose
        // initialization happens later. Declare every private result before
        // access, so any refusal releases access before those results and the
        // owned input parameters. Retained helpers never destroy those inputs.
        let cleanup;
        let creation;
        let protection;
        let mut observation_protection;
        let destination;
        let owner_credit;
        let publication;
        let mut registry = Some(registry);
        let access = access;
        cleanup = crate::error::PreparedCleanupStorage::bind(self.cleanup, &mut prepaid)?;
        if self.destination.has_search() {
            session
                .entry
                .recovery
                .observations
                .check_search_available()?;
        }
        creation = reservation.prepare_creation_ticket(session)?;
        protection = MutationProtection::take(session, &access, &mut prepaid)?;
        observation_protection = Some(ObservationProtection::mutation(&protection));
        destination = self.destination.bind_retained(
            session,
            &access,
            &plan,
            None,
            epoch,
            &mut observation_protection,
            &mut prepaid,
        )?;
        owner_credit = prepaid.split(std::mem::size_of::<CreationOwner>())?;
        publication =
            crate::managed::SinglePublication::prepare(session, epoch, &mut permit, &mut prepaid)?;
        let owner = CreationOwner {
            publication,
            ciphertext: None,
            phase: Phase::Destination(Box::new(destination)),
            native: match call {
                PreparedCall::Create(call) => NativeCreation::Prepared {
                    call: call.with_protection(ObservationProtection::mutation(&protection)),
                    creation,
                },
                PreparedCall::Unwrap(call) => NativeCreation::PreparedUnwrap { call, creation },
                PreparedCall::Kem(call) => NativeCreation::PreparedKem { call, creation },
            },
            post: self.post,
            selected: Some(self.selected),
            permit: Some(permit),
            class,
            admission,
            content,
            protection,
            epoch,
            prepaid,
            _credit: owner_credit,
        };
        registry = Some(
            registry
                .take()
                .expect("creation registry preparation")
                .bind_creation(owner),
        );
        let coordination = session
            .entry
            .recovery
            .observations
            .publish_retained(&mut registry)?;
        Ok((coordination, access, cleanup))
    }
}
pub(in crate::managed::mutations) mod runner;
mod typed;
pub(super) use typed::create;
mod public;
pub(crate) use public::{create_public, create_public_prepared, create_public_with_publication};
mod private;
pub(crate) use private::{
    prepare_private_creation, prepare_rsa_creation, prepare_signing_creation,
};

pub(crate) mod restoration;

pub(crate) mod kem;
