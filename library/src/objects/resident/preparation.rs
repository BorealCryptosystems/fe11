// SPDX-License-Identifier: Apache-2.0
//! Prepare both RSA snapshots and all known source/destination storage together.
use super::*;
use crate::attributes::{OwnedTemplateStorage, TemplateSink, TemplateSize};
use crate::destination_controls::DestinationIdentity;
use crate::native::template::NativeTemplate;

enum Start {
    Generate {
        public: DestinationInitial,
        private: DestinationInitial,
        public_template: OwnedTemplateStorage,
        private_template: OwnedTemplateStorage,
    },
    Find {
        public: SearchStorage,
        private: SearchStorage,
    },
}
pub(super) struct Initial {
    start: Start,
    pair: super::super::pair_observation::Initial,
    properties: [Option<ReadStorage>; 2],
}
fn add(a: usize, b: usize) -> Result<usize> {
    a.checked_add(b)
        .ok_or(Error::Rejected(crate::RejectionReason::ObjectObservation(
            crate::ObjectObservationRejection::RsaObjectGraphSize,
        )))
}
fn search_template<T: TemplateSink>(class: ObjectClass, id: &[u8]) -> T {
    let mut template = T::empty();
    template.integer(CKA_CLASS, class.raw());
    template.bytes(CKA_ID, id);
    template
}
fn destination(spec: &KeySpec, class: ObjectClass) -> DestinationIdentity<'_> {
    DestinationIdentity::KeyOrCertificate {
        class: if class == ObjectClass::PublicKey {
            crate::ManagedClass::PublicKey
        } else {
            crate::ManagedClass::PrivateKey
        },
        id: &spec.id,
        label: spec.label.as_bytes(),
    }
}
impl Initial {
    fn fixed(request: &Request) -> Result<usize> {
        let proof = match request {
            Request::Generate(_) => add(
                MutationProtection::allocation_bytes(),
                2 * crate::managed::NativeIdentity::allocation_bytes(),
            )?,
            Request::Find { .. } => ObservationProtection::selection_bytes(),
        };
        add(
            add(std::mem::size_of::<Owner>(), Prepared::allocation_bytes())?,
            proof,
        )
    }
    pub(super) fn requested(request: &Request) -> Result<usize> {
        let mut bytes = add(
            Self::fixed(request)?,
            super::super::pair_observation::Initial::requested(request.maximum())?,
        )?;
        for class in [ObjectClass::PublicKey, ObjectClass::PrivateKey] {
            if matches!(request, Request::Generate(_)) || class == request.selected_class() {
                bytes = add(
                    bytes,
                    ReadStorage::requested(Recipe::Controls(request.admission(class)))?,
                )?;
            }
        }
        match request {
            Request::Generate(spec) => {
                bytes = add(bytes, PairGeneration::public_frame_bytes())?;
                for class in [ObjectClass::PublicKey, ObjectClass::PrivateKey] {
                    bytes = add(
                        bytes,
                        super::super::template::<TemplateSize>(spec, class).owned_bytes()?,
                    )?;
                    bytes = add(
                        bytes,
                        DestinationInitial::requested(
                            &request.admission(class).destination,
                            &destination(spec, class),
                        )?,
                    )?;
                }
            }
            Request::Find { selector, .. } => {
                for class in [ObjectClass::PublicKey, ObjectClass::PrivateKey] {
                    bytes = add(
                        bytes,
                        SearchStorage::requested_bytes(
                            search_template::<TemplateSize>(class, &selector.id).owned_bytes()?,
                            selector.admission.search,
                        )?,
                    )?;
                }
            }
        }
        Ok(bytes)
    }
    pub(super) fn allocate(request: &Request) -> Result<Self> {
        let pair = super::super::pair_observation::Initial::allocate(request.maximum())?;
        let mut properties = [None, None];
        for class in [ObjectClass::PublicKey, ObjectClass::PrivateKey] {
            if matches!(request, Request::Generate(_)) || class == request.selected_class() {
                properties[index(class)] = Some(ReadStorage::allocate(Recipe::Controls(
                    request.admission(class),
                ))?);
            }
        }
        let start = match request {
            Request::Generate(spec) => Start::Generate {
                public: DestinationInitial::allocate(
                    &spec.public_admission.destination,
                    &destination(spec, ObjectClass::PublicKey),
                )?,
                private: DestinationInitial::allocate(
                    &spec.private_admission.destination,
                    &destination(spec, ObjectClass::PrivateKey),
                )?,
                public_template: OwnedTemplateStorage::allocate(super::super::template(
                    spec,
                    ObjectClass::PublicKey,
                ))?,
                private_template: OwnedTemplateStorage::allocate(super::super::template(
                    spec,
                    ObjectClass::PrivateKey,
                ))?,
            },
            Request::Find { selector, .. } => Start::Find {
                public: SearchStorage::allocate_owned(
                    search_template::<Template>(ObjectClass::PublicKey, &selector.id),
                    selector.admission.search,
                )?,
                private: SearchStorage::allocate_owned(
                    search_template::<Template>(ObjectClass::PrivateKey, &selector.id),
                    selector.admission.search,
                )?,
            },
        };
        Ok(Self {
            start,
            pair,
            properties,
        })
    }
    pub(super) fn allocated_bytes(&self, request: &Request) -> Result<usize> {
        let mut bytes = add(Self::fixed(request)?, self.pair.allocated_bytes()?)?;
        for read in self.properties.iter().flatten() {
            bytes = add(bytes, read.allocated_bytes()?)?;
        }
        match &self.start {
            Start::Generate {
                public,
                private,
                public_template,
                private_template,
            } => {
                for count in [
                    PairGeneration::public_frame_bytes(),
                    public.allocated_bytes()?,
                    private.allocated_bytes()?,
                    public_template.allocated_bytes()?,
                    private_template.allocated_bytes()?,
                ] {
                    bytes = add(bytes, count)?;
                }
            }
            Start::Find { public, private } => {
                bytes = add(
                    add(bytes, public.allocated_bytes()?)?,
                    private.allocated_bytes()?,
                )?;
            }
        }
        Ok(bytes)
    }
    pub(super) fn publish<'a>(
        self,
        request: Request,
        session: &Session,
        access: SessionAccess<'a>,
        reservation: Option<&crate::managed::Reservation>,
        mut permit: crate::registry::Reservation<crate::managed::NativeIdentity>,
        epoch: u64,
        registry: Prepared,
        mut prepaid: Credit,
        selection: Option<crate::managed::PreparedManagedSelection>,
    ) -> Result<(
        Arc<crate::session::recovery::observations::Coordination>,
        SessionAccess<'a>,
    )> {
        // Declare partial results before the local access, so refusal releases
        // possession before either a prepared native identity or the registry.
        let public_identity;
        let private_identity;
        let publication;
        let owner_credit;
        let mut registry = Some(registry);
        let (phase, protection, access) = match self.start {
            Start::Generate {
                public,
                private,
                public_template,
                private_template,
            } => {
                // Arm-local owners precede access for failures before a complete
                // phase exists. Both template credits transfer as one group.
                let creation;
                let call;
                let proof;
                let access = access;
                let reservation = reservation.ok_or(Error::Rejected(
                    crate::RejectionReason::ObjectObservation(
                        crate::ObjectObservationRejection::RsaCreationReservationAbsent,
                    ),
                ))?;
                creation = reservation.prepare_creation_ticket(session)?;
                let [public_credit, private_credit, call_credit] = prepaid.split_group([
                    public_template.allocated_bytes()?,
                    private_template.allocated_bytes()?,
                    PairGeneration::public_frame_bytes(),
                ])?;
                call = PairGeneration::new(
                    CKM_RSA_PKCS_KEY_PAIR_GEN,
                    NativeTemplate::Public(public_template.into_prepaid(public_credit)),
                    NativeTemplate::Public(private_template.into_prepaid(private_credit)),
                    call_credit,
                );
                proof = MutationProtection::take(session, &access, &mut prepaid)?;
                (
                    Phase::PublicDestinationReady {
                        public,
                        private,
                        generation: Generation {
                            call: Box::new(call),
                            creation,
                        },
                    },
                    ObservationProtection::mutation(&proof),
                    access,
                )
            }
            Start::Find { public, private } => {
                let mut selected;
                let mut owned_selection;
                let mut selection = selection;
                let access = access;
                selected = selection
                    .as_mut()
                    .ok_or(Error::Rejected(crate::RejectionReason::ObjectObservation(
                        crate::ObjectObservationRejection::RsaSelectionPreparationAbsent,
                    )))?
                    .select_retained(session)?;
                owned_selection =
                    Some(selected.into_owned_retained(&session.inner, &session.entry)?);
                let protection = ObservationProtection::selection_retained(
                    session,
                    &mut owned_selection,
                    &mut prepaid,
                )?;
                (
                    Phase::PublicSearchReady {
                        public: Some(public),
                        private: Some(private),
                    },
                    protection,
                    access,
                )
            }
        };
        publication = if matches!(request, Request::Generate(_)) {
            // Separate bindings retain the first identity if the second refuses.
            public_identity = crate::managed::NativeIdentity::prepare_creation(
                session,
                epoch,
                &mut permit,
                &mut prepaid,
            )?;
            private_identity = crate::managed::NativeIdentity::prepare_creation(
                session,
                epoch,
                &mut permit,
                &mut prepaid,
            )?;
            Some(NativePublication::Prepared([
                public_identity,
                private_identity,
            ]))
        } else {
            None
        };
        owner_credit = prepaid.split(std::mem::size_of::<Owner>())?;
        let owner = Owner {
            publication,
            retained_creation: None,
            phase,
            request,
            pair: Some(self.pair),
            properties: self.properties,
            permit,
            protection,
            epoch,
            prepaid,
            _credit: owner_credit,
        };
        registry = Some(
            registry
                .take()
                .expect("RSA registry preparation")
                .bind_rsa_objects(owner),
        );
        let coordination = session
            .entry
            .recovery
            .observations
            .publish_retained(&mut registry)?;
        Ok((coordination, access))
    }
}
