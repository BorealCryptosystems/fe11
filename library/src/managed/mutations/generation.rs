// SPDX-License-Identifier: Apache-2.0
//! Native generation with caller templates and a shared creation lifetime.
use super::{input_identity::InputIdentity, outputs, Reservation};
use crate::{
    attribute_values::InputTemplate,
    native::{
        generation::{parameters::Parameters, KeyGeneration, PairGeneration},
        template::NativeTemplate,
    },
    Error, GenerationTemplate, KeyGenerator, KeyPairGenerator, ManagedClass, NativeGeneratedObject,
    NativeKeyGeneration, NativeKeyPair, Result, Session,
};

impl Session {
    /// Generate one secret key, OTP key or domain-parameter object.
    ///
    /// The selected mechanism defines the structural result class. Template
    /// attributes, including an explicit conflicting CKA_CLASS, are passed to the
    /// module unchanged. No default key size, mathematical test, persistence or
    /// usage policy is introduced. Availability and native refusals stay native.
    ///
    /// All known template/frame storage is reserved before acquiring the session.
    /// Once the native result is registered, observation failure is returned
    /// alongside the owned object in CreatedObjects; it does not destroy it.
    /// Only a failure to establish native-result ownership can require targeted
    /// cleanup with an ObjectsMayRemain diagnostic. Do not retry automatically.
    pub fn generate_native_key(
        &self,
        generator: KeyGenerator,
        request: GenerationTemplate<'_>,
    ) -> Result<crate::CreatedObjects<crate::NativeObjectView>> {
        let mut diagnostics = crate::error::PreparedCreationDiagnostics::default();
        self.generate_native_key_selected(
            NativeKeyGeneration::Simple(generator),
            request,
            &mut diagnostics,
        )
        .map(|outcome| outcome.map(|generated| generated.object))
    }

    /// Generate with owned native parameters and retain auxiliary output.
    /// Passwords are passed as exact bytes; no terminator, encoding conversion,
    /// iteration minimum or local key mathematics is imposed. DSA seed capacity
    /// is selected by the caller; no native probe or automatic replay is made.
    pub fn generate_native_key_with_parameters(
        &self,
        generator: NativeKeyGeneration<'_>,
        request: GenerationTemplate<'_>,
    ) -> Result<crate::CreatedObjects<NativeGeneratedObject>> {
        let mut diagnostics = crate::error::PreparedCreationDiagnostics::default();
        self.generate_native_key_selected(generator, request, &mut diagnostics)
    }

    fn generate_native_key_selected(
        &self,
        generator: NativeKeyGeneration<'_>,
        request: GenerationTemplate<'_>,
        diagnostics: &mut crate::error::PreparedCreationDiagnostics,
    ) -> Result<crate::CreatedObjects<NativeGeneratedObject>> {
        if let NativeKeyGeneration::Extension { request, .. } = &generator {
            request
                .contract
                .check(&self.inner, crate::ExtensionOperation::GenerateKey)?;
        }
        let plan = InputTemplate::plan_scoped(request.attributes, request.limits, &self.inner)?;
        let class = generator.object_class();
        let specs = || [outputs::Spec::new(class, &request, "generated content")];
        let observation_bytes = outputs::Initial::requested(specs())?;
        let epoch = self.snapshot.authentication_stamp();
        let parameter_bytes = Parameters::payload_bytes(&generator)?;
        let mut required = plan
            .prepared_allocation_bytes()?
            .checked_add(KeyGeneration::allocation_bytes())
            .and_then(|n| n.checked_add(parameter_bytes))
            .and_then(|n| n.checked_add(observation_bytes))
            .ok_or(Error::Rejected(crate::RejectionReason::ObjectCreation(
                crate::ObjectCreationRejection::KeyGenerationStorageAccounting,
            )))?;
        let reference_admission = self.reference_admission_at_epoch(
            crate::session::ReferenceMode::Synchronous,
            epoch,
            |state| {
                state.native.table.C_GenerateKey.ok_or(Error::Rejected(
                    crate::RejectionReason::NativeExecution(
                        crate::NativeExecutionRejection::CGenerateKeyUnavailable,
                    ),
                ))?;
                Ok(())
            },
        )?;
        let identity = InputIdentity::new(class, request.attributes, None);
        let destinations = [identity.destination(self)?];
        let (((prepared, observations, registry, permits, prepaid), reservation), state) =
            Reservation::prepare_generation_prepaid(
                self,
                &destinations,
                epoch,
                reference_admission.progress(),
                |overhead, current| loop {
                    self.snapshot.check_authentication_unchanged(epoch)?;
                    let admitted = required.checked_add(overhead).ok_or(Error::Rejected(
                        crate::RejectionReason::ObjectCreation(
                            crate::ObjectCreationRejection::CreationAggregateAccounting,
                        ),
                    ))?;
                    let group =
                        reference_admission.managed_with_observation_storage(1, admitted, || {
                            crate::session::recovery::observations::context(
                                self,
                                Some(epoch),
                                epoch,
                            )?;
                            if !current()? {
                                return Err(Error::Busy(crate::BusyReason::ObjectCreation(
                                    crate::ObjectCreationBusy::GenerationCreationPlanChanged,
                                )));
                            }
                            Ok(())
                        });
                    let (permits, mut prepaid) = match group {
                        Ok(group) => group,
                        // Internal sizing redirect, never an externally imposed
                        // Immediate policy. The original deadline is unchanged.
                        Err(Error::Busy(crate::BusyReason::ObjectCreation(
                            crate::ObjectCreationBusy::GenerationCreationPlanChanged,
                        ))) => return Ok(None),
                        Err(error) => return Err(error),
                    };
                    let template = plan.allocate()?;
                    let parameters =
                        crate::native::generation::parameters::Storage::allocate(&generator)?;
                    let observations = outputs::Initial::allocate(specs())?;
                    let observation_bytes = observations.allocated_bytes()?;
                    let actual = template
                        .allocated_bytes()?
                        .checked_add(parameters.allocated_bytes()?)
                        .and_then(|n| n.checked_add(KeyGeneration::allocation_bytes()))
                        .and_then(|n| n.checked_add(observation_bytes))
                        .and_then(|bytes| bytes.checked_add(overhead))
                        .ok_or(Error::Rejected(crate::RejectionReason::ObjectCreation(
                            crate::ObjectCreationRejection::KeyGenerationStorageAccounting,
                        )))?;
                    if actual > admitted {
                        drop((template, parameters, observations));
                        drop((prepaid, permits));
                        required = actual.checked_sub(overhead).ok_or(Error::Rejected(
                            crate::RejectionReason::ObjectCreation(
                                crate::ObjectCreationRejection::CreationAggregateAccounting,
                            ),
                        ))?;
                        continue;
                    }
                    prepaid.release(admitted - actual);
                    prepaid.observation_budget()?;
                    let template = template.bind(&mut prepaid)?;
                    let parameters = parameters.bind(&generator, &mut prepaid)?;
                    template.check_extensions(&self.inner)?;
                    let prepared = KeyGeneration::new(
                        generator.native(),
                        NativeTemplate::Typed(template),
                        parameters,
                        prepaid.split(KeyGeneration::allocation_bytes())?,
                    );
                    let registry = crate::session::recovery::observations::Prepared::allocate(
                        &self.inner.symmetric_budget,
                        &mut prepaid,
                    )?;
                    let coordination = prepaid.split(overhead)?;
                    return Ok(Some((
                        (prepared, observations, registry, permits, prepaid),
                        coordination,
                    )));
                },
                |access| reference_admission.check(access),
            )?;
        reference_admission.check(&state)?;

        self.entry(&state)?;
        if state.native.table.C_GenerateKey.is_none() {
            return Err(Error::Rejected(crate::RejectionReason::NativeExecution(
                crate::NativeExecutionRejection::CGenerateKeyUnavailable,
            )));
        }
        let (coordination, state, diagnostic, cleanup) = observations.publish(
            self,
            state,
            outputs::PreparedCall::Key(Box::new(prepared)),
            &reservation,
            permits,
            [request.into_content()],
            outputs::Order::EachReferenceThenContent,
            epoch,
            registry,
            prepaid,
        )?;
        drop(reservation);
        let (diagnostic, cleanup) = diagnostics.install(diagnostic, cleanup);
        outputs::run(
            self,
            reference_admission.progress(),
            epoch,
            coordination,
            state,
            diagnostic,
            cleanup,
            |access, owner, _cleanup| {
                let object = owner
                    .take_reference(self, access, 0)?
                    .ok_or(Error::Rejected(crate::RejectionReason::ObjectCreation(
                        crate::ObjectCreationRejection::GeneratedObjectAbsent,
                    )))?;
                let outputs::Output::Key { value, .. } = owner.take_output()? else {
                    return Err(Error::Rejected(crate::RejectionReason::ObjectCreation(
                        crate::ObjectCreationRejection::GeneratedOutputKind,
                    )));
                };
                Ok(NativeGeneratedObject {
                    object,
                    output: value?,
                })
            },
        )
    }

    /// Generate a native key pair from two exact caller templates.
    ///
    /// Both templates and the native frame share one memory reservation before
    /// native access. No local RSA/DSA/EC/PQC mathematical validation or implicit
    /// export is performed. Each reference receives its own observed access and
    /// explicitly requested admission/content/destination report.
    ///
    /// Native creation is atomic under PKCS#11; local observation is not.
    /// Once published, both objects remain owned if an observation fails.
    /// Only an intrinsic publication failure may require targeted cleanup;
    /// failed or uncertain cleanup retains ObjectsMayRemain. No replay occurs.
    pub fn generate_native_key_pair(
        &self,
        generator: KeyPairGenerator,
        public: GenerationTemplate<'_>,
        private: GenerationTemplate<'_>,
    ) -> Result<crate::CreatedObjects<NativeKeyPair>> {
        let mut diagnostics = crate::error::PreparedCreationDiagnostics::default();
        self.generate_native_key_pair_owned(
            generator.native(),
            None,
            public,
            private,
            &mut diagnostics,
        )
    }

    /// Generate a pair in one native call using an explicitly asserted owned ABI.
    /// All declared writable parameters and both object outputs remain owned.
    pub fn generate_extension_key_pair(
        &self,
        request: crate::ExtensionRequest<'_>,
        public: GenerationTemplate<'_>,
        private: GenerationTemplate<'_>,
    ) -> Result<crate::CreatedObjects<NativeKeyPair>> {
        let mut diagnostics = crate::error::PreparedCreationDiagnostics::default();
        self.generate_extension_key_pair_selected(request, public, private, &mut diagnostics)
    }

    fn generate_extension_key_pair_selected(
        &self,
        request: crate::ExtensionRequest<'_>,
        public: GenerationTemplate<'_>,
        private: GenerationTemplate<'_>,
        diagnostics: &mut crate::error::PreparedCreationDiagnostics,
    ) -> Result<crate::CreatedObjects<NativeKeyPair>> {
        request
            .contract
            .check(&self.inner, crate::ExtensionOperation::GenerateKeyPair)?;
        self.generate_native_key_pair_owned(
            request.contract.native_mechanism(),
            Some(request),
            public,
            private,
            diagnostics,
        )
    }

    fn generate_native_key_pair_owned(
        &self,
        mechanism: fe11_sys::CK_MECHANISM_TYPE,
        extension: Option<crate::ExtensionRequest<'_>>,
        public: GenerationTemplate<'_>,
        private: GenerationTemplate<'_>,
        diagnostics: &mut crate::error::PreparedCreationDiagnostics,
    ) -> Result<crate::CreatedObjects<NativeKeyPair>> {
        // Measure both graphs before retaining either. In Wait mode, splitting
        // this into two ordinary template constructors could wait on ourselves.
        let public_plan =
            InputTemplate::plan_scoped(public.attributes, public.limits, &self.inner)?;
        let private_plan =
            InputTemplate::plan_scoped(private.attributes, private.limits, &self.inner)?;
        let specs = || {
            [
                outputs::Spec::new(ManagedClass::PublicKey, &public, "generated public content"),
                outputs::Spec::new(
                    ManagedClass::PrivateKey,
                    &private,
                    "generated private content",
                ),
            ]
        };
        let parameter_bytes = extension
            .as_ref()
            .map(|request| {
                crate::mechanism_extension::OwnedGraph::allocation_bytes(&request.parameters)
            })
            .transpose()?
            .unwrap_or(0);
        let observation_bytes = outputs::Initial::requested(specs())?;
        let epoch = self.snapshot.authentication_stamp();
        let mut required = public_plan
            .prepared_allocation_bytes()?
            .checked_add(private_plan.prepared_allocation_bytes()?)
            .and_then(|bytes| bytes.checked_add(parameter_bytes))
            .and_then(|bytes| bytes.checked_add(PairGeneration::allocation_bytes()))
            .and_then(|bytes| bytes.checked_add(observation_bytes))
            .ok_or(Error::Rejected(crate::RejectionReason::ObjectCreation(
                crate::ObjectCreationRejection::KeyPairGenerationStorageAccounting,
            )))?;
        let reference_admission = self.reference_admission_at_epoch(
            crate::session::ReferenceMode::Synchronous,
            epoch,
            |state| {
                state.native.table.C_GenerateKeyPair.ok_or(Error::Rejected(
                    crate::RejectionReason::NativeExecution(
                        crate::NativeExecutionRejection::CGenerateKeyPairUnavailable,
                    ),
                ))?;
                Ok(())
            },
        )?;
        let public_identity = InputIdentity::new(ManagedClass::PublicKey, public.attributes, None);
        let private_identity =
            InputIdentity::new(ManagedClass::PrivateKey, private.attributes, None);
        let destinations = [
            public_identity.destination(self)?,
            private_identity.destination(self)?,
        ];
        let (((prepared, observations, registry, permits, prepaid), reservation), state) =
            Reservation::prepare_generation_prepaid(
                self,
                &destinations,
                epoch,
                reference_admission.progress(),
                |overhead, current| loop {
                    self.snapshot.check_authentication_unchanged(epoch)?;
                    let admitted = required.checked_add(overhead).ok_or(Error::Rejected(
                        crate::RejectionReason::ObjectCreation(
                            crate::ObjectCreationRejection::CreationAggregateAccounting,
                        ),
                    ))?;
                    let group =
                        reference_admission.managed_with_observation_storage(2, admitted, || {
                            crate::session::recovery::observations::context(
                                self,
                                Some(epoch),
                                epoch,
                            )?;
                            if !current()? {
                                return Err(Error::Busy(crate::BusyReason::ObjectCreation(
                                    crate::ObjectCreationBusy::GenerationCreationPlanChanged,
                                )));
                            }
                            Ok(())
                        });
                    let (permits, mut prepaid) = match group {
                        Ok(group) => group,
                        // Internal sizing redirect, never an externally imposed
                        // Immediate policy. The original deadline is unchanged.
                        Err(Error::Busy(crate::BusyReason::ObjectCreation(
                            crate::ObjectCreationBusy::GenerationCreationPlanChanged,
                        ))) => return Ok(None),
                        Err(error) => return Err(error),
                    };
                    let parameters = extension
                        .as_ref()
                        .map(|request| {
                            crate::mechanism_extension::GraphStorage::allocate(&request.parameters)
                        })
                        .transpose()?;
                    let parameter_bytes = parameters
                        .as_ref()
                        .map(|graph| graph.allocated_bytes())
                        .transpose()?
                        .unwrap_or(0);
                    let public_storage = public_plan.allocate()?;
                    let private_storage = private_plan.allocate()?;
                    let observations = outputs::Initial::allocate(specs())?;
                    let observation_bytes = observations.allocated_bytes()?;
                    let actual = public_storage
                        .allocated_bytes()?
                        .checked_add(private_storage.allocated_bytes()?)
                        .and_then(|bytes| bytes.checked_add(parameter_bytes))
                        .and_then(|n| n.checked_add(PairGeneration::allocation_bytes()))
                        .and_then(|n| n.checked_add(observation_bytes))
                        .and_then(|bytes| bytes.checked_add(overhead))
                        .ok_or(Error::Rejected(crate::RejectionReason::ObjectCreation(
                            crate::ObjectCreationRejection::KeyPairGenerationStorageAccounting,
                        )))?;
                    if actual > admitted {
                        drop((public_storage, private_storage, observations, parameters));
                        drop((prepaid, permits));
                        required = actual.checked_sub(overhead).ok_or(Error::Rejected(
                            crate::RejectionReason::ObjectCreation(
                                crate::ObjectCreationRejection::CreationAggregateAccounting,
                            ),
                        ))?;
                        continue;
                    }
                    prepaid.release(admitted - actual);
                    prepaid.observation_budget()?;
                    let public = public_storage.bind(&mut prepaid)?;
                    let private = private_storage.bind(&mut prepaid)?;
                    public.check_extensions(&self.inner)?;
                    private.check_extensions(&self.inner)?;
                    let parameters = match (parameters, extension.as_ref()) {
                        (Some(graph), Some(request)) => Parameters::extension(
                            request.contract.clone(),
                            graph.bind(&mut prepaid)?,
                        ),
                        (None, None) => Parameters::None,
                        _ => {
                            return Err(Error::Rejected(crate::RejectionReason::ObjectCreation(
                                crate::ObjectCreationRejection::PairParameterPreparationChanged,
                            )))
                        }
                    };
                    let prepared = PairGeneration::new(
                        mechanism,
                        NativeTemplate::Typed(public),
                        NativeTemplate::Typed(private),
                        prepaid.split(PairGeneration::allocation_bytes())?,
                    )
                    .with_parameters(parameters);
                    let registry = crate::session::recovery::observations::Prepared::allocate(
                        &self.inner.symmetric_budget,
                        &mut prepaid,
                    )?;
                    let coordination = prepaid.split(overhead)?;
                    return Ok(Some((
                        (prepared, observations, registry, permits, prepaid),
                        coordination,
                    )));
                },
                |access| reference_admission.check(access),
            )?;
        reference_admission.check(&state)?;

        self.entry(&state)?;
        if state.native.table.C_GenerateKeyPair.is_none() {
            return Err(Error::Rejected(crate::RejectionReason::NativeExecution(
                crate::NativeExecutionRejection::CGenerateKeyPairUnavailable,
            )));
        }
        let (coordination, state, diagnostic, cleanup) = observations.publish(
            self,
            state,
            outputs::PreparedCall::Pair(Box::new(prepared)),
            &reservation,
            permits,
            [public.into_content(), private.into_content()],
            outputs::Order::AllReferencesThenContent,
            epoch,
            registry,
            prepaid,
        )?;
        drop(reservation);
        let (diagnostic, cleanup) = diagnostics.install(diagnostic, cleanup);
        outputs::run(
            self,
            reference_admission.progress(),
            epoch,
            coordination,
            state,
            diagnostic,
            cleanup,
            |access, owner, _cleanup| {
                let public = owner
                    .take_reference(self, access, 0)?
                    .ok_or(Error::Rejected(crate::RejectionReason::ObjectCreation(
                        crate::ObjectCreationRejection::GeneratedPublicObjectAbsent,
                    )))?;
                let private = owner
                    .take_reference(self, access, 1)?
                    .ok_or(Error::Rejected(crate::RejectionReason::ObjectCreation(
                        crate::ObjectCreationRejection::GeneratedPrivateObjectAbsent,
                    )))?;
                let public_access = public.identity.access();
                let private_access = private.identity.access();
                private_access.result(self, access, public_access.result(self, access, Ok(())))?;
                let outputs::Output::Pair { value, .. } = owner.take_output()? else {
                    return Err(Error::Rejected(crate::RejectionReason::ObjectCreation(
                        crate::ObjectCreationRejection::PairAuxiliaryOutputOwner,
                    )));
                };
                Ok(NativeKeyPair {
                    public,
                    private,
                    output: value?,
                })
            },
        )
    }
}

impl crate::AdvancedSession {
    /// Synchronous parameterized native generation with its auxiliary output.
    pub fn generate_native_key_with_parameters(
        &self,
        generator: NativeKeyGeneration<'_>,
        request: GenerationTemplate<'_>,
    ) -> Result<crate::CreatedObjects<NativeGeneratedObject>> {
        let mut diagnostics = crate::error::PreparedCreationDiagnostics::default();
        self.session
            .generate_native_key_selected(generator, request, &mut diagnostics)
    }

    /// Synchronous generation through the same owner as Session. This does not
    /// enable native asynchronous mode or create a worker thread. See Session::generate_native_key.
    pub fn generate_native_key(
        &self,
        generator: KeyGenerator,
        request: GenerationTemplate<'_>,
    ) -> Result<crate::CreatedObjects<crate::NativeObjectView>> {
        let mut diagnostics = crate::error::PreparedCreationDiagnostics::default();
        self.session
            .generate_native_key_selected(
                NativeKeyGeneration::Simple(generator),
                request,
                &mut diagnostics,
            )
            .map(|outcome| outcome.map(|generated| generated.object))
    }

    /// Synchronous key-pair generation with identical native effects, ownership
    /// and diagnostics. See Session::generate_native_key_pair.
    pub fn generate_native_key_pair(
        &self,
        generator: KeyPairGenerator,
        public: GenerationTemplate<'_>,
        private: GenerationTemplate<'_>,
    ) -> Result<crate::CreatedObjects<NativeKeyPair>> {
        let mut diagnostics = crate::error::PreparedCreationDiagnostics::default();
        self.session.generate_native_key_pair_owned(
            generator.native(),
            None,
            public,
            private,
            &mut diagnostics,
        )
    }
}

impl crate::AdvancedSession {
    /// Synchronous owned extension generation; no worker or native asynchronous mode operation.
    pub fn generate_extension_key_pair(
        &self,
        request: crate::ExtensionRequest<'_>,
        public: GenerationTemplate<'_>,
        private: GenerationTemplate<'_>,
    ) -> Result<crate::CreatedObjects<NativeKeyPair>> {
        let mut diagnostics = crate::error::PreparedCreationDiagnostics::default();
        self.session.generate_extension_key_pair_selected(
            request,
            public,
            private,
            &mut diagnostics,
        )
    }
}
