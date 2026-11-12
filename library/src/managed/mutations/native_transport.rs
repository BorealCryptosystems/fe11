// SPDX-License-Identifier: Apache-2.0
//! Generic unwrap publication through the existing creation/observation owner.
use super::{input_identity::InputIdentity, outputs, Reservation};
use crate::{
    attribute_values::InputTemplate,
    mechanism_extension::transport::{CreationInput, KeyCreation},
    Error, ExtensionRequest, ExtensionResult, GenerationTemplate, ManagedClass, NativeKemResult,
    NativeObjectRef, NativeUnwrappedObject, Result, Session,
};

impl Session {
    /// Wrap one managed object through an exact caller-asserted ABI contract.
    /// Native permissions, key suitability and blob format remain module decisions.
    /// `capacity` is an explicit allocation bound; no sizing call or retry occurs.
    /// Mechanism parameter outputs are available on the returned result.
    /// A size refusal with an input-integrity failure retains both observations
    /// in NativeOutputAndLocalFailure; the size does not permit output use/replay.
    pub fn wrap_key_extension(
        &self,
        key: &crate::NativeObjectRef,
        target: &crate::NativeObjectRef,
        request: ExtensionRequest<'_>,
        capacity: usize,
    ) -> Result<ExtensionResult> {
        let mut diagnostic = None;
        crate::mechanism_extension::transport::wrap(
            self,
            request,
            key,
            target,
            capacity,
            &mut diagnostic,
        )
    }

    /// Unwrap with the exact caller template and an explicit ABI declaration.
    /// `class` selects observation semantics, not an attribute added to the template.
    /// A returned source alias is never destroyed. CreatedObjects retains the
    /// published reference independently of optional observations and parameter
    /// outputs; their failure does not implicitly destroy the created object.
    pub fn unwrap_key_extension(
        &self,
        key: &crate::NativeObjectRef,
        blob: &[u8],
        parameters: ExtensionRequest<'_>,
        class: ManagedClass,
        request: GenerationTemplate<'_>,
    ) -> Result<crate::CreatedObjects<NativeUnwrappedObject>> {
        let mut diagnostics = crate::error::PreparedCreationDiagnostics::default();
        self.unwrap_key_with_sources(
            key,
            blob,
            parameters,
            class,
            request,
            [None; 4],
            &mut diagnostics,
        )
    }
    pub(crate) fn unwrap_key_with_sources<'a>(
        &self,
        key: &crate::NativeObjectRef,
        blob: &[u8],
        parameters: impl Into<crate::mechanism_extension::graph::recipe::Request<'a>>,
        class: ManagedClass,
        request: GenerationTemplate<'_>,
        sources: [Option<&NativeObjectRef>; 4],
        diagnostics: &mut crate::error::PreparedCreationDiagnostics,
    ) -> Result<crate::CreatedObjects<NativeUnwrappedObject>> {
        self.create_key_transport(
            Some(key),
            CreationInput::Unwrap(blob),
            parameters,
            class,
            request,
            sources,
            diagnostics,
        )
        .map(|outcome| {
            outcome.map(|result| NativeUnwrappedObject {
                object: result.object,
                parameters: result.parameters,
                provenance: result.provenance,
            })
        })
    }
    pub(crate) fn create_key_transport<'a>(
        &self,
        key: Option<&crate::NativeObjectRef>,
        input: CreationInput<'_>,
        parameters: impl Into<crate::mechanism_extension::graph::recipe::Request<'a>>,
        class: ManagedClass,
        request: GenerationTemplate<'_>,
        sources: [Option<&NativeObjectRef>; 4],
        diagnostics: &mut crate::error::PreparedCreationDiagnostics,
    ) -> Result<crate::CreatedObjects<NativeKemResult>> {
        let parameters = parameters.into();
        parameters.contract.check(&self.inner, input.operation())?;
        let mutates = parameters.contract.mutates_key();
        let provenance = parameters.contract.provenance();

        let plan = InputTemplate::plan_scoped(request.attributes, request.limits, &self.inner)?;
        let specs = || {
            [outputs::Spec::new(
                class,
                &request,
                "created key transport content",
            )]
        };
        let observation_bytes = outputs::Initial::requested(specs())?;
        let epoch = self.snapshot.authentication_stamp();
        let mut required = plan
            .prepared_allocation_bytes()?
            .checked_add(KeyCreation::allocation_bytes(&parameters, input)?)
            .and_then(|n| n.checked_add(observation_bytes))
            .ok_or(Error::Rejected(
                crate::RejectionReason::DerivedObjectCreation(
                    crate::DerivedObjectCreationRejection::KeyTransportRequestStorageAccounting,
                ),
            ))?;
        if mutates && key.is_none() {
            return Err(Error::Rejected(
                crate::RejectionReason::DerivedObjectCreation(
                    crate::DerivedObjectCreationRejection::MutatingKeyTransportRequiresARetainedKey,
                ),
            ));
        }
        let reference_admission = self.reference_admission_at_epoch(
            crate::session::ReferenceMode::Synchronous,
            epoch,
            |state| input.check_function(state),
        )?;
        let identity = InputIdentity::new(class, request.attributes, None);
        let destinations = [identity.destination(self)?];
        let (((prepared, observations, registry, permits, prepaid, targets), reservation), state) = loop {
            // The driver has returned before revocation binding. This
            // scope also retires catalogue entries after a failed binding drops
            // the returned destination, before a fresh source/session wait.
            let retirement = super::reservation_preparation::DestinationRetirement::new(self);
            retirement.retire();
            let (
                (
                    (prepared, observations, registry, permits, prepaid, mut revocations),
                    reservation,
                ),
                state,
            ) = Reservation::prepare_mutation_prepaid(
                self,
                &destinations,
                1,
                None,
                [
                    (
                        key,
                        if mutates {
                            crate::session::activity::AccessMode::Write
                        } else {
                            crate::session::activity::AccessMode::Read
                        },
                    ),
                    (sources[0], crate::session::activity::AccessMode::Read),
                    (sources[1], crate::session::activity::AccessMode::Read),
                    (sources[2], crate::session::activity::AccessMode::Read),
                    (sources[3], crate::session::activity::AccessMode::Read),
                ],
                false,
                epoch,
                reference_admission.progress(),
                |overhead, current| loop {
                    let shapes = crate::managed::RevocationSetPlan::discover(
                        self,
                        [
                            key.map(|key| key.identity.resource()),
                            sources[0].map(|key| key.identity.resource()),
                            sources[1].map(|key| key.identity.resource()),
                            sources[2].map(|key| key.identity.resource()),
                            sources[3].map(|key| key.identity.resource()),
                            if mutates {
                                key.map(|key| key.identity.resource())
                            } else {
                                None
                            },
                        ],
                        epoch,
                    )?;
                    let revocation_bytes = shapes.allocation_bytes()?;
                    let admitted = required
                        .checked_add(overhead)
                        .and_then(|n| n.checked_add(revocation_bytes))
                        .ok_or(Error::Rejected(crate::RejectionReason::DerivedObjectCreation(crate::DerivedObjectCreationRejection::KeyTransportRequestStorageAccounting)))?;
                    self.snapshot.check_authentication_unchanged(epoch)?;
                    let group =
                        reference_admission.managed_with_observation_storage(1, admitted, || {
                            crate::session::recovery::observations::context(
                                self,
                                Some(epoch),
                                epoch,
                            )?;
                            if !current()? {
                                return Err(Error::Busy(crate::BusyReason::DerivedObjectCreation(crate::DerivedObjectCreationBusy::KeyTransportCreationPlanChanged)));
                            }
                            Ok(())
                        });
                    let (permits, mut prepaid) = match group {
                        Ok(group) => group,
                        // Replan only after returning every private owner to the driver.
                        Err(Error::Busy(crate::BusyReason::DerivedObjectCreation(
                            crate::DerivedObjectCreationBusy::KeyTransportCreationPlanChanged,
                        ))) => return Ok(None),
                        Err(error) => return Err(error),
                    };
                    let revocations = shapes.allocate()?;
                    let revocation_actual = revocations.allocated_bytes()?;
                    let template = plan.allocate()?;
                    let transport =
                        crate::mechanism_extension::transport::KeyCreationStorage::allocate(
                            parameters, input,
                        )?;
                    let observations = outputs::Initial::allocate(specs())?;
                    let observation_bytes = observations.allocated_bytes()?;
                    let actual = template
                        .allocated_bytes()?
                        .checked_add(transport.allocated_bytes()?)
                        .and_then(|n| n.checked_add(observation_bytes))
                        .and_then(|bytes| bytes.checked_add(overhead))
                        .and_then(|bytes| bytes.checked_add(revocation_actual))
                        .ok_or(Error::Rejected(crate::RejectionReason::DerivedObjectCreation(crate::DerivedObjectCreationRejection::KeyTransportRequestStorageAccounting)))?;
                    if actual > admitted {
                        drop(revocations);
                        drop(observations);
                        drop(transport);
                        drop(template);
                        drop((prepaid, permits));
                        required = actual
                            .checked_sub(overhead)
                            .and_then(|n| n.checked_sub(revocation_bytes))
                            .ok_or(Error::Rejected(crate::RejectionReason::DerivedObjectCreation(crate::DerivedObjectCreationRejection::KeyTransportRequestStorageAccounting)))?;
                        continue;
                    }
                    prepaid.release(admitted - actual);
                    prepaid.observation_budget()?;
                    let revocations = revocations.bind(&mut prepaid)?;
                    let template = template.bind(&mut prepaid)?;
                    template.check_extensions(&self.inner)?;
                    let prepared = transport.bind(template, &mut prepaid)?;
                    let registry = crate::session::recovery::observations::Prepared::allocate(
                        &self.inner.symmetric_budget,
                        &mut prepaid,
                    )?;
                    let coordination = prepaid.split(overhead)?;
                    return Ok(Some((
                        (
                            prepared,
                            observations,
                            registry,
                            permits,
                            prepaid,
                            revocations,
                        ),
                        coordination,
                    )));
                },
                |access| reference_admission.check(access),
            )?;
            let binding = self
                .snapshot
                .check_authentication_unchanged(epoch)
                .and_then(|()| revocations.bind(&state));
            let targets = match binding {
                Ok(Some(targets)) => targets,
                Ok(None) => {
                    // No observation or native effect has occurred. Drop the
                    // guard and all unbound storage before returning its credit.
                    drop(state);
                    drop((prepared, observations, registry));
                    drop((permits, reservation, prepaid));
                    continue;
                }
                Err(error) => {
                    // Context refusal and snapshot failure share the same
                    // disposal order; neither can release the credit early.
                    drop(state);
                    drop((prepared, observations, registry));
                    drop((permits, reservation, prepaid));
                    return Err(error);
                }
            };
            break (
                (
                    (prepared, observations, registry, permits, prepaid, targets),
                    reservation,
                ),
                state,
            );
        };
        reference_admission.check(&state)?;
        self.entry(&state)?;
        if let Some(key) = key {
            self.native_object_handle(&state, key)?;
        } else if mutates {
            return Err(Error::Rejected(
                crate::RejectionReason::DerivedObjectCreation(
                    crate::DerivedObjectCreationRejection::MutatingKeyTransportRequiresARetainedKey,
                ),
            ));
        }

        // Keep every snapshot in its original owner during fallible source
        // checks. Transfer to the call only when no local validation remains.
        let mut secondary_handles = [None, None, None, None];
        for (index, source) in sources.iter().enumerate() {
            let Some(source) = source else { continue };
            self.native_object_handle(&state, source)?;
            let handle = self.native_object_handle(&state, source)?;
            targets[index + 1].as_ref().ok_or(Error::Rejected(
                crate::RejectionReason::DerivedObjectCreation(
                    crate::DerivedObjectCreationRejection::SecondaryTransportSnapshotAbsent,
                ),
            ))?;
            secondary_handles[index] = Some(handle);
        }
        let key_handle = key
            .map(|key| self.native_object_handle(&state, key))
            .transpose()?
            .unwrap_or(fe11_sys::CK_INVALID_HANDLE);
        let [aliases, first, second, third, fourth, mutation] = targets;
        let mut secondary_aliases = [None, None, None, None];
        for ((slot, handle), targets) in secondary_aliases
            .iter_mut()
            .zip(secondary_handles)
            .zip([first, second, third, fourth])
        {
            *slot = handle.map(|handle| (handle, targets.expect("validated transport snapshot")));
        }
        let call = outputs::PreparedCall::Transport {
            call: Box::new(prepared),
            key: key_handle,
            aliases,
            mutation,
            secondary: secondary_aliases,
        };
        let (coordination, state, diagnostic, cleanup) = observations.publish(
            self,
            state,
            call,
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
                    .ok_or(Error::Rejected(
                        crate::RejectionReason::DerivedObjectCreation(
                            crate::DerivedObjectCreationRejection::TransportObjectAbsent,
                        ),
                    ))?;
                if let Some(key) = key {
                    key.identity.access().check(&self.snapshot)?;
                }
                for source in sources.into_iter().flatten() {
                    source.identity.access().check(&self.snapshot)?;
                }
                object.identity.access().result(self, access, Ok(()))?;
                let outputs::Output::Transport { value, .. } = owner.take_output()? else {
                    return Err(Error::Rejected(
                        crate::RejectionReason::DerivedObjectCreation(
                            crate::DerivedObjectCreationRejection::TransportOutputKind,
                        ),
                    ));
                };
                let output = value?;
                Ok(NativeKemResult {
                    object,
                    parameters: output.parameters,
                    ciphertext: output.ciphertext,
                    provenance,
                })
            },
        )
    }
}
impl crate::AdvancedSession {
    /// Synchronous wrapping through the same owner as Session.
    pub fn wrap_key_extension(
        &self,
        key: &crate::NativeObjectRef,
        target: &crate::NativeObjectRef,
        request: ExtensionRequest<'_>,
        capacity: usize,
    ) -> Result<ExtensionResult> {
        let mut diagnostic = None;
        crate::mechanism_extension::transport::wrap(
            &self.session,
            request,
            key,
            target,
            capacity,
            &mut diagnostic,
        )
    }
    /// Synchronous unwrapping through the same creation/cleanup owner as Session.
    pub fn unwrap_key_extension(
        &self,
        key: &crate::NativeObjectRef,
        blob: &[u8],
        parameters: ExtensionRequest<'_>,
        class: ManagedClass,
        request: GenerationTemplate<'_>,
    ) -> Result<crate::CreatedObjects<NativeUnwrappedObject>> {
        let mut diagnostics = crate::error::PreparedCreationDiagnostics::default();
        self.session.unwrap_key_with_sources(
            key,
            blob,
            parameters,
            class,
            request,
            [None; 4],
            &mut diagnostics,
        )
    }
}
