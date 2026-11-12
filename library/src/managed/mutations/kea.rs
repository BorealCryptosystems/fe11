// SPDX-License-Identifier: Apache-2.0
//! KEA publishes either native randoms or a newly observed key with randoms.
use super::{input_identity::InputIdentity, outputs, Reservation};
use crate::{
    attribute_values::InputTemplate,
    native::derivation::kea::{Kea, Phase},
    Error, GenerationTemplate, KeaRequest, KeaResult, ManagedClass, Result, Session,
};
impl Session {
    /// Execute the exact KEA phase selected by role and the full big-endian
    /// RandomB value. Both random buffers are copied and returned after success.
    /// A zero RandomB requests no object: object/content/destination observations
    /// are unused and the native template is passed unchanged for the module to
    /// ignore. Native refusals never trigger a different phase or identifier.
    pub fn derive_kea(
        &self,
        base: &crate::NativeObjectRef,
        parameters: KeaRequest<'_>,
        request: GenerationTemplate<'_>,
    ) -> Result<crate::CreatedObjects<KeaResult>> {
        let mut diagnostics = crate::error::PreparedCreationDiagnostics::default();
        self.derive_kea_selected(base, parameters, request, &mut diagnostics)
    }

    fn derive_kea_selected(
        &self,
        base: &crate::NativeObjectRef,
        parameters: KeaRequest<'_>,
        request: GenerationTemplate<'_>,
        diagnostics: &mut crate::error::PreparedCreationDiagnostics,
    ) -> Result<crate::CreatedObjects<KeaResult>> {
        let phase = Phase::from_request(&parameters);
        let random_diagnostic_bytes = crate::error::PreparedCompletionStorage::allocation_bytes();
        let plan = InputTemplate::plan_scoped(request.attributes, request.limits, &self.inner)?;
        let specs = || {
            [outputs::Spec::new(
                ManagedClass::SecretKey,
                &request,
                "KEA derived content",
            )]
        };
        let observation_bytes = if phase.creates() {
            outputs::Initial::requested(specs())?
        } else {
            random_diagnostic_bytes
        };
        let epoch = self.snapshot.authentication_stamp();
        let mut required = plan
            .prepared_allocation_bytes()?
            .checked_add(Kea::allocation_bytes(&parameters)?)
            .and_then(|n| n.checked_add(observation_bytes))
            .ok_or(Error::Rejected(
                crate::RejectionReason::DerivedObjectCreation(
                    crate::DerivedObjectCreationRejection::KeaRequestAccounting,
                ),
            ))?;
        let reference_admission = self.reference_admission_at_epoch(
            crate::session::ReferenceMode::Synchronous,
            epoch,
            |state| {
                state.native.table.C_DeriveKey.ok_or(Error::Rejected(
                    crate::RejectionReason::NativeDerivation(
                        crate::NativeDerivationRejection::CDeriveKeyUnavailable,
                    ),
                ))?;
                Ok(())
            },
        )?;
        let identity = InputIdentity::new(ManagedClass::SecretKey, request.attributes, None);
        let destinations = if phase.creates() {
            Some([identity.destination(self)?])
        } else {
            None
        };
        let (
            (
                (
                    mut random_diagnostic,
                    prepared,
                    observations,
                    registry,
                    permits,
                    prepaid,
                    aliases,
                ),
                reservation,
            ),
            state,
        ) = loop {
            // The driver has returned before revocation binding. This
            // scope also retires catalogue entries after a failed binding drops
            // the returned destination, before a fresh source/session wait.
            let retirement = destinations
                .as_ref()
                .map(|_| super::reservation_preparation::DestinationRetirement::new(self));
            if let Some(retirement) = &retirement {
                retirement.retire();
            }
            let mut prepare = |overhead, current: &dyn Fn() -> Result<bool>| loop {
                let shape = crate::managed::RevocationShape::discover(
                    self,
                    base.identity.resource(),
                    epoch,
                )?;
                let revocation_bytes = shape.allocation_bytes()?;
                let admitted = required
                    .checked_add(overhead)
                    .and_then(|n| n.checked_add(revocation_bytes))
                    .ok_or(Error::Rejected(
                        crate::RejectionReason::DerivedObjectCreation(
                            crate::DerivedObjectCreationRejection::KeaRequestAccounting,
                        ),
                    ))?;
                self.snapshot.check_authentication_unchanged(epoch)?;
                let valid = || {
                    crate::session::recovery::observations::context(self, Some(epoch), epoch)?;
                    current()
                };
                let (permits, mut prepaid) = if phase.creates() {
                    let group =
                        reference_admission.managed_with_observation_storage(1, admitted, || {
                            if !valid()? {
                                return Err(Error::Busy(crate::BusyReason::DerivedObjectCreation(
                                    crate::DerivedObjectCreationBusy::KeaCreationPlanChanged,
                                )));
                            }
                            Ok(())
                        });
                    match group {
                        Ok((permits, prepaid)) => (Some(permits), prepaid),
                        Err(Error::Busy(crate::BusyReason::DerivedObjectCreation(
                            crate::DerivedObjectCreationBusy::KeaCreationPlanChanged,
                        ))) => return Ok(None),
                        Err(error) => return Err(error),
                    }
                } else {
                    // Random-only KEA reserves no publication quota or destination.
                    let Some(prepaid) = crate::advanced::reserve_preparation_while(
                        self,
                        admitted,
                        reference_admission.progress(),
                        valid,
                    )?
                    else {
                        return Ok(None);
                    };
                    (None, prepaid)
                };
                let revocation = shape.allocate()?;
                let revocation_actual = revocation.allocated_bytes()?;
                let template = plan.allocate()?;
                let parameters_storage =
                    crate::native::derivation::kea::KeaStorage::allocate(&parameters)?;
                let observations = if phase.creates() {
                    Some(outputs::Initial::allocate(specs())?)
                } else {
                    None
                };
                let observation_bytes = observations
                    .as_ref()
                    .map(outputs::Initial::allocated_bytes)
                    .transpose()?
                    .unwrap_or(random_diagnostic_bytes);
                let actual = template
                    .allocated_bytes()?
                    .checked_add(parameters_storage.allocated_bytes()?)
                    .and_then(|n| n.checked_add(observation_bytes))
                    .and_then(|bytes| bytes.checked_add(overhead))
                    .and_then(|bytes| bytes.checked_add(revocation_actual))
                    .ok_or(Error::Rejected(
                        crate::RejectionReason::DerivedObjectCreation(
                            crate::DerivedObjectCreationRejection::KeaRequestAccounting,
                        ),
                    ))?;
                if actual > admitted {
                    drop(revocation);
                    drop(observations);
                    drop(parameters_storage);
                    drop(template);
                    drop((prepaid, permits));
                    required = actual
                        .checked_sub(overhead)
                        .and_then(|n| n.checked_sub(revocation_bytes))
                        .ok_or(Error::Rejected(
                            crate::RejectionReason::DerivedObjectCreation(
                                crate::DerivedObjectCreationRejection::KeaRequestAccounting,
                            ),
                        ))?;
                    continue;
                }
                prepaid.release(admitted - actual);
                if phase.creates() {
                    prepaid.observation_budget()?;
                }
                let random_diagnostic = if phase.creates() {
                    None
                } else {
                    Some(crate::error::PreparedCompletionStorage::prepare(
                        &mut prepaid,
                    )?)
                };
                let revocation = revocation.bind(&mut prepaid)?;
                let template = template.bind(&mut prepaid)?;
                template.check_extensions(&self.inner)?;
                let prepared = parameters_storage.bind(&parameters, template, &mut prepaid)?;
                let registry = if phase.creates() {
                    Some(crate::session::recovery::observations::Prepared::allocate(
                        &self.inner.symmetric_budget,
                        &mut prepaid,
                    )?)
                } else {
                    None
                };
                let coordination = prepaid.split(overhead)?;
                return Ok(Some((
                    (
                        random_diagnostic,
                        prepared,
                        observations,
                        registry,
                        permits,
                        prepaid,
                        revocation,
                    ),
                    coordination,
                )));
            };
            let roles = [(Some(base), crate::session::activity::AccessMode::Read)];
            let (
                (
                    (
                        random_diagnostic,
                        prepared,
                        observations,
                        registry,
                        permits,
                        prepaid,
                        mut revocation,
                    ),
                    reservation,
                ),
                state,
            ) = if let Some(destinations) = &destinations {
                Reservation::prepare_mutation_prepaid(
                    self,
                    destinations,
                    1,
                    None,
                    roles,
                    false,
                    epoch,
                    reference_admission.progress(),
                    prepare,
                    |access| reference_admission.check(access),
                )
                .map(|((candidate, reservation), state)| ((candidate, Some(reservation)), state))?
            } else {
                self.prepare_with_native_roles_prepaid_at_epoch(
                    roles,
                    false,
                    epoch,
                    reference_admission.progress(),
                    |overhead| {
                        // There is no destination recipe to invalidate here.
                        // Context refusal remains an error from the predicate.
                        prepare(overhead, &|| Ok(true))?.ok_or(Error::Rejected(
                            crate::RejectionReason::DerivedObjectCreation(crate::DerivedObjectCreationRejection::UnchangingKeaPreparationWasInvalidated),
                        ))
                    },
                )
                .map(|(candidate, state)| ((candidate, None), state))?
            };
            let binding = self
                .snapshot
                .check_authentication_unchanged(epoch)
                .and_then(|()| revocation.bind(&state));
            let aliases = match binding {
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
                    (
                        random_diagnostic,
                        prepared,
                        observations,
                        registry,
                        permits,
                        prepaid,
                        aliases,
                    ),
                    reservation,
                ),
                state,
            );
        };
        reference_admission.check(&state)?;
        self.entry(&state)?;
        let base_handle = self.native_object_handle(&state, base)?;
        if state.native.table.C_DeriveKey.is_none() {
            return Err(Error::Rejected(crate::RejectionReason::NativeDerivation(
                crate::NativeDerivationRejection::CDeriveKeyUnavailable,
            )));
        }
        if let Some(reservation) = reservation {
            let call;
            let prepared_observations;
            let prepared_permits;
            let prepared_registry;
            let state = state;
            call = outputs::PreparedCall::Kea {
                call: Box::new(prepared),
                base: base_handle,
                aliases,
            };
            prepared_observations = observations.ok_or(Error::Rejected(
                crate::RejectionReason::DerivedObjectCreation(
                    crate::DerivedObjectCreationRejection::KeaObservationPreparationAbsent,
                ),
            ))?;
            prepared_permits = permits.ok_or(Error::Rejected(
                crate::RejectionReason::DerivedObjectCreation(
                    crate::DerivedObjectCreationRejection::KeaPublicationPhase,
                ),
            ))?;
            prepared_registry = registry.ok_or(Error::Rejected(
                crate::RejectionReason::DerivedObjectCreation(
                    crate::DerivedObjectCreationRejection::KeaObservationRegistryAbsent,
                ),
            ))?;
            let (coordination, state, diagnostic, cleanup) = prepared_observations.publish(
                self,
                state,
                call,
                &reservation,
                prepared_permits,
                [request.into_content()],
                outputs::Order::EachReferenceThenContent,
                epoch,
                prepared_registry,
                prepaid,
            )?;
            drop(reservation);
            let (diagnostic, cleanup) = diagnostics.install(diagnostic, cleanup);
            return outputs::run(
                self,
                reference_admission.progress(),
                epoch,
                coordination,
                state,
                diagnostic,
                cleanup,
                |access, owner, _cleanup| {
                    let key = owner
                        .take_reference(self, access, 0)?
                        .ok_or(Error::Rejected(
                            crate::RejectionReason::DerivedObjectCreation(
                                crate::DerivedObjectCreationRejection::KeaOutputAbsent,
                            ),
                        ))?;
                    key.identity.access().check(&self.snapshot)?;
                    base.identity.access().result(self, access, Ok(()))?;
                    let outputs::Output::Kea { randoms, .. } = owner.take_output()? else {
                        return Err(Error::Rejected(
                            crate::RejectionReason::DerivedObjectCreation(
                                crate::DerivedObjectCreationRejection::KeaPublicationPhase,
                            ),
                        ));
                    };
                    Ok(KeaResult::Derived { key, randoms })
                },
            );
        }
        // The random-only phase still creates no quota, destination observation
        // or output registry owner. All parameter storage was prepared above.
        drop((observations, registry, prepaid));
        let completion = random_diagnostic.take().ok_or(Error::Rejected(
            crate::RejectionReason::DerivedObjectCreation(
                crate::DerivedObjectCreationRejection::KeaRandomDiagnosticAbsent,
            ),
        ))?;
        let random_diagnostic = diagnostics.retain_randoms(completion);
        let completed = prepared.execute(
            self,
            &state,
            random_diagnostic.take()?,
            None,
            base_handle,
            aliases,
            None,
        )?;
        let handle = completed.handle();
        let (completion, randoms) = completed.into_parts();
        let result = (|| {
            self.mutation_context(&state, |cause| cause)?;
            if handle.is_some() {
                return Err(Error::Rejected(
                    crate::RejectionReason::DerivedObjectCreation(
                        crate::DerivedObjectCreationRejection::KeaPublicationPhase,
                    ),
                ));
            }
            base.identity
                .access()
                .result(self, &state, Ok(KeaResult::Randoms(randoms)))
        })();
        completion
            .finish(result)
            .map(|value| crate::CreatedObjects::without_objects(Ok(value)))
    }
}
impl crate::AdvancedSession {
    /// Synchronous KEA through the same owned phase/effect boundary.
    pub fn derive_kea(
        &self,
        base: &crate::NativeObjectRef,
        parameters: KeaRequest<'_>,
        request: GenerationTemplate<'_>,
    ) -> Result<crate::CreatedObjects<KeaResult>> {
        let mut diagnostics = crate::error::PreparedCreationDiagnostics::default();
        self.session
            .derive_kea_selected(base, parameters, request, &mut diagnostics)
    }
}
