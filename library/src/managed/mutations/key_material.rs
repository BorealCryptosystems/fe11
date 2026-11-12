// SPDX-License-Identifier: Apache-2.0
//! Observe and publish a complete native TLS/WTLS key-material result.
use super::{outputs, DestinationRecipe, Reservation};
use crate::{
    attribute_values::InputTemplate,
    native::derivation::{key_material::KeyMaterial, sp800::size},
    Error, ManagedClass, NativeTlsKeyMaterial, Result, Session, TlsKeyMaterialObservations,
    TlsKeyMaterialPart, TlsKeyMaterialRequest,
};
use std::mem::size_of;

// Field order frees the publication vector before its credit. It remains empty
// while resident; public references are built only after terminal extraction.
pub(in crate::managed) struct Publication {
    pub(super) keys: Vec<(TlsKeyMaterialPart, crate::NativeObjectView)>,
    pub(super) result_credit: crate::symmetric::memory::Credit,
}

impl Session {
    /// Derive the selected SSL/TLS/WTLS keys and IVs in one native call.
    ///
    /// One template is passed unchanged. Independent observations correspond to
    /// the native output slots. Zero-length keys may be absent; a missing handle
    /// for a nonzero requested key length is a post-success error. The whole set
    /// is registered before any observation and published only as one result.
    /// Native errors are retained; no size probe, retry or fallback is performed.
    ///
    /// The application chooses protocol parameters. In particular ordinary TLS
    /// key-material derivation can expose secret material through IVs when used
    /// with inconsistent lengths; select the SAFE mechanism when appropriate.
    pub fn derive_tls_key_material(
        &self,
        base: &crate::NativeObjectRef,
        request: TlsKeyMaterialRequest<'_>,
        observations: TlsKeyMaterialObservations,
    ) -> Result<crate::CreatedObjects<NativeTlsKeyMaterial>> {
        let mut diagnostics = crate::error::PreparedCreationDiagnostics::default();
        self.derive_tls_key_material_selected(base, request, observations, &mut diagnostics)
    }

    fn derive_tls_key_material_selected(
        &self,
        base: &crate::NativeObjectRef,
        request: TlsKeyMaterialRequest<'_>,
        observations: TlsKeyMaterialObservations,
        diagnostics: &mut crate::error::PreparedCreationDiagnostics,
    ) -> Result<crate::CreatedObjects<NativeTlsKeyMaterial>> {
        let count = request.mechanism.count();
        if observations.as_slice().len() != count {
            return Err(Error::Rejected(crate::RejectionReason::ObjectCreation(
                crate::ObjectCreationRejection::KeyMaterialObservationLayout,
            )));
        }
        let plan = InputTemplate::plan_scoped(request.attributes, request.limits, &self.inner)?;
        let result_bytes = size::<(TlsKeyMaterialPart, crate::NativeObjectView)>(count)?
            .checked_add(size_of::<NativeTlsKeyMaterial>())
            .ok_or(Error::Rejected(crate::RejectionReason::ObjectCreation(
                crate::ObjectCreationRejection::KeyMaterialResultAccounting,
            )))?;
        let specs = || {
            observations
                .as_slice()
                .iter()
                .map(|observation| outputs::Spec {
                    class: ManagedClass::SecretKey,
                    attributes: request.attributes,
                    destination: &observation.destination,
                    admission: observation
                        .observation
                        .as_ref()
                        .map(|value| &value.admission),
                    content: observation.observation.as_ref().map(|value| &value.content),
                    stage: "derived key-material content",
                })
        };
        let observation_bytes = outputs::Initial::requested(specs())?;
        let epoch = self.snapshot.authentication_stamp();
        let mut required = plan
            .prepared_allocation_bytes()?
            .checked_add(KeyMaterial::allocation_bytes(&request)?)
            .and_then(|n| n.checked_add(result_bytes))
            .and_then(|n| n.checked_add(observation_bytes))
            .ok_or(Error::Rejected(crate::RejectionReason::ObjectCreation(
                crate::ObjectCreationRejection::KeyMaterialRequestAccounting,
            )))?;
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
        // One invocation legitimately creates several keys with the same CKA_ID.
        // Coordinate the entire class during creation; native handles, never
        // caller identifiers, distinguish the resulting resource lifetimes.
        let destinations = [DestinationRecipe::class_scope(
            self,
            ManagedClass::SecretKey,
        )?];
        let (
            (
                (prepared, publication, output_observations, registry, permits, prepaid, aliases),
                reservation,
            ),
            state,
        ) = loop {
            // The driver has returned before revocation binding. This
            // scope also retires catalogue entries after a failed binding drops
            // the returned destination, before a fresh source/session wait.
            let retirement = super::reservation_preparation::DestinationRetirement::new(self);
            retirement.retire();
            let (
                (
                    (
                        prepared,
                        publication,
                        output_observations,
                        registry,
                        permits,
                        prepaid,
                        mut revocation,
                    ),
                    reservation,
                ),
                state,
            ) = Reservation::prepare_mutation_prepaid(
                self,
                &destinations,
                count,
                None,
                [(Some(base), crate::session::activity::AccessMode::Read)],
                false,
                epoch,
                reference_admission.progress(),
                |overhead, current| loop {
                    let shape = crate::managed::RevocationShape::discover(
                        self,
                        base.identity.resource(),
                        epoch,
                    )?;
                    let revocation_bytes = shape.allocation_bytes()?;
                    let admitted = required
                        .checked_add(overhead)
                        .and_then(|n| n.checked_add(revocation_bytes))
                        .ok_or(Error::Rejected(crate::RejectionReason::ObjectCreation(
                            crate::ObjectCreationRejection::KeyMaterialRequestAccounting,
                        )))?;
                    self.snapshot.check_authentication_unchanged(epoch)?;
                    let group = reference_admission.managed_with_observation_storage(
                        count,
                        admitted,
                        || {
                            crate::session::recovery::observations::context(
                                self,
                                Some(epoch),
                                epoch,
                            )?;
                            if !current()? {
                                return Err(Error::Busy(crate::BusyReason::ObjectCreation(
                                    crate::ObjectCreationBusy::KeyMaterialCreationPlanChanged,
                                )));
                            }
                            Ok(())
                        },
                    );
                    let (permits, mut prepaid) = match group {
                        Ok(group) => group,
                        // Replan only after returning every private owner to the driver.
                        Err(Error::Busy(crate::BusyReason::ObjectCreation(
                            crate::ObjectCreationBusy::KeyMaterialCreationPlanChanged,
                        ))) => return Ok(None),
                        Err(error) => return Err(error),
                    };
                    let revocation = shape.allocate()?;
                    let revocation_actual = revocation.allocated_bytes()?;
                    let template = plan.allocate()?;
                    let material =
                        crate::native::derivation::key_material::KeyMaterialStorage::allocate(
                            &request,
                        )?;
                    let mut keys = Vec::<(TlsKeyMaterialPart, crate::NativeObjectView)>::new();
                    keys.try_reserve_exact(count).map_err(|_| {
                        Error::Rejected(crate::RejectionReason::ObjectCreation(
                            crate::ObjectCreationRejection::KeyMaterialResultAllocation,
                        ))
                    })?;
                    let output_observations = outputs::Initial::allocate(specs())?;
                    let observation_bytes = output_observations.allocated_bytes()?;
                    let result_bytes =
                        size::<(TlsKeyMaterialPart, crate::NativeObjectView)>(keys.capacity())?
                            .checked_add(size_of::<NativeTlsKeyMaterial>())
                            .ok_or(Error::Rejected(crate::RejectionReason::ObjectCreation(
                                crate::ObjectCreationRejection::KeyMaterialResultAccounting,
                            )))?;
                    let actual = template
                        .allocated_bytes()?
                        .checked_add(material.allocated_bytes()?)
                        .and_then(|n| n.checked_add(result_bytes))
                        .and_then(|n| n.checked_add(observation_bytes))
                        .and_then(|bytes| bytes.checked_add(overhead))
                        .and_then(|bytes| bytes.checked_add(revocation_actual))
                        .ok_or(Error::Rejected(crate::RejectionReason::ObjectCreation(
                            crate::ObjectCreationRejection::KeyMaterialRequestAccounting,
                        )))?;
                    if actual > admitted {
                        drop(revocation);
                        drop(output_observations);
                        drop(keys);
                        drop(material);
                        drop(template);
                        drop((prepaid, permits));
                        required = actual
                            .checked_sub(overhead)
                            .and_then(|n| n.checked_sub(revocation_bytes))
                            .ok_or(Error::Rejected(crate::RejectionReason::ObjectCreation(
                                crate::ObjectCreationRejection::KeyMaterialRequestAccounting,
                            )))?;
                        continue;
                    }
                    prepaid.release(admitted - actual);
                    prepaid.observation_budget()?;
                    let revocation = revocation.bind(&mut prepaid)?;
                    let publication = Publication {
                        keys,
                        result_credit: prepaid.split(result_bytes)?,
                    };
                    let template = template.bind(&mut prepaid)?;
                    template.check_extensions(&self.inner)?;
                    let prepared = material.bind(&request, template, &mut prepaid)?;
                    let registry = crate::session::recovery::observations::Prepared::allocate(
                        &self.inner.symmetric_budget,
                        &mut prepaid,
                    )?;
                    let coordination = prepaid.split(overhead)?;
                    return Ok(Some((
                        (
                            prepared,
                            publication,
                            output_observations,
                            registry,
                            permits,
                            prepaid,
                            revocation,
                        ),
                        coordination,
                    )));
                },
                |access| reference_admission.check(access),
            )?;
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
                    drop((prepared, publication, output_observations, registry));
                    drop((permits, reservation, prepaid));
                    continue;
                }
                Err(error) => {
                    // Context refusal and snapshot failure share the same
                    // disposal order; neither can release the credit early.
                    drop(state);
                    drop((prepared, publication, output_observations, registry));
                    drop((permits, reservation, prepaid));
                    return Err(error);
                }
            };
            break (
                (
                    (
                        prepared,
                        publication,
                        output_observations,
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
        let call = outputs::PreparedCall::Tls {
            call: Box::new(prepared),
            base: base_handle,
            aliases,
            publication,
        };
        let (coordination, state, diagnostic, cleanup) = output_observations.publish(
            self,
            state,
            call,
            &reservation,
            permits,
            observations.into_iter().map(|observation| {
                observation
                    .observation
                    .map_or(crate::ContentObservation::NotRequested, |value| {
                        value.content
                    })
            }),
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
            |access, owner, cleanup| {
                base.identity.access().check(&self.snapshot)?;
                self.mutation_context(access, |cause| cleanup.mark_remaining(cause))?;
                let output = owner.take_vector_output(self, access)?;
                let outputs::Output::Tls {
                    mut data,
                    publication,
                } = output
                else {
                    return Err(Error::Rejected(crate::RejectionReason::ObjectCreation(
                        crate::ObjectCreationRejection::TlsOutputKind,
                    )));
                };
                Ok(NativeTlsKeyMaterial {
                    keys: publication.keys,
                    ivs: data.take_output_ivs(),
                    mechanism: request.mechanism,
                    _credit: publication.result_credit,
                })
            },
        )
    }
}
impl crate::AdvancedSession {
    /// Synchronous key-material derivation through the common native owner.
    pub fn derive_tls_key_material(
        &self,
        base: &crate::NativeObjectRef,
        request: TlsKeyMaterialRequest<'_>,
        observations: TlsKeyMaterialObservations,
    ) -> Result<crate::CreatedObjects<NativeTlsKeyMaterial>> {
        let mut diagnostics = crate::error::PreparedCreationDiagnostics::default();
        self.session
            .derive_tls_key_material_selected(base, request, observations, &mut diagnostics)
    }
}
