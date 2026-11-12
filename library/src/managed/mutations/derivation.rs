// SPDX-License-Identifier: Apache-2.0
//! Generic derivation, with the same owner for both synchronous facades.
use super::{input_identity::InputIdentity, outputs, Reservation};
use crate::{
    attribute_values::InputTemplate, native::derivation::input::Input, Error, GenerationTemplate,
    NativeKeyDerivation, NativeObjectRef, Result, Session,
};

impl Session {
    /// Derive an object using exact native parameters and a caller template.
    ///
    /// The module decides base-key suitability, KDF support, public-value
    /// validity and output type/size from the selected mechanism and template.
    /// Fe11 adds no ID, label, policy, curve conversion or local mathematics.
    /// Caller content/admission/destination checks remain explicit.
    ///
    /// Input parameters and nested attributes are copied to erased storage;
    /// caller buffers are outside this erasure guarantee. The complete graph is
    /// reserved before native access. The base is borrowed and protected against
    /// concurrent mutation; it is never an automatic cleanup target.
    ///
    /// This convenience method returns the object only. For TLS/WTLS version
    /// observations, use derive_native_key_with_output and check the protocol
    /// version in the calling application.
    ///
    /// Native refusals are returned without fallback. CreatedObjects retains
    /// the created reference independently of optional content observations.
    /// An observation failure does not destroy an already published object.
    /// Intrinsically invalid native outputs are handled before publication;
    /// an uncertain effect is never retried automatically.
    pub fn derive_native_key(
        &self,
        base: &crate::NativeObjectRef,
        parameters: NativeKeyDerivation<'_>,
        request: GenerationTemplate<'_>,
    ) -> Result<crate::CreatedObjects<crate::NativeObjectView>> {
        let mut diagnostics = crate::error::PreparedCreationDiagnostics::default();
        self.derive_native_key_with_source(base, parameters, request, [None; 4], &mut diagnostics)
            .map(|outcome| outcome.map(|result| result.object))
    }

    /// Derive and retain mechanism-defined auxiliary output, including native
    /// TLS/WTLS version observations. The caller must validate protocol versions;
    /// Fe11 performs no implicit version check or cryptographic substitution.
    pub fn derive_native_key_with_output(
        &self,
        base: &crate::NativeObjectRef,
        parameters: NativeKeyDerivation<'_>,
        request: GenerationTemplate<'_>,
    ) -> Result<crate::CreatedObjects<crate::NativeDerivedObject>> {
        let mut diagnostics = crate::error::PreparedCreationDiagnostics::default();
        self.derive_native_key_with_source(base, parameters, request, [None; 4], &mut diagnostics)
    }
    pub(crate) fn derive_native_key_with_source<'a>(
        &self,
        base: &crate::NativeObjectRef,
        parameters: NativeKeyDerivation<'a>,
        request: GenerationTemplate<'_>,
        additional: [Option<&'a NativeObjectRef>; 4],
        diagnostics: &mut crate::error::PreparedCreationDiagnostics,
    ) -> Result<crate::CreatedObjects<crate::NativeDerivedObject>> {
        self.derive_native_input(
            base,
            Input::Native(&parameters),
            request,
            additional,
            diagnostics,
        )
    }
    pub(crate) fn derive_native_recipe<'a>(
        &self,
        base: &crate::NativeObjectRef,
        parameters: crate::mechanism_extension::graph::recipe::Request<'a>,
        class: crate::ManagedClass,
        request: GenerationTemplate<'_>,
        additional: [Option<&'a NativeObjectRef>; 4],
        diagnostics: &mut crate::error::PreparedCreationDiagnostics,
    ) -> Result<crate::CreatedObjects<crate::NativeDerivedObject>> {
        self.derive_native_input(
            base,
            Input::Recipe {
                request: parameters,
                class,
            },
            request,
            additional,
            diagnostics,
        )
    }
    fn derive_native_input<'r, 'a>(
        &self,
        base: &crate::NativeObjectRef,
        parameters: Input<'r, 'a>,
        request: GenerationTemplate<'_>,
        additional: [Option<&'a NativeObjectRef>; 4],
        diagnostics: &mut crate::error::PreparedCreationDiagnostics,
    ) -> Result<crate::CreatedObjects<crate::NativeDerivedObject>> {
        parameters.check_extension(&self.inner)?;
        let provenance = parameters.layout_provenance();
        let mutates_base = parameters.mutates_base();

        let class = parameters.output_class();
        let mut secondary_keys = parameters.secondary_keys();
        for additional in additional.into_iter().flatten() {
            let slot = secondary_keys
                .iter_mut()
                .find(|slot| slot.is_none())
                .ok_or(Error::Rejected(
                    crate::RejectionReason::DerivedObjectCreation(
                        crate::DerivedObjectCreationRejection::InternalDerivationSourceComposition,
                    ),
                ))?;
            *slot = Some(additional);
        }
        let plan = InputTemplate::plan_scoped(request.attributes, request.limits, &self.inner)?;
        let specs = || [outputs::Spec::new(class, &request, "derived content")];
        let observation_bytes = outputs::Initial::requested(specs())?;
        let epoch = self.snapshot.authentication_stamp();
        let mut required = plan
            .prepared_allocation_bytes()?
            .checked_add(parameters.allocation_bytes()?)
            .and_then(|n| n.checked_add(observation_bytes))
            .ok_or(Error::Rejected(
                crate::RejectionReason::DerivedObjectCreation(
                    crate::DerivedObjectCreationRejection::DerivationRequestStorageAccounting,
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
                        Some(base),
                        if mutates_base {
                            crate::session::activity::AccessMode::Write
                        } else {
                            crate::session::activity::AccessMode::Read
                        },
                    ),
                    (
                        secondary_keys[0],
                        crate::session::activity::AccessMode::Read,
                    ),
                    (
                        secondary_keys[1],
                        crate::session::activity::AccessMode::Read,
                    ),
                    (
                        secondary_keys[2],
                        crate::session::activity::AccessMode::Read,
                    ),
                    (
                        secondary_keys[3],
                        crate::session::activity::AccessMode::Read,
                    ),
                ],
                false,
                epoch,
                reference_admission.progress(),
                |overhead, current| loop {
                    let shapes = crate::managed::RevocationSetPlan::discover(
                        self,
                        [
                            Some(base.identity.resource()),
                            secondary_keys[0].map(|key| key.identity.resource()),
                            secondary_keys[1].map(|key| key.identity.resource()),
                            secondary_keys[2].map(|key| key.identity.resource()),
                            secondary_keys[3].map(|key| key.identity.resource()),
                            mutates_base.then_some(base.identity.resource()),
                        ],
                        epoch,
                    )?;
                    let revocation_bytes = shapes.allocation_bytes()?;
                    let admitted = required
                        .checked_add(overhead)
                        .and_then(|n| n.checked_add(revocation_bytes))
                        .ok_or(Error::Rejected(crate::RejectionReason::DerivedObjectCreation(crate::DerivedObjectCreationRejection::DerivationRequestStorageAccounting)))?;
                    self.snapshot.check_authentication_unchanged(epoch)?;
                    let group =
                        reference_admission.managed_with_observation_storage(1, admitted, || {
                            crate::session::recovery::observations::context(
                                self,
                                Some(epoch),
                                epoch,
                            )?;
                            if !current()? {
                                return Err(Error::Busy(crate::BusyReason::DerivedObjectCreation(
                                    crate::DerivedObjectCreationBusy::DerivationCreationPlanChanged,
                                )));
                            }
                            Ok(())
                        });
                    let (permits, mut prepaid) = match group {
                        Ok(group) => group,
                        // Replan outside the wait, with no private owners.
                        Err(Error::Busy(crate::BusyReason::DerivedObjectCreation(
                            crate::DerivedObjectCreationBusy::DerivationCreationPlanChanged,
                        ))) => return Ok(None),
                        Err(error) => return Err(error),
                    };
                    let revocations = shapes.allocate()?;
                    let revocation_actual = revocations.allocated_bytes()?;
                    let template = plan.allocate()?;
                    let native = parameters.allocate()?;
                    let observations = outputs::Initial::allocate(specs())?;
                    let observation_bytes = observations.allocated_bytes()?;
                    let actual = template
                        .allocated_bytes()?
                        .checked_add(native.allocated_bytes()?)
                        .and_then(|n| n.checked_add(observation_bytes))
                        .and_then(|bytes| bytes.checked_add(overhead))
                        .and_then(|bytes| bytes.checked_add(revocation_actual))
                        .ok_or(Error::Rejected(crate::RejectionReason::DerivedObjectCreation(crate::DerivedObjectCreationRejection::DerivationRequestStorageAccounting)))?;
                    if actual > admitted {
                        drop(revocations);
                        drop(observations);
                        drop(native);
                        drop(template);
                        drop((prepaid, permits));
                        required = actual
                            .checked_sub(overhead)
                            .and_then(|n| n.checked_sub(revocation_bytes))
                            .ok_or(Error::Rejected(crate::RejectionReason::DerivedObjectCreation(crate::DerivedObjectCreationRejection::DerivationRequestStorageAccounting)))?;
                        continue;
                    }
                    prepaid.release(admitted - actual);
                    prepaid.observation_budget()?;
                    let revocations = revocations.bind(&mut prepaid)?;
                    let template = template.bind(&mut prepaid)?;
                    template.check_extensions(&self.inner)?;
                    let prepared = native.bind(template, &mut prepaid)?;
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
        let base_handle = self.native_object_handle(&state, base)?;
        // Validate handles and snapshot presence while the complete target set
        // still precedes state in drop order. A consuming zip would destroy its
        // remaining targets before state on an early error.
        let mut secondary_handles = [None, None, None, None];
        for (index, key) in secondary_keys.iter().enumerate() {
            let Some(key) = key else { continue };
            let handle = self.native_object_handle(&state, key)?;
            targets[index + 1].as_ref().ok_or(Error::Rejected(
                crate::RejectionReason::DerivedObjectCreation(
                    crate::DerivedObjectCreationRejection::SecondaryDerivationSnapshotAbsent,
                ),
            ))?;
            secondary_handles[index] = Some(handle);
        }
        if state.native.table.C_DeriveKey.is_none() {
            return Err(Error::Rejected(crate::RejectionReason::NativeDerivation(
                crate::NativeDerivationRejection::CDeriveKeyUnavailable,
            )));
        }
        targets[0].as_ref().ok_or(Error::Rejected(
            crate::RejectionReason::DerivedObjectCreation(
                crate::DerivedObjectCreationRejection::BaseDerivationSnapshotAbsent,
            ),
        ))?;
        let [aliases, first, second, third, fourth, mutation] = targets;
        let mut secondary_aliases = [None, None, None, None];
        for ((slot, handle), targets) in secondary_aliases
            .iter_mut()
            .zip(secondary_handles)
            .zip([first, second, third, fourth])
        {
            *slot = handle.map(|handle| (handle, targets.expect("validated derivation snapshot")));
        }
        let aliases = aliases.expect("validated base derivation snapshot");
        let call = outputs::PreparedCall::Derived {
            call: Box::new(prepared),
            base: base_handle,
            aliases,
            secondary: secondary_aliases,
            mutation,
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
                    .ok_or(Error::Rejected(crate::RejectionReason::KeyDerivation(
                        crate::KeyDerivationRejection::DerivedObjectAbsent,
                    )))?;
                base.identity.access().check(&self.snapshot)?;
                for key in secondary_keys.into_iter().flatten() {
                    key.identity.access().check(&self.snapshot)?;
                }
                object.identity.access().result(self, access, Ok(()))?;
                let outputs::Output::Derived { value: output, .. } = owner.take_output()? else {
                    return Err(Error::Rejected(
                        crate::RejectionReason::DerivedObjectCreation(
                            crate::DerivedObjectCreationRejection::DerivedOutputKind,
                        ),
                    ));
                };
                Ok(crate::NativeDerivedObject {
                    object,
                    output,
                    provenance,
                })
            },
        )
    }
}
impl crate::AdvancedSession {
    /// Synchronous derivation through the same owned boundary as Session.
    /// This does not enable native asynchronous mode or introduce a worker thread.
    pub fn derive_native_key(
        &self,
        base: &crate::NativeObjectRef,
        parameters: NativeKeyDerivation<'_>,
        request: GenerationTemplate<'_>,
    ) -> Result<crate::CreatedObjects<crate::NativeObjectView>> {
        let mut diagnostics = crate::error::PreparedCreationDiagnostics::default();
        self.session
            .derive_native_key_with_source(base, parameters, request, [None; 4], &mut diagnostics)
            .map(|outcome| outcome.map(|result| result.object))
    }
    /// Synchronous derivation retaining all mechanism-defined observations.
    pub fn derive_native_key_with_output(
        &self,
        base: &crate::NativeObjectRef,
        parameters: NativeKeyDerivation<'_>,
        request: GenerationTemplate<'_>,
    ) -> Result<crate::CreatedObjects<crate::NativeDerivedObject>> {
        let mut diagnostics = crate::error::PreparedCreationDiagnostics::default();
        self.session.derive_native_key_with_source(
            base,
            parameters,
            request,
            [None; 4],
            &mut diagnostics,
        )
    }
}
