// SPDX-License-Identifier: Apache-2.0
//! SP800-108 publication keeps the whole native creation set indivisible locally.
use super::{outputs, DestinationRecipe, Reservation};
use crate::{
    attribute_values::InputTemplate,
    managed::ResourceIdentity,
    native::derivation::sp800::{size, Sp800Frame, Sp800Storage, TemplateArray},
    Error, GenerationTemplate, ManagedClass, NativeDerivedKeys, Result, Session, Sp800Data,
    Sp800Request,
};
use fe11_sys::CK_OBJECT_HANDLE;
use std::mem::size_of;

// One publication owner keeps vector allocations ahead of their credits on
// every early exit. Source-identity storage is lent by value to the native result check;
// its credit remains here until that call has returned and freed the vector.
pub(in crate::managed) struct Publication {
    pub(super) keys: Vec<crate::NativeObjectView>,
    pub(super) sources: Vec<(CK_OBJECT_HANDLE, ResourceIdentity)>,
    pub(super) result_credit: crate::symmetric::memory::Credit,
    pub(super) _scratch_credit: crate::symmetric::memory::Credit,
}

fn empty<T>(count: usize) -> Result<Vec<T>> {
    let mut values = Vec::new();
    values.try_reserve_exact(count).map_err(|_| {
        Error::Rejected(crate::RejectionReason::DerivedObjectCreation(
            crate::DerivedObjectCreationRejection::Sp800ArrayAllocation,
        ))
    })?;
    Ok(values)
}

impl Session {
    /// Derive the primary key and all additional SP800-108 keys in one native
    /// call. The caller chooses the number and every output template.
    ///
    /// All native output handles are registered before optional observations.
    /// CreatedObjects retains the created references independently of observation
    /// failures; these failures do not destroy an already published key set.
    /// Intrinsically invalid outputs are handled before publication. Source
    /// handles are never cleanup targets, and no native replay occurs.
    /// The const size is caller-selected and has no library-imposed ceiling.
    pub fn derive_sp800_108<const N: usize>(
        &self,
        base: &crate::NativeObjectRef,
        parameters: Sp800Request<'_>,
        requests: [GenerationTemplate<'_>; N],
    ) -> Result<crate::CreatedObjects<NativeDerivedKeys>> {
        let mut diagnostics = crate::error::PreparedCreationDiagnostics::default();
        self.derive_sp800_108_selected(base, parameters, requests, &mut diagnostics)
    }

    fn derive_sp800_108_selected<const N: usize>(
        &self,
        base: &crate::NativeObjectRef,
        parameters: Sp800Request<'_>,
        requests: [GenerationTemplate<'_>; N],
        diagnostics: &mut crate::error::PreparedCreationDiagnostics,
    ) -> Result<crate::CreatedObjects<NativeDerivedKeys>> {
        if N == 0 {
            return Err(Error::Rejected(
                crate::RejectionReason::DerivedObjectCreation(
                    crate::DerivedObjectCreationRejection::Sp800PrimaryOutputRequired,
                ),
            ));
        }
        // Plans contain only borrowed operands and measured sizes. Their array
        // lets us measure all outputs before retaining any allocated template.
        let plans = requests.each_ref().map(|request| {
            InputTemplate::plan_scoped(request.attributes, request.limits, &self.inner)
        });
        let auxiliary = parameters.data.len().checked_add(1).ok_or(Error::Rejected(
            crate::RejectionReason::DerivedObjectCreation(
                crate::DerivedObjectCreationRejection::Sp800SourceCountOverflow,
            ),
        ))?;
        let result_bytes = size::<crate::NativeObjectView>(N)?
            .checked_add(size_of::<NativeDerivedKeys>())
            .ok_or(Error::Rejected(
                crate::RejectionReason::DerivedObjectCreation(
                    crate::DerivedObjectCreationRejection::Sp800ResultAccounting,
                ),
            ))?;
        let scratch_bytes = size::<(CK_OBJECT_HANDLE, ResourceIdentity)>(auxiliary)?;
        let specs = || {
            requests.iter().map(|request| {
                outputs::Spec::new(ManagedClass::SecretKey, request, "SP800 derived content")
            })
        };
        let observation_bytes = outputs::Initial::requested(specs())?;
        let epoch = self.snapshot.authentication_stamp();
        let mut total = Sp800Frame::allocation_bytes(&parameters, N)?
            .checked_add(result_bytes)
            .and_then(|n| n.checked_add(scratch_bytes))
            .and_then(|n| n.checked_add(observation_bytes))
            .ok_or(Error::Rejected(
                crate::RejectionReason::DerivedObjectCreation(
                    crate::DerivedObjectCreationRejection::Sp800RequestAccounting,
                ),
            ))?;
        for plan in &plans {
            total = total
                .checked_add(
                    plan.as_ref()
                        .map_err(Clone::clone)?
                        .prepared_allocation_bytes()?,
                )
                .ok_or(Error::Rejected(
                    crate::RejectionReason::DerivedObjectCreation(
                        crate::DerivedObjectCreationRejection::Sp800TemplateAccounting,
                    ),
                ))?;
        }
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
        let destinations = [DestinationRecipe::class_scope(
            self,
            ManagedClass::SecretKey,
        )?];
        let source_keys = std::iter::once(base).chain(parameters.data.iter().filter_map(|part| {
            if let Sp800Data::Key(key) = part {
                Some(*key)
            } else {
                None
            }
        }));
        let (
            ((prepared, mut publication, observations, registry, permits, prepaid), reservation),
            state,
        ) = Reservation::prepare_with_readers_prepaid(
            self,
            &destinations,
            N,
            source_keys,
            epoch,
            reference_admission.progress(),
            |overhead, current| loop {
                let admitted = total.checked_add(overhead).ok_or(Error::Rejected(
                    crate::RejectionReason::DerivedObjectCreation(
                        crate::DerivedObjectCreationRejection::Sp800RequestAccounting,
                    ),
                ))?;
                self.snapshot.check_authentication_unchanged(epoch)?;
                let group =
                    reference_admission.managed_with_observation_storage(N, admitted, || {
                        crate::session::recovery::observations::context(self, Some(epoch), epoch)?;
                        if !current()? {
                            return Err(Error::Busy(crate::BusyReason::DerivedObjectCreation(
                                crate::DerivedObjectCreationBusy::Sp800CreationPlanChanged,
                            )));
                        }
                        Ok(())
                    });
                let (permits, mut prepaid) = match group {
                    Ok(group) => group,
                    Err(Error::Busy(crate::BusyReason::DerivedObjectCreation(
                        crate::DerivedObjectCreationBusy::Sp800CreationPlanChanged,
                    ))) => return Ok(None),
                    Err(error) => return Err(error),
                };
                let keys = empty::<crate::NativeObjectView>(N)?;
                let observations = outputs::Initial::allocate(specs())?;
                let observation_bytes = observations.allocated_bytes()?;
                let sources = empty::<(CK_OBJECT_HANDLE, ResourceIdentity)>(auxiliary)?;
                let templates = empty::<InputTemplate>(N)?;
                let mut arenas: [_; N] = std::array::from_fn(|_| None);
                for (arena, plan) in arenas.iter_mut().zip(&plans) {
                    *arena = Some(plan.as_ref().map_err(Clone::clone)?.allocate()?);
                }
                let native = Sp800Storage::allocate(&parameters, N)?;
                let result_bytes = size::<crate::NativeObjectView>(keys.capacity())?
                    .checked_add(size_of::<NativeDerivedKeys>())
                    .ok_or(Error::Rejected(
                        crate::RejectionReason::DerivedObjectCreation(
                            crate::DerivedObjectCreationRejection::Sp800ResultAccounting,
                        ),
                    ))?;
                let scratch_bytes =
                    size::<(CK_OBJECT_HANDLE, ResourceIdentity)>(sources.capacity())?;
                let template_array_bytes =
                    size::<InputTemplate>(templates.capacity().checked_sub(N).ok_or(
                        Error::Rejected(crate::RejectionReason::DerivedObjectCreation(
                            crate::DerivedObjectCreationRejection::Sp800AllocatorCapacity,
                        )),
                    )?)?;
                let mut actual = native
                    .allocated_bytes()?
                    .checked_add(result_bytes)
                    .and_then(|n| n.checked_add(scratch_bytes))
                    .and_then(|n| n.checked_add(template_array_bytes))
                    .and_then(|n| n.checked_add(observation_bytes))
                    .ok_or(Error::Rejected(
                        crate::RejectionReason::DerivedObjectCreation(
                            crate::DerivedObjectCreationRejection::Sp800RequestAccounting,
                        ),
                    ))?;
                for arena in &arenas {
                    actual = actual
                        .checked_add(
                            arena
                                .as_ref()
                                .ok_or(Error::Rejected(crate::RejectionReason::DerivedObjectCreation(crate::DerivedObjectCreationRejection::Sp800MissingTemplateStorage)))?
                                .allocated_bytes()?,
                        )
                        .ok_or(Error::Rejected(crate::RejectionReason::DerivedObjectCreation(crate::DerivedObjectCreationRejection::Sp800TemplateAccounting)))?;
                }
                actual = actual.checked_add(overhead).ok_or(Error::Rejected(
                    crate::RejectionReason::DerivedObjectCreation(
                        crate::DerivedObjectCreationRejection::Sp800RequestAccounting,
                    ),
                ))?;
                if actual > admitted {
                    drop(native);
                    drop(arenas);
                    drop(templates);
                    drop(sources);
                    drop(observations);
                    drop(keys);
                    drop((prepaid, permits));
                    total = actual.checked_sub(overhead).ok_or(Error::Rejected(
                        crate::RejectionReason::DerivedObjectCreation(
                            crate::DerivedObjectCreationRejection::Sp800RequestAccounting,
                        ),
                    ))?;
                    continue;
                }
                prepaid.release(admitted - actual);
                prepaid.observation_budget()?;
                let publication = Publication {
                    keys,
                    sources,
                    result_credit: prepaid.split(result_bytes)?,
                    _scratch_credit: prepaid.split(scratch_bytes)?,
                };
                let mut templates = TemplateArray {
                    values: templates,
                    credit: prepaid.split(template_array_bytes)?,
                };
                for arena in arenas {
                    let template = arena
                        .ok_or(Error::Rejected(
                            crate::RejectionReason::DerivedObjectCreation(
                                crate::DerivedObjectCreationRejection::Sp800MissingTemplateStorage,
                            ),
                        ))?
                        .bind(&mut prepaid)?;
                    template.check_extensions(&self.inner)?;
                    templates.values.push(template);
                }
                let prepared = native.bind(&parameters, templates, &mut prepaid)?;
                let registry = crate::session::recovery::observations::Prepared::allocate(
                    &self.inner.symmetric_budget,
                    &mut prepaid,
                )?;
                let coordination = prepaid.split(overhead)?;
                return Ok(Some((
                    (
                        prepared,
                        publication,
                        observations,
                        registry,
                        permits,
                        prepaid,
                    ),
                    coordination,
                )));
            },
            |access| reference_admission.check(access),
        )?;
        reference_admission.check(&state)?;
        self.entry(&state)?;
        let base_handle = self.native_object_handle(&state, base)?;

        publication
            .sources
            .push((base_handle, base.identity.resource()));
        for segment in parameters.data {
            let Sp800Data::Key(key) = segment else {
                continue;
            };
            let handle = self.native_object_handle(&state, key)?;
            if !publication
                .sources
                .iter()
                .any(|(previous, _)| *previous == handle)
            {
                publication.sources.push((handle, key.identity.resource()));
            }
        }
        if state.native.table.C_DeriveKey.is_none() {
            return Err(Error::Rejected(crate::RejectionReason::NativeDerivation(
                crate::NativeDerivationRejection::CDeriveKeyUnavailable,
            )));
        }
        let call = outputs::PreparedCall::Sp800 {
            call: Box::new(prepared),
            base: base_handle,
            publication,
        };
        let (coordination, state, diagnostic, cleanup) = observations.publish(
            self,
            state,
            call,
            &reservation,
            permits,
            requests.into_iter().map(|request| request.into_content()),
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
                for segment in parameters.data {
                    if let Sp800Data::Key(key) = segment {
                        key.identity.access().check(&self.snapshot)?;
                    }
                }
                self.mutation_context(access, |cause| cleanup.mark_remaining(cause))?;
                let output = owner.take_vector_output(self, access)?;
                let outputs::Output::Sp800 { publication, .. } = output else {
                    return Err(Error::Rejected(
                        crate::RejectionReason::DerivedObjectCreation(
                            crate::DerivedObjectCreationRejection::Sp800OutputKind,
                        ),
                    ));
                };
                Ok(NativeDerivedKeys {
                    keys: publication.keys,
                    _credit: publication.result_credit,
                })
            },
        )
    }
}
impl crate::AdvancedSession {
    /// Synchronous multi-output derivation through the same native owner.
    pub fn derive_sp800_108<const N: usize>(
        &self,
        base: &crate::NativeObjectRef,
        parameters: Sp800Request<'_>,
        requests: [GenerationTemplate<'_>; N],
    ) -> Result<crate::CreatedObjects<NativeDerivedKeys>> {
        let mut diagnostics = crate::error::PreparedCreationDiagnostics::default();
        self.session
            .derive_sp800_108_selected(base, parameters, requests, &mut diagnostics)
    }
}
