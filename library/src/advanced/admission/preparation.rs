// SPDX-License-Identifier: Apache-2.0
//! Prepare key admission storage and observation phases before dispatch.
//! The operation owner receives the request and its accounting together.

use super::*;

pub(super) fn start_admission(
    session: &Session,
    policy: input::Input<'_>,
    generate: bool,
    pacing: OperationPacing,
    mode: crate::session::ReferenceMode,
    diagnostics: &mut super::super::poll::PollDiagnostics,
) -> Result<OperationTicket> {
    // Capture before the first potentially waiting preflight, then retain this
    // epoch and the returned progress throughout every aggregate retry.
    let authentication = session.snapshot.authentication_stamp();
    let references = session.reference_admission_at_epoch(mode, authentication, |state| {
        check_initial_functions(state, &policy, generate)
    })?;
    let mut guarded = Admission::new(
        session,
        policy,
        generate,
        generate && matches!(mode, crate::session::ReferenceMode::SynchronousAdmission),
        authentication,
        references,
    )?;
    diagnostics.pending = guarded.pending_marker.take();
    let s = guarded
        .access
        .as_ref()
        .expect("successful admission possession");
    let body = guarded.body.as_mut().expect("assembled admission");
    check_initial_functions(s, body.frames.policy(), generate)?;
    body.check_search_functions(&s)?;
    if body
        .destinations
        .as_ref()
        .map_or(true, |destinations| destinations.maximum_batch() != 0)
    {
        session
            .entry
            .recovery
            .observations
            .check_search_available()?;
    }
    session
        .snapshot
        .check_authentication_unchanged(authentication)?;
    let (token, cancel) = crate::advanced::preparation::Shell::bind_retained(
        &mut guarded.shell,
        &s.lease_admission()?,
    )?;
    guarded.operation = Some(Operation::new(
        OperationBody::Admission(guarded.body.take().expect("assembled admission")),
        token,
        cancel,
    ));
    let (id, operation) = s.operations.install_retained(
        &session.entry,
        &mut guarded.operation,
        &mut guarded.registry,
    )?;
    let ticket = OperationTicket {
        owner: session.inner.clone(),
        uid: session.uid,
        id,
        validation_report: None,
        state_provenance: None,
    };
    guarded.installed = Some(operation);
    // Errors from the first drive can outlive this internal starter while a
    // synchronous facade projects them. Its public root owns this final anchor.
    diagnostics.retired_owner = guarded.installed.clone();
    let mut operation = guarded
        .installed
        .as_ref()
        .expect("installed operation anchor")
        .lock()
        .map_err(|_| Error::Poisoned)?;
    s.operations.claim_progress(&session.entry, id)?;
    if let Err(error) = drive(
        &s,
        &session.entry,
        &mut operation,
        false,
        &mut pacing.budget(),
    ) {
        if let OperationBody::Admission(body) = &mut operation.body {
            if body
                .publication
                .as_ref()
                .is_some_and(|value| value.complete())
            {
                // Return the ticket even when its first descriptive step failed.
                // Poll publishes the original error and the already created objects.
                body.failure = Some(error);
                return Ok(ticket);
            }
        }
        let (error, _) = operation.retire_terminal_error(&s, &session.entry, error);
        return Err(error);
    }
    Ok(ticket)
}

impl Admission {
    pub(super) fn new<'a>(
        session: &'a Session,
        mut policy: input::Input<'_>,
        generate: bool,
        pending_marker: bool,
        authentication: u64,
        references: crate::session::ReferenceAdmission<'a>,
    ) -> Result<GuardedAdmission<'a>> {
        let mut reference_admission = Some(references);
        let references = reference_admission
            .as_ref()
            .expect("initial reference context");
        let progress = references.progress();
        let reference_count = 1 + usize::from(policy.is_pair());
        let resources = crate::admission_wait::current();
        let session_policy = session.admission();
        let generation_plan = if generate {
            Some(generation::preparation::Plan::new(&policy)?)
        } else {
            None
        };
        // Mechanism observation choices are inline values. Only the remaining
        // owned metadata has additional storage to charge here.
        let policy_bytes = policy.symmetric_metadata_bytes()?;
        let fixed_bytes = if generate {
            (if policy.is_pair() { 2 } else { 1 })
                * crate::managed::NativeIdentity::allocation_bytes()
        } else {
            0
        } + std::mem::size_of::<Self>()
            + (1 + usize::from(generate)) * crate::error::CleanupDiagnostic::allocation_bytes()
            + crate::error::CompletionStorage::allocation_bytes()
            + super::super::progress::FailureDiagnostics::allocation_bytes()
            + usize::from(pending_marker)
                * crate::error::PreparedCompletionStorage::allocation_bytes()
            + std::mem::size_of::<CK_ASYNC_DATA>()
            + 2 * std::mem::size_of::<CK_OBJECT_HANDLE>()
            + std::mem::size_of::<CK_ULONG>()
            + if generate {
                std::mem::size_of::<Template>()
            } else {
                0
            };
        let policy_bytes = policy_bytes
            .checked_add(policy.retained_object_observation_bytes()?)
            .ok_or(Error::Rejected(crate::RejectionReason::KeyAdmission(
                crate::KeyAdmissionRejection::ObjectAdmissionMetadataByteCount,
            )))?;
        let bytes = fixed_bytes
            .checked_add(policy_bytes)
            .ok_or(Error::Rejected(crate::RejectionReason::KeyAdmission(
                crate::KeyAdmissionRejection::AdmissionMetadataByteCount,
            )))?;
        let destination_plan = if generate {
            Some(destination::preparation::Plan::new(&policy)?)
        } else {
            None
        };
        let search_plan = policy.object_observation(false).search;
        let batch_capacity = if let Some(destinations) = &destination_plan {
            destinations.maximum_batch()
        } else {
            if policy.is_pair() {
                search_plan
                    .batch_size
                    .get()
                    .max(policy.object_observation(true).search.batch_size.get())
            } else {
                search_plan.batch_size.get()
            }
        };
        let mut prepared_readers = [None, None];
        if !generate {
            prepared_readers[0] = Some(
                managed::selection_activity_at_epoch(
                    session,
                    policy.admission_class(),
                    &[policy.admission_id()],
                    progress,
                    authentication,
                )?
                .prepare_reader(session.uid)?,
            );
            if policy.is_pair() {
                prepared_readers[1] = Some(
                    managed::selection_activity_at_epoch(
                        session,
                        ManagedClass::PrivateKey,
                        &[policy.admission_id()],
                        progress,
                        authentication,
                    )?
                    .prepare_reader(session.uid)?,
                );
            }
        }
        // Independently prepaid children own their inline metadata. The parent
        // charges only the remaining representation, never those bytes twice.
        let child_inline = if generate {
            std::mem::size_of::<Generation>()
        } else {
            0
        } + if destination_plan.is_some() {
            std::mem::size_of::<CreationDestinations>()
        } else {
            0
        };
        let child_inline = child_inline
            .checked_add(policy.parent_inline_bytes())
            .ok_or(Error::Rejected(crate::RejectionReason::KeyAdmission(
                crate::KeyAdmissionRejection::AdmissionMetadataByteCount,
            )))?;
        let bytes = bytes.checked_sub(child_inline).ok_or(Error::Rejected(
            crate::RejectionReason::KeyAdmission(
                crate::KeyAdmissionRejection::AdmissionMetadataByteCount,
            ),
        ))?;
        let family_plan = policy.initial_plan();
        let family_requested = family_plan.requested_bytes()?;
        let owner_requested = policy.requested_bytes()?;
        let registry_bytes = super::super::ledger::PreparedOperation::allocation_bytes()?;
        let initial_plan = initial::Plan::new(&policy, generate, batch_capacity, bytes)?;
        let mut required = initial_plan
            .requested_bytes()
            .checked_add(
                generation_plan
                    .as_ref()
                    .map_or(0, generation::preparation::Plan::requested_bytes),
            )
            .and_then(|n| {
                n.checked_add(
                    destination_plan
                        .as_ref()
                        .map_or(0, destination::preparation::Plan::requested_bytes),
                )
            })
            .and_then(|n| n.checked_add(crate::advanced::preparation::Shell::allocation_bytes()))
            .and_then(|n| n.checked_add(registry_bytes))
            .and_then(|n| n.checked_add(family_requested))
            .and_then(|n| n.checked_add(owner_requested))
            .ok_or(Error::Rejected(crate::RejectionReason::KeyAdmission(
                crate::KeyAdmissionRejection::AdmissionMetadataByteCount,
            )))?;
        let recipes = generation_plan
            .as_ref()
            .map(|plan| plan.recipes(session, &policy))
            .transpose()?;
        let mut prepare_candidate = |overhead: usize,
                                     current: &dyn Fn() -> Result<bool>|
         -> Result<Option<(InitialCandidate, Credit)>> {
            loop {
                let total = required.checked_add(overhead).ok_or(Error::Rejected(
                    crate::RejectionReason::KeyAdmission(
                        crate::KeyAdmissionRejection::AdmissionMetadataByteCount,
                    ),
                ))?;
                let group = references.managed_with_storage(reference_count, total, || {
                    crate::session::recovery::observations::context(
                        session,
                        Some(authentication),
                        authentication,
                    )?;
                    if !current()? {
                        return Err(Error::Busy(crate::BusyReason::KeyAdmission(
                            crate::KeyAdmissionBusy::InitialCreationPlanChanged,
                        )));
                    }
                    Ok(())
                });
                let (mut permit, mut credit) = match group {
                    Ok(group) => group,
                    Err(Error::Busy(crate::BusyReason::KeyAdmission(
                        crate::KeyAdmissionBusy::InitialCreationPlanChanged,
                    ))) => return Ok(None),
                    Err(error) => return Err(error),
                };
                let owner_storage = policy.allocate()?;
                let generation_storage = generation_plan
                    .as_ref()
                    .map(|plan| plan.allocate(&policy))
                    .transpose()?;
                let destination_storage = destination_plan
                    .as_ref()
                    .map(|plan| plan.allocate(session))
                    .transpose()?;
                let initial_storage = initial_plan.allocate()?;
                let family_storage = family_plan.allocate()?;
                let generation_bytes = generation_storage
                    .as_ref()
                    .map(generation::preparation::Storage::allocated_bytes)
                    .transpose()?
                    .unwrap_or(0);
                let destination_bytes = destination_storage
                    .as_ref()
                    .map(destination::preparation::Storage::allocated_bytes)
                    .transpose()?
                    .unwrap_or(0);
                let family_bytes = family_storage.allocated_bytes()?;
                let owner_bytes = policy.allocated_bytes(&owner_storage)?;
                let actual = initial_plan
                    .allocated_bytes(&initial_storage)?
                    .checked_add(generation_bytes)
                    .and_then(|n| n.checked_add(destination_bytes))
                    .and_then(|n| {
                        n.checked_add(crate::advanced::preparation::Shell::allocation_bytes())
                    })
                    .and_then(|n| n.checked_add(registry_bytes))
                    .and_then(|n| n.checked_add(family_bytes))
                    .and_then(|n| n.checked_add(owner_bytes))
                    .ok_or(Error::Rejected(crate::RejectionReason::KeyAdmission(
                        crate::KeyAdmissionRejection::AdmissionMetadataByteCount,
                    )))?;
                if actual > required {
                    drop((
                        owner_storage,
                        family_storage,
                        initial_storage,
                        destination_storage,
                        generation_storage,
                    ));
                    drop((credit, permit));
                    required = actual;
                    continue;
                }
                credit.release(required - actual);
                // The exclusive poll envelope stays globally charged. A peer
                // may release its own envelope while this operation is waiting;
                // resource admission includes only the current poll's leaves.
                let resource_diagnostics =
                    super::super::progress::FailureDiagnostics::from_prepaid(&mut credit)?;
                let pending_diagnostic = pending_marker
                    .then(|| crate::error::PreparedCompletionStorage::prepare(&mut credit))
                    .transpose()?;
                // The poll adds its global diagnostic leaves explicitly. Only
                // after separating those leaves, attribute the payload AND
                // Activity credit to this continuation. Counting the leaves in
                // both this account and the poll would reject admissible work.
                permit.begin_observation(&mut credit)?;
                let owner = policy.bind(owner_storage, &mut credit)?;
                let generation = generation_storage
                    .map(|storage| {
                        generation_plan
                            .as_ref()
                            .expect("generation storage has a plan")
                            .bind(storage, &mut credit)
                    })
                    .transpose()?;
                let destinations = destination_storage
                    .map(|storage| storage.bind(&mut credit))
                    .transpose()?;
                let family = family_plan.bind(family_storage, &mut credit)?;
                let mut initial = initial_plan.bind(
                    initial_storage,
                    &mut credit,
                    resource_diagnostics,
                    pending_diagnostic,
                )?;
                let publication = if generate {
                    Some(publication::Publication::prepare(
                        session,
                        reference_count,
                        authentication,
                        &mut permit,
                        &mut initial.metadata,
                    )?)
                } else {
                    None
                };
                if initial.primary.is_none() && initial.empty_template.is_none() {
                    return Err(Error::Rejected(crate::RejectionReason::KeyAdmission(
                        crate::KeyAdmissionRejection::PreparedEmptySelectorAbsent,
                    )));
                }
                let cancel = crate::advanced::preparation::Shell::from_prepaid(&mut credit)?;
                let registry = super::super::ledger::PreparedOperation::from_prepaid(&mut credit)?;
                let coordination = credit.split(overhead)?;
                return Ok(Some((
                    InitialCandidate {
                        owner,
                        publication,
                        permit: Some(permit),
                        generation,
                        destinations,
                        family: Some(family),
                        initial,
                        cancel,
                        registry,
                    },
                    coordination,
                )));
            }
        };
        let (
            initial,
            generation,
            destinations,
            cancel,
            registry,
            access,
            readers,
            policy,
            publication,
            permit,
        ) = loop {
            resources.check_available()?;
            session_policy.check_available()?;
            let before = || {
                crate::session::recovery::observations::context(
                    session,
                    Some(authentication),
                    authentication,
                )
            };
            before()?;
            let retirement = managed::DestinationRetirement::new(session);
            retirement.retire();
            let (reservation, candidate) = if let (Some(plan), Some(recipes)) =
                (&generation_plan, &recipes)
            {
                let (reservation, candidate) = managed::prepare_creation_grouped(
                    session,
                    &recipes[..plan.count()],
                    plan.count(),
                    &before,
                    || retirement.retire(),
                    |overhead, current| {
                        prepare_candidate(overhead, &|| Ok(current()? && retirement.current()?))
                    },
                )?;
                (Some(reservation), candidate)
            } else {
                let Some((candidate, coordination)) = prepare_candidate(0, &|| Ok(true))? else {
                    continue;
                };
                drop(coordination);
                (None, candidate)
            };
            // Field order is intentional: even an error during guarded transfer
            // releases access before any partial writer, ticket or reservation.
            let mut attempt = InitialAttempt {
                access: None,
                policy: None,
                generation: None,
                references: None,
                readers: [None, None],
                candidate,
                reservation,
            };
            if let (Some(prepared), Some(reservation)) =
                (&mut attempt.candidate.generation, &attempt.reservation)
            {
                before()?;
                prepared.prepare_ticket(session, reservation)?;
                before()?;
            }
            match session.try_advanced_access_progress_at_epoch(progress, authentication) {
                Ok(access) => attempt.access = Some(access),
                Err(error @ Error::Busy(_)) => {
                    drop(attempt);
                    retirement.retire();
                    if matches!(resources, crate::ResourceAdmission::Immediate)
                        && matches!(session_policy, crate::SessionAdmission::Immediate)
                    {
                        return Err(error);
                    }
                    drop(session.advanced_access_progress_at_epoch(progress, authentication)?);
                    continue;
                }
                Err(error) => return Err(error),
            }
            check_initial_functions(
                attempt.access.as_ref().expect("acquired access"),
                &policy,
                generate,
            )?;
            before()?;
            let need = if let (Some(prepared), Some(reservation)) =
                (&mut attempt.candidate.generation, &attempt.reservation)
            {
                prepared
                    .try_possession(session, reservation)?
                    .map(|_| InitialResource::Creation)
            } else {
                let mut need = None;
                for (index, prepared) in prepared_readers.iter().enumerate() {
                    let Some(prepared) = prepared else { continue };
                    match prepared.acquire_into(&resources, &mut attempt.readers[index]) {
                        Ok(()) => (),
                        Err(Error::Busy(crate::BusyReason::ReferenceRegistry(
                            crate::ReferenceRegistryBusy::ObjectMutation,
                        ))) => {
                            need = Some(InitialResource::Selection(index));
                            break;
                        }
                        Err(error) => return Err(error),
                    }
                }
                need
            };
            if let Some(need) = need {
                drop(attempt);
                retirement.retire();
                match need {
                    InitialResource::Creation => {
                        let plan = generation_plan.as_ref().expect("creation need has a plan");
                        managed::wait_creation_destinations(
                            session,
                            &recipes.as_ref().expect("creation recipes")[..plan.count()],
                            &resources,
                            || {
                                session_policy.check_available()?;
                                before()
                            },
                        )?;
                    }
                    InitialResource::Selection(index) => prepared_readers[index]
                        .as_ref()
                        .ok_or(Error::Rejected(crate::RejectionReason::ReferenceRegistry(
                            crate::ReferenceRegistryRejection::ObjectActivityOwner,
                        )))?
                        .wait_available_in_context(&resources, || {
                            session_policy.check_available()?;
                            before()
                        })?,
                }
                continue;
            }
            resources.check_available()?;
            session_policy.check_available()?;
            before()?;
            // No further retry is allowed after family attachment. A failure
            // keeps access in `attempt` until its other resources can retire.
            references.check(attempt.access.as_ref().expect("acquired access"))?;
            drop(prepare_candidate);
            drop(destination_plan);
            drop(initial_plan);
            // Recipes contain borrowed references; no resource is released here.
            attempt.references = Some(
                crate::session::ReferenceAdmission::into_prepaid_managed_retained(
                    &mut reference_admission,
                    &mut attempt.candidate.permit,
                    reference_count,
                )?,
            );
            attempt.candidate.permit =
                Some(crate::session::ManagedReferences::into_permit_retained(
                    &mut attempt.references,
                    session,
                    attempt.access.as_ref().expect("acquired access"),
                )?);
            // The sole quota now belongs to publication. Family owners have
            // no production quota field and cannot reserve or publish a second one.
            attempt.policy = Some(attempt.candidate.owner.finish(&mut policy)?);
            pair::initial::Prepared::attach_retained(
                &mut attempt.candidate.family,
                attempt.policy.as_mut().expect("prepared family"),
            )?;
            attempt.generation = match &mut attempt.reservation {
                Some(reservation) => Some(generation::preparation::Prepared::transfer(
                    &mut attempt.candidate.generation,
                    session,
                    reservation,
                )?),
                None => None,
            };
            let InitialAttempt {
                access,
                readers,
                candidate,
                reservation,
                policy,
                generation,
                references,
            } = attempt;
            drop(reservation);
            drop(references);
            break (
                candidate.initial,
                generation,
                candidate.destinations,
                candidate.cancel,
                candidate.registry,
                access.expect("successful possession"),
                readers,
                policy.expect("prepared family"),
                candidate.publication,
                candidate.permit.expect("retained publication quota"),
            );
        };
        let mut guarded = GuardedAdmission {
            access: Some(access),
            pending_marker: None,
            body: None,
            shell: Some(cancel),
            operation: None,
            registry: Some(registry),
            installed: None,
        };
        let initial::InitialResources {
            metadata,
            handles,
            found,
            primary,
            empty_template,
            count,
            completion,
            private: private_selector,
            read_plans,
            collection,
            search_diagnostic,
            return_diagnostic,
            retirement_diagnostic,
            resource_diagnostics,
            pending_diagnostic,
        } = initial;
        guarded.pending_marker = pending_diagnostic;
        let (template, attrs, selector_credit) = match primary {
            Some(selector) => (selector.template, selector.attrs, Some(selector.credit)),
            None => (
                empty_template.expect("initial selector checked before possession"),
                Vec::new(),
                None,
            ),
        };
        guarded.body = Some(Self {
            publication,
            stage: Stage::Init,
            dispatched: false,
            pending: false,
            generation,
            destinations,
            failure: None,
            search_diagnostic: Some(search_diagnostic),
            return_diagnostic: Some(return_diagnostic),
            retirement_diagnostic,
            resource_diagnostics: Some(resource_diagnostics),
            frames: Frames::new(
                policy,
                FindFrame {
                    acceptance: SearchAcceptance::Native,
                    _template: template,
                    attrs,
                    handles,
                    count,
                    _selector_credit: selector_credit,
                },
                collection,
                private_selector,
            ),
            completion: CompletionFrame {
                result: completion,
                name: [0; 32],
            },
            found,
            read_plans,
            attributes: None,
            history_observations: None,
            mechanism_report: None,
            object_report: None,
            search_report: None,
            observation_authentication: authentication,
            close_epoch: session.snapshot.domain.close_epoch.load(Ordering::Acquire),
            permit: PublicationQuota::Bound(permit),
            _destination_activity: readers,
            _metadata: metadata,
        });
        let admission = guarded.body.as_mut().expect("assembled admission");
        if let Some(destinations) = &mut admission.destinations {
            let search = admission.frames.search_mut();
            admission.stage =
                if destinations.activate(&mut search.native, &mut search.collection)? {
                    Stage::Init
                } else {
                    Stage::Generate
                };
        }
        Ok(guarded)
    }

    /// Only live search/read/creation stages can need another response buffer.
    /// Destruction and terminal publication must not wait for a fresh envelope
    /// whose credit their own cleanup is intended to return.
    pub(in crate::advanced) fn may_prepare_resource(&self) -> bool {
        !matches!(self.stage, Stage::Destroy | Stage::Done | Stage::Failed)
    }

    pub(super) fn start_mechanism_observation(&mut self) -> Result<()> {
        let selection = self.frames.policy().mechanisms();
        match *selection {
            crate::MechanismObservationPlan::NotRequested => {
                self.mechanism_report = Some(selection.record(crate::Observation::NotRequested)?);
                self.start_object_observation()
            }
            crate::MechanismObservationPlan::Read { .. } => self.next_read(Stage::Allowed),
        }
    }

    pub(super) fn start_object_observation(&mut self) -> Result<()> {
        let selection = self.frames.policy().object_admission();
        if selection.observation_field_iter().next().is_none() {
            self.object_report =
                Some(selection.observe_owned(crate::attributes::ObservedAttributes::empty())?);
            self.complete_object_observations()
        } else {
            self.next_read(Stage::Properties)
        }
    }
}
