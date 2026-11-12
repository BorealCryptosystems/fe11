// SPDX-License-Identifier: Apache-2.0
//! Only immutable caller choices and scalar needs survive outside possession.
use super::*;

pub(crate) fn find(
    session: &Session,
    selector: ManagedSelector,
    admission: crate::ObjectAdmission,
) -> Result<ManagedObjectRef> {
    let class = validate_selector(&selector)?;
    let content_plan = content_plan(selected_content(&selector));
    let reference = session.reference_admission(
        crate::session::ReferenceMode::Synchronous,
        Session::reference_search_functions,
    )?;
    let progress = reference.progress();
    let epoch = session.snapshot.authentication_stamp();
    let policy = crate::admission_wait::current();
    let fixed = Prepared::allocation_bytes()
        .checked_add(std::mem::size_of::<DiscoveryOwner>())
        .and_then(|bytes| {
            bytes.checked_add(crate::error::PreparedCleanupDiagnostic::allocation_bytes())
        })
        .and_then(|bytes| bytes.checked_add(ObservationProtection::selection_bytes()))
        .ok_or(Error::Rejected(crate::RejectionReason::ObjectSearch(
            crate::ObjectSearchRejection::ManagedDiscoveryStorageSize,
        )))?;
    let selection_bytes = mutations::ManagedSelectionStorage::requested_bytes(&selector)?;
    let mut required = SearchStorage::requested_bytes(
        template::<TemplateSize>(&selector, class).owned_bytes()?,
        admission.search,
    )?
    .checked_add(fixed)
    .and_then(|bytes| bytes.checked_add(selection_bytes))
    .ok_or(Error::Rejected(crate::RejectionReason::ObjectSearch(
        crate::ObjectSearchRejection::ManagedDiscoveryStorageSize,
    )))?;
    let (mut search_cleanup, coordination, first_access) = loop {
        context(session, Some(epoch), epoch)?;
        policy.check_available()?;
        session.admission().check_available()?;
        let (permit, mut credit) =
            reference.managed_with_observation_storage(1, required, || {
                context(session, Some(epoch), epoch)
            })?;
        let storage = SearchStorage::allocate_owned(
            template::<Template>(&selector, class),
            admission.search,
        )?;
        let selection = mutations::ManagedSelectionStorage::allocate(&selector)?;
        let actual = storage
            .allocated_bytes()?
            .checked_add(fixed)
            .and_then(|bytes| bytes.checked_add(selection.allocated_bytes()))
            .ok_or(Error::Rejected(crate::RejectionReason::ObjectSearch(
                crate::ObjectSearchRejection::ManagedDiscoveryStorageSize,
            )))?;
        if actual > required {
            drop(selection);
            drop(storage);
            drop(credit);
            drop(permit);
            required = actual;
            continue;
        }
        credit.release(required - actual);
        credit.observation_budget()?;
        let search_cleanup = crate::error::PreparedCleanupDiagnostic::prepare(&mut credit)?;
        let registry = Prepared::allocate(&session.inner.symmetric_budget, &mut credit)?;
        let selection = selection.bind(session, &mut credit)?;
        let access = match session.try_operation_access_progress(false, progress) {
            Ok(access) => access,
            Err(Error::Busy(_)) => {
                drop(search_cleanup);
                drop(selection);
                drop(storage);
                drop(registry);
                drop(credit);
                drop(permit);
                drop(session.access_progress(progress)?);
                continue;
            }
            Err(error) => return Err(error),
        };
        context(session, Some(epoch), epoch)?;
        reference.check(&access)?;
        SearchOwner::check_functions(&access)?;
        session
            .entry
            .recovery
            .observations
            .check_search_available()?;
        let selected = selection
            .select(session)?
            .into_owned(&session.inner, &session.entry)?;
        let protection = ObservationProtection::selection(session, selected, &mut credit)?;
        let owner = DiscoveryOwner {
            native: None,
            phase: Phase::Search(storage.bind(admission.search, epoch, &access, &mut credit)?),
            class,
            admission: admission.clone(),
            content: take_content(selector),
            content_stage: "managed admission",
            permit: Some(permit),
            epoch,
            protection,
            _credit: credit.split(std::mem::size_of::<DiscoveryOwner>())?,
        };
        let coordination = session
            .entry
            .recovery
            .observations
            .publish(registry.bind_discovery(owner))?;
        break (search_cleanup, coordination, access);
    };
    run(
        session,
        coordination,
        epoch,
        progress,
        class,
        &admission,
        content_plan,
        first_access,
        Some(&mut search_cleanup),
    )
}

fn run<'a>(
    session: &'a Session,
    coordination: Arc<crate::session::recovery::observations::Coordination>,
    epoch: u64,
    progress: &crate::session::AdmissionProgress,
    class: ManagedClass,
    admission: &crate::ObjectAdmission,
    content_plan: Option<ContentReadPlan>,
    first_access: SessionAccess<'a>,
    search_cleanup: Option<&mut crate::error::PreparedCleanupDiagnostic>,
) -> Result<ManagedObjectRef> {
    let policy = crate::admission_wait::current();
    let waiter = Waiting::new(session, coordination, Some(epoch), epoch);
    let search_open = std::cell::Cell::new(false);
    let _withdrawal = SearchWithdrawal::new(session, &search_open);
    let mut access = Some(first_access);
    let result = (|| loop {
        waiter.check()?;
        let owned_access =
            access
                .take()
                .ok_or(Error::Rejected(crate::RejectionReason::ObjectSearch(
                    crate::ObjectSearchRejection::ManagedDiscoveryPossessionAbsent,
                )))?;
        let slot = session
            .entry
            .recovery
            .observations
            .get(&waiter.coordination)?;
        let mut payload = slot.owner.lock().map_err(|_| Error::Poisoned)?;
        let owner = payload
            .as_mut()
            .ok_or(Error::Rejected(crate::RejectionReason::ObjectSearch(
                crate::ObjectSearchRejection::ManagedDiscoveryOwnerAbsent,
            )))?
            .discovery_mut()?;
        search_open.set(owner.search_claimed());
        let advanced = owner.advance(session, &owned_access);
        search_open.set(owner.search_claimed() && owner.pending());
        advanced?;
        if owner.complete() {
            return payload
                .take()
                .expect("completed managed discovery")
                .into_discovery()?
                .result(session, &owned_access);
        }
        let need = owner
            .need()?
            .ok_or(Error::Rejected(crate::RejectionReason::ObjectSearch(
                crate::ObjectSearchRejection::ManagedDiscoveryNeedAbsent,
            )))?;
        drop(payload);
        drop(slot);
        drop(owned_access);
        loop {
            let candidate = prepare(
                need,
                class,
                &admission,
                content_plan,
                session,
                &policy,
                &waiter,
            )?;
            // Attach empty storage using only the resident-owner lock. No
            // native dispatch or session access is needed for this transition.
            // Thus every fallible attach (including nested helpers consuming
            // the candidate) releases refused storage outside session guards.
            waiter.check()?;
            let slot = session
                .entry
                .recovery
                .observations
                .get(&waiter.coordination)?;
            let mut payload = slot.owner.lock().map_err(|_| Error::Poisoned)?;
            payload
                .as_mut()
                .ok_or(Error::Rejected(crate::RejectionReason::ObjectSearch(
                    crate::ObjectSearchRejection::ManagedDiscoveryOwnerAbsent,
                )))?
                .discovery_mut()?
                .attach(need, candidate)?;
            drop(payload);
            drop(slot);
            access = Some(session.access_progress_at_epoch(progress, epoch)?);
            break;
        }
    })();
    drop(access);
    // Observation of an existing NativeObjectRef starts at Required and never
    // enters Search. It needs neither FindObjectsFinal nor cleanup storage.
    let Some(search_cleanup) = search_cleanup else {
        debug_assert!(!search_open.get());
        return result;
    };
    let result = crate::managed::search::finish_failed_search(
        session,
        &waiter.coordination,
        &search_open,
        result,
        search_cleanup,
        None,
        || session.try_advanced_access_progress(progress),
        |owner, access| {
            let owner = owner.discovery_mut()?;
            let cleanup = owner.finish_search(session, access);
            search_open.set(owner.search_claimed() && owner.pending());
            cleanup
        },
    );
    result
}

fn selected_content(selector: &ManagedSelector) -> &ContentObservation {
    match selector {
        ManagedSelector::Class { content, .. }
        | ManagedSelector::Key { content, .. }
        | ManagedSelector::Certificate { content, .. }
        | ManagedSelector::Data { content, .. } => content,
    }
}
fn take_content(selector: ManagedSelector) -> ContentObservation {
    match selector {
        ManagedSelector::Class { content, .. }
        | ManagedSelector::Key { content, .. }
        | ManagedSelector::Certificate { content, .. }
        | ManagedSelector::Data { content, .. } => content,
    }
}
fn validate_selector(selector: &ManagedSelector) -> Result<ManagedClass> {
    Ok(match selector {
        ManagedSelector::Class { class, .. } => {
            if matches!(class, ManagedClass::Other(_)) {
                return Err(Error::Rejected(crate::RejectionReason::ObjectSearch(
                    crate::ObjectSearchRejection::UnknownObjectClassRequiresAnExtensionContract,
                )));
            }
            *class
        }
        ManagedSelector::Key { class, id, .. } => {
            if !class.key() {
                return Err(Error::Rejected(crate::RejectionReason::ObjectSearch(
                    crate::ObjectSearchRejection::ManagedKeySelector,
                )));
            }
            id_valid(id)?;
            *class
        }
        ManagedSelector::Certificate { id, .. } => {
            id_valid(id)?;
            ManagedClass::Certificate
        }
        ManagedSelector::Data {
            application,
            object_type,
            label,
            ..
        } => {
            for bytes in [
                application.as_slice(),
                object_type.as_slice(),
                label.as_slice(),
            ] {
                crate::bounds::ck_length(bytes.len())?;
            }
            ManagedClass::Data
        }
    })
}
// The same borrowed recipe counts and materializes the template. Caller-owned
// selectors are not copied until local admission, publication quota and byte credit are held.
fn template<T: TemplateSink>(selector: &ManagedSelector, class: ManagedClass) -> T {
    let mut template = T::empty();
    match selector {
        ManagedSelector::Class { .. } => {}
        ManagedSelector::Key { id, .. } | ManagedSelector::Certificate { id, .. } => {
            template.bytes(CKA_ID, id)
        }
        ManagedSelector::Data {
            application,
            object_type,
            label,
            ..
        } => {
            template.bytes(CKA_APPLICATION, application);
            template.bytes(CKA_OBJECT_ID, object_type);
            template.bytes(CKA_LABEL, label);
        }
    }
    template.integer(CKA_CLASS, class.raw());
    template
}

/// Read a descriptive view of an existing generic owner. No new reference slot
/// or native object is created, and failure leaves the borrowed owner intact.
pub(in crate::managed) fn observe_native(
    session: &Session,
    object: &NativeObjectRef,
    class: ManagedClass,
    admission: crate::ObjectAdmission,
    content: ContentObservation,
) -> Result<ManagedObjectRef> {
    if !Arc::ptr_eq(&session.inner, &object.inner) {
        return Err(Error::Rejected(crate::RejectionReason::ObjectReferences(
            crate::ObjectReferencesRejection::ForeignNativeObject,
        )));
    }
    let selected_content = content_plan(&content);
    let mut reference =
        session.reference_admission(crate::session::ReferenceMode::Synchronous, |state| {
            state
                .native
                .table
                .C_GetAttributeValue
                .ok_or(Error::Rejected(crate::RejectionReason::AttributeValues(
                    crate::AttributeValuesRejection::CGetAttributeValueUnavailable,
                )))
                .map(|_| ())
        })?;
    // Only a ledger token is needed to reuse the common discovery driver.
    // Its zero quota cannot wait for a slot held by the borrowed object.
    let permit = reference.managed(0)?;
    let progress = reference.progress();
    let epoch = session.snapshot.authentication_stamp();
    let policy = crate::admission_wait::current();
    let fixed = Prepared::allocation_bytes();
    let mut required = preparation::SelectedInitial::requested(class, &admission)?
        .checked_add(fixed)
        .ok_or(Error::Rejected(crate::RejectionReason::ObjectSearch(
            crate::ObjectSearchRejection::NativeObservationStorageSize,
        )))?;
    let (coordination, first) = loop {
        object.identity.access().check(&session.snapshot)?;
        let reader =
            object
                .identity
                .activity()?
                .prepare_reader_checked(session.uid, &policy, || {
                    object.identity.access().check(&session.snapshot)
                })?;
        let mut credit =
            crate::advanced::reserve_preparation_with_progress(session, required, progress)?;
        let initial = preparation::SelectedInitial::allocate(class, &admission)?;
        let actual = initial
            .allocated_bytes()?
            .checked_add(fixed)
            .ok_or(Error::Rejected(crate::RejectionReason::ObjectSearch(
                crate::ObjectSearchRejection::NativeObservationStorageSize,
            )))?;
        if actual > required {
            drop((initial, credit, reader));
            required = actual;
            continue;
        }
        credit.release(required - actual);
        let registry = Prepared::allocate(&session.inner.symmetric_budget, &mut credit)?;
        let mut reader_permit = None;
        let access = match session.try_operation_access_progress(false, progress) {
            Ok(access) => access,
            Err(Error::Busy(_)) => {
                drop((registry, initial, credit, reader));
                drop(session.access_progress(progress)?);
                continue;
            }
            Err(error) => return Err(error),
        };
        reference.check(&access)?;
        let handle = session.native_identity_handle(&access, &object.identity)?;
        let protection = match reader.acquire_into(&policy, &mut reader_permit) {
            Ok(()) => ObservationProtection::object(
                reader_permit.take().expect("observation reader acquired"),
            ),
            Err(Error::Busy(_)) => {
                drop(access);
                drop((registry, initial, credit));
                reader.wait_available_checked(&policy, || {
                    object.identity.access().check(&session.snapshot)
                })?;
                continue;
            }
            Err(error) => return Err(error),
        };
        let owner = initial
            .bind(
                class,
                handle,
                admission.clone(),
                content,
                "native object observation",
                permit,
                epoch,
                protection,
                &mut credit,
            )?
            .retain_native(object.identity.clone());
        let coordination = session
            .entry
            .recovery
            .observations
            .publish(registry.bind_discovery(owner))?;
        break (coordination, access);
    };
    run(
        session,
        coordination,
        epoch,
        progress,
        class,
        &admission,
        selected_content,
        first,
        None,
    )
}
