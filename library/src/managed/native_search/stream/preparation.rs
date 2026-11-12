// SPDX-License-Identifier: Apache-2.0
//! Private, credited preparation precedes possession and native initialization.
use super::*;

pub(super) fn start<'session, 'input>(
    session: &'session Session,
    input: &'input [AttributeInput<'input>],
    limits: AttributeTemplateLimits,
    batch_size: NonZeroUsize,
) -> Result<NativeObjectIterator<'session>> {
    let template = InputTemplate::plan_scoped(input, limits, &session.inner)?;
    let reference =
        session.reference_admission(crate::session::ReferenceMode::Synchronous, |state| {
            if state.native.table.C_FindObjectsInit.is_none() {
                return Err(Error::Unsupported(
                    crate::UnsupportedReason::NativeFunction {
                        function: "C_FindObjectsInit",
                    },
                ));
            }
            if state.native.table.C_FindObjects.is_none() {
                return Err(Error::Unsupported(
                    crate::UnsupportedReason::NativeFunction {
                        function: "C_FindObjects",
                    },
                ));
            }
            if state.native.table.C_FindObjectsFinal.is_none() {
                return Err(Error::Unsupported(
                    crate::UnsupportedReason::NativeFunction {
                        function: "C_FindObjectsFinal",
                    },
                ));
            }
            Ok(())
        })?;
    let epoch = session.snapshot.authentication_stamp();
    let image = session.inner.read()?.native.image.clone();
    let plan = SearchPlan {
        maximum_objects: None,
        batch_size,
    };
    let fixed = Prepared::allocation_bytes()
        .checked_add(std::mem::size_of::<NativeSearchStreamOwner>())
        .and_then(|bytes| bytes.checked_add(StreamDiagnostics::allocation_bytes()))
        .ok_or(Error::Rejected(crate::RejectionReason::ObjectSearch(
            crate::ObjectSearchRejection::SearchStreamStorageAccounting,
        )))?;
    let mut required = NativeStorage::requested(template.prepared_allocation_bytes()?, plan)?
        .checked_add(fixed)
        .ok_or(Error::Rejected(crate::RejectionReason::ObjectSearch(
            crate::ObjectSearchRejection::SearchStreamStorageAccounting,
        )))?;
    let (diagnostics, coordination) = loop {
        context(session, Some(epoch), epoch)?;
        let mut credit = crate::advanced::reserve_preparation_while(
            session,
            required,
            reference.progress(),
            || {
                context(session, Some(epoch), epoch)?;
                Ok(true)
            },
        )?
        .ok_or(Error::Rejected(crate::RejectionReason::ObjectSearch(
            crate::ObjectSearchRejection::SearchPreparationUnexpectedlyInvalidated,
        )))?;
        let input = template.allocate()?;
        let storage = NativeStorage::allocate(plan)?;
        let actual = input
            .allocated_bytes()?
            .checked_add(storage.allocated_bytes()?)
            .and_then(|bytes| bytes.checked_add(fixed))
            .ok_or(Error::Rejected(crate::RejectionReason::ObjectSearch(
                crate::ObjectSearchRejection::SearchStreamStorageAccounting,
            )))?;
        if actual > required {
            drop((input, storage, credit));
            required = actual;
            continue;
        }
        credit.release(required - actual);
        credit.observation_budget()?;
        let diagnostics = StreamDiagnostics::prepare(&mut credit)?;
        let input = input.bind(&mut credit)?;
        input.check_extensions(&session.inner)?;
        let registry = Prepared::allocate(&session.inner.symmetric_budget, &mut credit)?;
        let owner = NativeSearchStreamOwner {
            search: storage.bind_image(input, plan, epoch, image.clone(), &mut credit)?,
            batch: Batch::Idle,
            _credit: credit.split(std::mem::size_of::<NativeSearchStreamOwner>())?,
        };
        // This early local also anchors the entire owner on publish refusal.
        // No private parameter/batch allocation is freed under possession.
        let mut prepared = Some(registry.bind_native_search_stream(owner));
        let access = match session.try_operation_access_progress(false, reference.progress()) {
            Ok(access) => access,
            Err(Error::Busy(_)) => {
                drop((prepared, diagnostics, credit));
                drop(session.access_progress(reference.progress())?);
                continue;
            }
            Err(error) => return Err(error),
        };
        reference.check(&access)?;
        context(session, Some(epoch), epoch)?;
        // Native Init decides whether another search prevents this one.
        // This attempt has independent resident storage; refusal must not
        // finalize or retire the earlier search.
        let coordination = session
            .entry
            .recovery
            .observations
            .publish_retained(&mut prepared)?;
        break (diagnostics, coordination);
    };
    let mut iterator = NativeObjectIterator {
        session,
        cursor: Some(Cursor {
            session,
            waiter: Waiting::new(session, coordination, Some(epoch), epoch),
            epoch,
            pending: Cell::new(false),
        }),
        cache: None,
        diagnostics: Some(diagnostics),
    };
    let initialized = (|| {
        let cursor = iterator.cursor.as_ref().expect("prepared search cursor");
        let access = session.access_progress(reference.progress())?;
        reference.check(&access)?;
        cursor.waiter.check()?;
        let slot = session
            .entry
            .recovery
            .observations
            .get(&cursor.waiter.coordination)?;
        let mut payload = slot.owner.lock().map_err(|_| Error::Poisoned)?;
        let owner = payload
            .as_mut()
            .ok_or(Error::Rejected(crate::RejectionReason::ObjectSearch(
                crate::ObjectSearchRejection::NativeSearchStreamOwnerAbsent,
            )))?
            .native_search_stream_mut()?;
        // If dispatch unwinds, conservatively retain its stable operands.
        cursor.pending.set(true);
        let result = owner.search.initialize_stream(session, &access);
        cursor.pending.set(owner.pending());
        result
    })();
    match initialized {
        Ok(()) => Ok(iterator),
        Err(error) => {
            let mut diagnostics = iterator
                .diagnostics
                .take()
                .expect("prepared iterator diagnostics");
            Err(iterator.fail(error, &mut diagnostics))
        }
    }
}
