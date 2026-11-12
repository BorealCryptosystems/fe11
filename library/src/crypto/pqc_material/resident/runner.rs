// SPDX-License-Identifier: Apache-2.0
//! No private material or native observation follows the waiting caller.
use super::*;

struct Initial {
    identity: ReadStorage,
    before: Option<ReadStorage>,
    repeated: ReadStorage,
    after: Option<ReadStorage>,
}
fn add(values: impl IntoIterator<Item = usize>) -> Result<usize> {
    values.into_iter().try_fold(0usize, |sum, value| {
        sum.checked_add(value)
            .ok_or(Error::Rejected(crate::RejectionReason::PostQuantumKeys(
                crate::PostQuantumKeysRejection::PqcExportMetadataSize,
            )))
    })
}
fn properties(admission: &crate::ObjectAdmission) -> Result<Option<ReadStorage>> {
    if Recipe::Controls(admission).len() == 0 {
        Ok(None)
    } else {
        ReadStorage::allocate(Recipe::Controls(admission)).map(Some)
    }
}
impl Initial {
    fn requested(admission: &crate::ObjectAdmission) -> Result<usize> {
        let identity = ReadStorage::requested(identity_recipe(admission))?;
        let properties = if Recipe::Controls(admission).len() == 0 {
            0
        } else {
            ReadStorage::requested(Recipe::Controls(admission))?
        };
        add([identity, properties, identity, properties])
    }
    fn allocate(admission: &crate::ObjectAdmission) -> Result<Self> {
        Ok(Self {
            identity: ReadStorage::allocate(identity_recipe(admission))?,
            before: properties(admission)?,
            repeated: ReadStorage::allocate(identity_recipe(admission))?,
            after: properties(admission)?,
        })
    }
    fn allocated_bytes(&self) -> Result<usize> {
        let optional = |storage: &Option<ReadStorage>| -> Result<usize> {
            Ok(storage
                .as_ref()
                .map(ReadStorage::allocated_bytes)
                .transpose()?
                .unwrap_or(0))
        };
        add([
            self.identity.allocated_bytes()?,
            optional(&self.before)?,
            self.repeated.allocated_bytes()?,
            optional(&self.after)?,
        ])
    }
}
pub(crate) fn export(
    session: &Session,
    key: &ManagedObjectRef,
    encoding: PqcPrivateEncoding,
    admission: crate::ObjectAdmission,
) -> Result<PqcPrivateExport> {
    if key.class() != ManagedClass::PrivateKey {
        return Err(Error::Rejected(crate::RejectionReason::PostQuantumKeys(
            crate::PostQuantumKeysRejection::PqcExportRequiresPrivateKey,
        )));
    }
    identity_recipe(&admission).validate()?;
    Recipe::Controls(&admission).validate()?;
    let reference =
        session.reference_admission(crate::session::ReferenceMode::Synchronous, |state| {
            state
                .native
                .table
                .C_GetAttributeValue
                .ok_or(Error::Rejected(crate::RejectionReason::AttributeValues(
                    crate::AttributeValuesRejection::CGetAttributeValueUnavailable,
                )))?;
            Ok(())
        })?;
    let epoch = session.snapshot.authentication_stamp();
    let progress = reference.progress();
    let policy = crate::admission_wait::current();
    let reader = key
        .identity
        .activity
        .prepare_reader_checked(session.uid, &policy, || {
            context(session, Some(epoch), epoch)
        })?;
    let fixed = add([
        Prepared::allocation_bytes(),
        std::mem::size_of::<PqcExportOwner>(),
    ])?;
    let mut required = add([fixed, Initial::requested(&admission)?])?;
    let (coordination, first_access) = loop {
        context(session, Some(epoch), epoch)?;
        policy.check_available()?;
        session.admission().check_available()?;
        let mut credit =
            crate::advanced::reserve_preparation_with_progress(session, required, progress)?;
        let storage = Initial::allocate(&admission)?;
        let actual = add([fixed, storage.allocated_bytes()?])?;
        if actual > required {
            drop(storage);
            drop(credit);
            required = actual;
            continue;
        }
        credit.release(required - actual);
        let registry = Prepared::allocate(&session.inner.symmetric_budget, &mut credit)?;
        let acquired = (|| {
            // This slot predates access: refusal releases the guards first.
            let mut permit = None;
            let access = session.try_operation_access_progress(false, progress)?;
            reference.check(&access)?;
            reader.acquire_into(&policy, &mut permit)?;
            let handle = session.managed_handle(&access, key)?;
            Ok((access, permit.take().expect("reader acquired"), handle))
        })();
        match acquired {
            Ok((access, permit, handle)) => {
                let protection = ObservationProtection::object(permit);
                let initial = storage.identity.bind_with_protection(
                    &mut credit,
                    identity_recipe(&admission),
                    handle,
                    Some(epoch),
                    protection.duplicate()?,
                )?;
                let owner_credit = credit.split(std::mem::size_of::<PqcExportOwner>())?;
                let owner = PqcExportOwner {
                    phase: Phase::Identity(initial),
                    future: FutureReads {
                        before: storage.before,
                        identity: Some(storage.repeated),
                        after: storage.after,
                        credit,
                    },
                    admission,
                    protection,
                    epoch,
                    _credit: owner_credit,
                };
                let coordination = session
                    .entry
                    .recovery
                    .observations
                    .publish(registry.bind_pqc_export(owner))?;
                break (coordination, access);
            }
            Err(Error::Busy(_)) => {
                drop(storage);
                drop(registry);
                drop(credit);
                drop(session.access_progress(progress)?);
                reader.wait_available_checked(&policy, || context(session, Some(epoch), epoch))?;
            }
            Err(error) => return Err(error),
        }
    };
    let waiter = Waiting::new(session, coordination, Some(epoch), epoch);
    let mut access = Some(first_access);
    let result = (|| loop {
        waiter.check()?;
        let held =
            access
                .take()
                .ok_or(Error::Rejected(crate::RejectionReason::PostQuantumKeys(
                    crate::PostQuantumKeysRejection::PqcExportPossessionAbsent,
                )))?;
        let handle = session.managed_handle(&held, key)?;
        let slot = session
            .entry
            .recovery
            .observations
            .get(&waiter.coordination)?;
        let mut payload = slot.owner.lock().map_err(|_| Error::Poisoned)?;
        let owner = payload
            .as_mut()
            .ok_or(Error::Rejected(crate::RejectionReason::PostQuantumKeys(
                crate::PostQuantumKeysRejection::PqcExportOwnerAbsent,
            )))?
            .pqc_export_mut()?;
        owner.advance(session, &held, handle)?;
        if matches!(owner.phase, Phase::Complete(_)) {
            return payload
                .take()
                .expect("completed PQC export")
                .into_pqc_export()?
                .result(session, &held, key);
        }
        let need = owner
            .need()
            .ok_or(Error::Rejected(crate::RejectionReason::PostQuantumKeys(
                crate::PostQuantumKeysRejection::PqcExportResourceNeedAbsent,
            )))?;
        drop(payload);
        drop(slot);
        drop(held);
        loop {
            let candidate = prepare(need, encoding, &policy, &waiter)?;
            let resumed = match session.try_operation_access_progress(false, progress) {
                Ok(access) => access,
                Err(Error::Busy(_)) => {
                    drop(candidate);
                    drop(session.access_progress(progress)?);
                    continue;
                }
                Err(error) => return Err(error),
            };
            waiter.check()?;
            session.managed_handle(&resumed, key)?;
            let slot = session
                .entry
                .recovery
                .observations
                .get(&waiter.coordination)?;
            let mut payload = slot.owner.lock().map_err(|_| Error::Poisoned)?;
            payload
                .as_mut()
                .ok_or(Error::Rejected(crate::RejectionReason::PostQuantumKeys(
                    crate::PostQuantumKeysRejection::PqcExportOwnerAbsent,
                )))?
                .pqc_export_mut()?
                .attach(need, candidate)?;
            drop(payload);
            drop(slot);
            access = Some(resumed);
            break;
        }
    })();
    if let Err(error) = &result {
        session.observe_authentication_error(error);
    }
    result
}
