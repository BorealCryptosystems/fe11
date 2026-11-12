// SPDX-License-Identifier: Apache-2.0
//! Bind creation provenance and record whether dispatch created an object.
//! Cleanup follows the exact creator and effect evidence, not a reused handle alone.

use super::*;

impl CreationTicket {
    // The ledger/catalogue retain native lifetime. A resident creation ticket
    // only identifies it and cannot keep its own recovery registry alive.
    pub(super) fn creator(&self) -> Result<Arc<SessionEntry>> {
        self.creator
            .upgrade()
            .ok_or(Error::Rejected(crate::RejectionReason::ObjectCreation(
                crate::ObjectCreationRejection::CreationSessionReleased,
            )))
    }

    pub(crate) fn check_cleanup_epoch(&self) -> Result<()> {
        let creator = self.creator()?;
        creator
            .snapshot
            .check_authentication_unchanged(self.authentication)
            .map_err(|error| {
                creator.poisoned.store(true, Ordering::Release);
                error
            })
    }

    // This closure contains local preparation only, never a native call. Its
    // failure proves no dispatch, independently of native non-creation rules.
    pub(crate) fn prepare_dispatch(
        &self,
        s: &State,
        prepare: impl FnOnce() -> Result<()>,
    ) -> Result<()> {
        let result = self.creator().and_then(|creator| {
            creator
                .snapshot
                .check_authentication_unchanged(self.authentication)?;
            prepare()
        });
        if result.is_err() {
            self.release_uncreated(s);
        }
        result
    }

    pub(crate) fn refused(&self, s: &State, call: crate::native_return::MutationCall, rv: CK_RV) {
        if call.non_creation(rv) {
            self.release_uncreated(s);
        }
    }

    /// The mechanism-specific caller has established completed failure and its
    /// normative no-object guarantee. Unknown completion must not use this path.
    pub(crate) fn refused_without_objects(&self, s: &State) {
        self.release_uncreated(s);
    }

    pub(super) fn release_uncreated(&self, s: &State) {
        let result = (|| {
            let inner = self.inner.upgrade().ok_or(Error::Rejected(
                crate::RejectionReason::ObjectCreation(
                    crate::ObjectCreationRejection::CreationOwnerUnavailable,
                ),
            ))?;
            let mut catalog = inner.reservations.lock().map_err(|_| Error::Poisoned)?;
            if catalog.broken {
                return Err(Error::Poisoned);
            }
            for key in &self.keys {
                let origin = catalog.pending_creations.get(key).ok_or(Error::Rejected(
                    crate::RejectionReason::ObjectCreation(
                        crate::ObjectCreationRejection::CreationRecordMissing,
                    ),
                ))?;
                if !std::sync::Weak::ptr_eq(&Arc::downgrade(&origin.creator), &self.creator)
                    || origin.authentication != self.authentication
                    || !catalog.occupied.contains(key)
                {
                    return Err(Error::Rejected(crate::RejectionReason::ObjectCreation(
                        crate::ObjectCreationRejection::CreationRecordChanged,
                    )));
                }
            }
            for key in &self.keys {
                catalog.pending_creations.remove(key);
            }
            Ok(())
        })();
        if result.is_err() {
            s.native.mark_uncertain();
        }
    }

    pub(crate) fn destroyed(&self, s: &State, handle: CK_OBJECT_HANDLE) -> Result<()> {
        self.check_cleanup_epoch()?;
        let inner =
            self.inner
                .upgrade()
                .ok_or(Error::Rejected(crate::RejectionReason::ObjectCreation(
                    crate::ObjectCreationRejection::CreationOwnerUnavailable,
                )))?;
        let mut catalog = inner.reservations.lock().map_err(|_| Error::Poisoned)?;
        if catalog.broken {
            s.native.mark_uncertain();
            return Err(Error::Poisoned);
        }
        let creator = self.creator()?;
        forget_creation_in(&mut catalog, &creator, handle);
        Ok(())
    }

    /// Prepare distinct resource lifetimes for one native multi-output creation
    /// sharing a destination scope. This happens before dispatch, not while
    /// publishing returned handles. The original pending scope stays retained.
    pub(crate) fn prepare_group(self, state: &State, capacity: usize) -> Result<Self> {
        let prepared = (|| {
            if self.keys.len() != 1 || self.group_resources.len() != capacity {
                return Err(Error::Rejected(crate::RejectionReason::ObjectCreation(
                    crate::ObjectCreationRejection::GroupCreationScope,
                )));
            }
            let inner = self.inner.upgrade().ok_or(Error::Rejected(
                crate::RejectionReason::ObjectCreation(
                    crate::ObjectCreationRejection::CreationOwnerUnavailable,
                ),
            ))?;
            let catalog = inner.reservations.lock().map_err(|_| Error::Poisoned)?;
            let pending = catalog
                .pending_creations
                .get(&self.keys[0])
                .ok_or(Error::Rejected(crate::RejectionReason::ObjectCreation(
                    crate::ObjectCreationRejection::CreatedObjectRecordMissing,
                )))?;
            if pending.close.remaining() < capacity {
                return Err(Error::Rejected(crate::RejectionReason::ObjectCleanup(
                    crate::ObjectCleanupRejection::CreatorCloseCapacityNotPrepared,
                )));
            }
            Ok(())
        })();
        if let Err(cause) = prepared {
            self.release_uncreated(state);
            return Err(cause);
        }
        Ok(self)
    }

    /// A failed registration leaves creation unresolved. The invocation root
    /// supplies the uncertainty leaf prepared before dispatch and retains its
    /// credit through publication or cleanup of the resulting error.
    pub(crate) fn handles_prepared(
        &self,
        s: &State,
        handles: &[CK_OBJECT_HANDLE],
        mark: impl FnOnce(Error) -> Error,
    ) -> Result<()> {
        self.register_handles(s, handles, false).map_err(mark)
    }

    pub(crate) fn handles_group_prepared(
        &self,
        s: &State,
        handles: &[CK_OBJECT_HANDLE],
        mark: impl FnOnce(Error) -> Error,
    ) -> Result<()> {
        self.register_handles(s, handles, true).map_err(mark)
    }

    pub(super) fn register_handles(
        &self,
        s: &State,
        handles: &[CK_OBJECT_HANDLE],
        grouped: bool,
    ) -> Result<()> {
        let creator = self.creator()?;
        if let Err(cause) = creator
            .snapshot
            .check_authentication_unchanged(self.authentication)
        {
            // Successful native creation followed by logout does not leave a
            // trustworthy handle for automatic Destroy. Preserve the ticket.
            creator.poisoned.store(true, Ordering::Release);
            return Err(cause);
        }
        let count_valid = if grouped {
            self.keys.len() == 1 && handles.len() <= self.group_resources.len()
        } else {
            handles.len() == self.keys.len()
        };
        if !count_valid
            || handles
                .iter()
                .enumerate()
                .any(|(i, handle)| *handle == CK_INVALID_HANDLE || handles[..i].contains(handle))
        {
            // Bounded invalid identities do not establish an ABI violation.
            // Keep the destination creation tickets unresolved; do not publish,
            // revoke unrelated aliases or attempt destruction of these values.
            return Err(Error::Rejected(crate::RejectionReason::ObjectCreation(
                crate::ObjectCreationRejection::CreatedObjectHandles,
            )));
        }
        let result = (|| {
            let inner = self.inner.upgrade().ok_or(Error::Rejected(
                crate::RejectionReason::ObjectCreation(
                    crate::ObjectCreationRejection::CreationOwnerUnavailable,
                ),
            ))?;
            // A successful creation returns a new object even if its handle was
            // previously used. Retire old local aliases before publication.
            // Never collect registry entries while holding the catalogue lock.
            for handle in handles {
                crate::managed::destruction::revoke_resource(s, resource(&creator, *handle))?;
            }
            let mut catalog = inner.reservations.lock().map_err(|_| Error::Poisoned)?;
            if catalog.broken {
                return Err(Error::Poisoned);
            }
            for key in &self.keys {
                let pending = catalog.pending_creations.get(key).ok_or(Error::Rejected(
                    crate::RejectionReason::ObjectCreation(
                        crate::ObjectCreationRejection::CreatedObjectRecordMissing,
                    ),
                ))?;
                if !std::sync::Weak::ptr_eq(&Arc::downgrade(&pending.creator), &self.creator)
                    || pending.authentication != self.authentication
                {
                    return Err(Error::Rejected(crate::RejectionReason::ObjectCreation(
                        crate::ObjectCreationRejection::CreatedObjectRecordChanged,
                    )));
                }
            }
            self.publication.check(&catalog, handles.len())?;
            for (index, handle) in handles.iter().enumerate() {
                let key = &self.keys[if grouped { 0 } else { index }];
                let pending = catalog
                    .pending_creations
                    .get_mut(key)
                    .ok_or(Error::Rejected(crate::RejectionReason::ObjectCreation(
                        crate::ObjectCreationRejection::CreatedObjectRecordMissing,
                    )))?;
                let close = pending.close.take()?;
                let creator = pending.creator.clone();
                let destination_activity = pending.destination_activity.clone();
                let resource_activity = if grouped {
                    self.group_resources[index].clone()
                } else {
                    pending.resource_activity.clone()
                };
                let resource = resource(&creator, *handle);

                catalog.resource_activities.insert(
                    resource.native(),
                    ResourceActivity {
                        activity: Arc::downgrade(&resource_activity),
                        visibility: None,
                        creation: Some(CreationEpoch {
                            session: creator.credit.uid(),
                            authentication: self.authentication,
                        }),
                    },
                );
                catalog.origins.insert(
                    resource.native(),
                    Origin {
                        _close: close,
                        creator,
                        destination: key.clone(),
                        destination_activity,
                        resource_activity,
                        visibility: None,
                    },
                );
                self.publication.consume(&mut catalog)?;
            }
            // Remove the pending scope only after every returned object has an
            // origin. A zero-output group proves no object for this completed call.
            for key in &self.keys {
                catalog.pending_creations.remove(key);
            }
            Ok(())
        })();
        if let Err(cause) = result {
            s.native.mark_uncertain();
            return Err(cause);
        }
        Ok(())
    }
}

// Only a creation originating in this session and authentication epoch may
// be destroyed by automatic post-creation cleanup. No native call is made here.
pub(in crate::managed::mutations) fn check_creation_for_cleanup(
    session: &Session,
    handle: CK_OBJECT_HANDLE,
) -> Result<()> {
    let result = (|| {
        let catalog = session
            .inner
            .reservations
            .lock()
            .map_err(|_| Error::Poisoned)?;
        if catalog.broken {
            return Err(Error::Poisoned);
        }
        let creation = catalog
            .resource_activities
            .get(&resource(&session.entry, handle).native())
            .and_then(|entry| entry.creation)
            .ok_or(Error::Rejected(crate::RejectionReason::ObjectCreation(
                crate::ObjectCreationRejection::CreationOriginUnavailableForCleanup,
            )))?;
        if creation.session != session.uid {
            return Err(Error::Rejected(crate::RejectionReason::ObjectCreation(
                crate::ObjectCreationRejection::CreationOwnerChangedBeforeCleanup,
            )));
        }
        session
            .snapshot
            .check_authentication_unchanged(creation.authentication)
    })();
    if result.is_err() {
        session.entry.poisoned.store(true, Ordering::Release);
    }
    result
}

pub(crate) fn object_creator(
    session: &Session,
    handle: CK_OBJECT_HANDLE,
    persistence: crate::Observation<bool>,
    visibility: crate::Observation<bool>,
) -> Result<ObjectCreator> {
    if let crate::Observation::NativeError {
        function,
        code,
        may_have_effect,
    } = persistence
    {
        return Err(Error::Native {
            function,
            code,
            may_have_effect,
        });
    }
    let resource = resource(&session.entry, handle);
    let mut catalog = session
        .inner
        .reservations
        .lock()
        .map_err(|_| Error::Poisoned)?;
    if catalog.broken {
        return Err(Error::Poisoned);
    }
    let origin = catalog.origins.get_mut(&resource.native());
    if persistence == crate::Observation::Observed(true) {
        if origin.is_some() {
            catalog.origins.remove(&resource.native());
        }
        return Ok(ObjectCreator::TokenObject);
    }
    let Some(origin) = origin else {
        if catalog
            .unknown_closing
            .contains_key(&(resource.slot, resource.generation))
        {
            return Err(Error::Busy(crate::BusyReason::ObjectCreation(
                crate::ObjectCreationBusy::UnknownCreatorSessionClosing,
            )));
        }
        return Ok(if persistence == crate::Observation::Observed(false) {
            ObjectCreator::UnknownSessionCreator
        } else {
            ObjectCreator::UnknownPersistence
        });
    };
    let creator = ObjectCreator::Known(Arc::downgrade(&origin.creator));
    check_creator(&creator)?;
    remember_visibility(&mut origin.visibility, visibility);
    Ok(creator)
}

pub(crate) fn check_creator(creator: &ObjectCreator) -> Result<()> {
    if let ObjectCreator::Known(creator) = creator {
        let e =
            creator
                .upgrade()
                .ok_or(Error::Rejected(crate::RejectionReason::ObjectCreation(
                    crate::ObjectCreationRejection::CreatingSessionReleased,
                )))?;
        if e.closed.load(Ordering::Acquire) {
            return Err(Error::Rejected(crate::RejectionReason::ObjectCreation(
                crate::ObjectCreationRejection::CreatingSessionClosed,
            )));
        }
        if e.close_attempted.load(Ordering::Acquire) {
            return Err(Error::Rejected(crate::RejectionReason::ObjectCreation(
                crate::ObjectCreationRejection::CreatingSessionClosingOrUncertain,
            )));
        }
    }
    Ok(())
}

pub(crate) fn forget_created_handle(session: &Session, handle: CK_OBJECT_HANDLE) -> Result<()> {
    let mut catalog = session
        .inner
        .reservations
        .lock()
        .map_err(|_| Error::Poisoned)?;
    if catalog.broken {
        return Err(Error::Poisoned);
    }
    forget_creation_in(&mut catalog, &session.entry, handle);
    Ok(())
}

/// Called only after confirmed destruction of this session's creation. The
/// session guard excludes another creation by the same creator; other sessions
/// may already have published a new object reusing the returned native handle.
/// Compare and remove under one catalogue lock, without invalidating that object.
fn forget_creation_in(catalog: &mut Catalog, creator: &SessionEntry, handle: CK_OBJECT_HANDLE) {
    let key = resource(creator, handle).native();
    let uid = creator.credit.uid();
    if catalog
        .origins
        .get(&key)
        .is_some_and(|origin| origin.creator.credit.uid() == uid)
    {
        catalog.origins.remove(&key);
    }
    if catalog.resource_activities.get(&key).is_some_and(|entry| {
        entry
            .creation
            .is_some_and(|creation| creation.session == uid)
    }) {
        catalog.resource_activities.remove(&key);
    }
}

pub(crate) fn forget_creator(inner: &Inner, uid: u64) -> Result<()> {
    let mut catalog = inner.reservations.lock().map_err(|_| Error::Poisoned)?;
    if catalog.broken {
        return Err(Error::Poisoned);
    }
    // Discard knowledge for objects actually created by the closing session,
    // including evaluations made through another session's handle binding.
    let Catalog {
        origins,
        resource_activities,
        pending_creations,
        ..
    } = &mut *catalog;
    resource_activities.retain(|resource, activity| {
        activity.activity.strong_count() > 0
            && !origins
                .get(resource)
                .is_some_and(|origin| origin.creator.credit.uid() == uid)
    });
    origins.retain(|_, origin| origin.creator.credit.uid() != uid);
    pending_creations.retain(|_, pending| pending.creator.credit.uid() != uid);
    Ok(())
}

pub(crate) fn forget_private_origins(
    inner: &Inner,
    state: &State,
    slot: CK_SLOT_ID,
    generation: u64,
) -> Result<()> {
    // Logout holds the token writer and has expired authentication observations.
    // Numeric references survive for native validation, including private and
    // unknown ones. Preserve their catalogue activity so a rediscovered alias
    // cannot obtain a different protection for the same native handle.
    let objects = state.objects.live()?;
    let managed = state.managed.live()?;
    let capacity = objects
        .len()
        .checked_add(managed.len())
        .ok_or(Error::Rejected(crate::RejectionReason::ObjectCreation(
            crate::ObjectCreationRejection::LogoutAliasSnapshotSize,
        )))?;
    let mut survivors = std::collections::HashSet::new();
    survivors.try_reserve(capacity).map_err(|_| {
        Error::Rejected(crate::RejectionReason::ObjectCreation(
            crate::ObjectCreationRejection::LogoutAliasSnapshotAllocation,
        ))
    })?;
    for object in &objects {
        if object.slot == slot
            && object.generation == generation
            && !object.revoked.load(Ordering::Acquire)
        {
            survivors.insert(object.resource().native());
        }
    }
    for object in &managed {
        if object.slot == slot
            && object.generation == generation
            && !object.revoked.load(Ordering::Acquire)
        {
            survivors.insert(object.resource().native());
        }
    }
    let mut catalog = inner.reservations.lock().map_err(|_| Error::Poisoned)?;
    if catalog.broken {
        return Err(Error::Poisoned);
    }
    catalog.origins.retain(|key, o| {
        !(key.slot == slot
            && key.generation == generation
            && !survivors.contains(key)
            && o.visibility
                .is_some_and(|v| v != crate::Observation::Observed(false)))
    });
    catalog.resource_activities.retain(|key, entry| {
        !(key.slot == slot
            && key.generation == generation
            && !survivors.contains(key)
            && entry
                .visibility
                .is_some_and(|v| v != crate::Observation::Observed(false)))
    });

    Ok(())
}
