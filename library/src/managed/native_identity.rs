// SPDX-License-Identifier: Apache-2.0
//! One registry lifetime for a native object and all of its descriptive views.
use super::*;
use std::sync::OnceLock;

/// No class, key type or attribute value is inferred from successful creation.
/// Publication installs the returned handle and its shared activity before any
/// optional observation. Typed views retain this same registry entry.
pub(crate) struct NativeIdentity {
    pub(super) _reference_lifetime: crate::registry::ReferenceLifetime,
    pub(super) _credit: Option<crate::symmetric::memory::Credit>,
    pub slot: CK_SLOT_ID,
    pub session: u64,
    pub generation: u64,
    pub handle: CK_OBJECT_HANDLE,
    pub revoked: AtomicBool,
    pub(super) initial_access: ObjectAccess,
    pub(super) initial_creator: ObjectCreator,
    pub(super) observed: OnceLock<ObservedLifetime>,
    pub(super) activity: OnceLock<Arc<crate::registry::Activity>>,
}

pub(super) struct ObservedLifetime {
    pub access: ObjectAccess,
    pub creator: ObjectCreator,
}

/// Single-output creation keeps its publication entirely prepaid. This owner
/// contains no strong module reference while resident in recovery storage.
pub(crate) enum SinglePublication {
    Prepared(Arc<NativeIdentity>),
    Published(Arc<NativeIdentity>),
}
impl SinglePublication {
    pub(crate) fn prepare(
        session: &Session,
        epoch: u64,
        permit: &mut crate::registry::Reservation<NativeIdentity>,
        prepaid: &mut crate::symmetric::memory::Credit,
    ) -> Result<Self> {
        NativeIdentity::prepare_creation(session, epoch, permit, prepaid).map(Self::Prepared)
    }

    pub(crate) fn publish(
        &mut self,
        session: &Session,
        state: &State,
        handle: CK_OBJECT_HANDLE,
        permit: &mut crate::registry::Reservation<NativeIdentity>,
    ) -> Result<()> {
        let Self::Prepared(identity) = self else {
            return Err(Error::Rejected(crate::RejectionReason::ObjectReferences(
                crate::ObjectReferencesRejection::NativeCreationAlreadyPublished,
            )));
        };
        NativeIdentity::publish_created(identity, session, state, handle, permit)?;
        *self = Self::Published(identity.clone());
        Ok(())
    }

    pub(crate) fn identity(&self) -> Option<&Arc<NativeIdentity>> {
        match self {
            Self::Published(identity) => Some(identity),
            Self::Prepared(_) => None,
        }
    }

    pub(crate) fn reference(&self, session: &Session) -> Result<NativeObjectRef> {
        Ok(NativeObjectRef {
            inner: session.inner.clone(),
            identity: self
                .identity()
                .ok_or(Error::Rejected(crate::RejectionReason::ObjectReferences(
                    crate::ObjectReferencesRejection::NativeCreationNotPublished,
                )))?
                .clone(),
            output_slot: Some(0),
        })
    }
}

impl NativeIdentity {
    /// The published identity's own allocation is immutable while borrowed.
    /// Count it when a continuation already retains this identity; do not walk
    /// its mutable activity, close storage, module or weak creator links.
    pub(crate) fn retain_identity_credit(
        &self,
        retained: &mut crate::symmetric::memory::RetainedBytes,
    ) -> Result<()> {
        if let Some(credit) = &self._credit {
            retained.add_credit(credit)?;
        }
        Ok(())
    }

    pub(crate) fn allocation_bytes() -> usize {
        std::mem::size_of::<Self>() + 2 * std::mem::size_of::<usize>()
    }

    /// Allocate the lifetime before the native effect. The invalid handle is
    /// private preparation state and cannot be placed in the registry.
    pub(crate) fn prepare_creation(
        session: &Session,
        epoch: u64,
        permit: &mut crate::registry::Reservation<Self>,
        prepaid: &mut crate::symmetric::memory::Credit,
    ) -> Result<Arc<Self>> {
        let creator = ObjectCreator::Known(Arc::downgrade(&session.entry));
        let access =
            ObjectAccess::bind(&session.snapshot, crate::Observation::NotRequested, epoch)?;
        // All fallible checks precede the lifetime/credit ownership transfer.
        // A known creator needs no unknown-creator close participant.
        let credit = prepaid.split(Self::allocation_bytes())?;
        Ok(Arc::new(Self {
            _reference_lifetime: permit.known_reference_lifetime(),
            _credit: Some(credit),
            slot: session.entry.slot,
            session: session.uid,
            generation: session.snapshot.generation,
            handle: CK_INVALID_HANDLE,
            revoked: AtomicBool::new(false),
            initial_access: access,
            initial_creator: creator,
            observed: OnceLock::new(),
            activity: OnceLock::new(),
        }))
    }

    /// Search results have an unknown creator and persistence. Reserve close
    /// participation before publication; no attribute read is required. A full
    /// search keeps catalog protection while its exact result count is prepared.
    pub(crate) fn prepare_discovery(
        session: &Session,
        epoch: u64,
        permit: &mut crate::registry::Reservation<Self>,
        prepaid: &mut crate::symmetric::memory::Credit,
    ) -> Result<Arc<Self>> {
        let creator = ObjectCreator::UnknownPersistence;
        Ok(Arc::new(Self {
            _reference_lifetime: permit.reference_lifetime_for(&creator)?,
            _credit: Some(prepaid.split(Self::allocation_bytes())?),
            slot: session.entry.slot,
            session: session.uid,
            generation: session.snapshot.generation,
            handle: CK_INVALID_HANDLE,
            revoked: AtomicBool::new(false),
            initial_access: ObjectAccess::bind(
                &session.snapshot,
                crate::Observation::NotRequested,
                epoch,
            )?,
            initial_creator: creator,
            observed: OnceLock::new(),
            activity: OnceLock::new(),
        }))
    }

    /// Publish a selected search handle without claiming that this session
    /// created it. Catalog protection covers search through publication; a
    /// reader of the canonical Activity also excludes already active writers.
    pub(crate) fn publish_discovered(
        prepared: &mut Arc<Self>,
        session: &Session,
        state: &State,
        handle: CK_OBJECT_HANDLE,
        permit: &mut crate::registry::Reservation<Self>,
        publication: &mut [Option<crate::registry::ReadPermit>],
    ) -> Result<()> {
        let identity = Arc::get_mut(prepared).ok_or(Error::Rejected(
            crate::RejectionReason::ObjectReferences(
                crate::ObjectReferencesRejection::DiscoveryIdentityAlreadyShared,
            ),
        ))?;
        if handle == CK_INVALID_HANDLE
            || identity.handle != CK_INVALID_HANDLE
            || identity.session != session.uid
            || identity.slot != session.entry.slot
            || identity.generation != session.snapshot.generation
            || !matches!(identity.initial_creator, ObjectCreator::UnknownPersistence)
        {
            return Err(Error::Rejected(crate::RejectionReason::ObjectReferences(
                crate::ObjectReferencesRejection::DiscoveryIdentityMismatch,
            )));
        }
        let activity = mutations::object_activity_at(
            &session.inner,
            ResourceIdentity {
                handle,
                ..identity.resource()
            },
            crate::Observation::NotRequested,
            permit,
        )?;
        let _reader =
            crate::registry::ReadPermit::take_prepared(publication, &activity, session.uid)?;
        identity.handle = handle;
        identity.activity.set(activity).map_err(|_| {
            Error::Rejected(crate::RejectionReason::ObjectReferences(
                crate::ObjectReferencesRejection::DiscoveryActivityAlreadyBound,
            ))
        })?;
        permit.insert(&state.objects, prepared)
    }

    /// Install a known returned handle without allocating an identity or taking
    /// another quota. The creation ticket has already registered its activity.
    pub(crate) fn publish_created(
        prepared: &mut Arc<Self>,
        session: &Session,
        state: &State,
        handle: CK_OBJECT_HANDLE,
        permit: &mut crate::registry::Reservation<Self>,
    ) -> Result<()> {
        Self::publish_at(
            prepared,
            &session.inner,
            &session.entry,
            state,
            handle,
            permit,
        )
    }

    /// Publication records an already completed native effect. A later context
    /// invalidation can make the reference unusable, but cannot erase its owner.
    pub(crate) fn publish_at(
        prepared: &mut Arc<Self>,
        inner: &Inner,
        entry: &crate::module::SessionEntry,
        state: &State,
        handle: CK_OBJECT_HANDLE,
        permit: &mut crate::registry::Reservation<Self>,
    ) -> Result<()> {
        Self::publish_into(prepared, inner, entry, handle, permit, &state.managed)
    }

    pub(crate) fn publish_into(
        prepared: &mut Arc<Self>,
        inner: &Inner,
        entry: &crate::module::SessionEntry,
        handle: CK_OBJECT_HANDLE,
        permit: &mut crate::registry::Reservation<Self>,
        registry: &crate::registry::Registry<Self>,
    ) -> Result<()> {
        if handle == CK_INVALID_HANDLE {
            return Err(Error::Rejected(crate::RejectionReason::ObjectReferences(
                crate::ObjectReferencesRejection::InvalidReturnedNativeHandle,
            )));
        }
        let identity = Arc::get_mut(prepared).ok_or(Error::Rejected(
            crate::RejectionReason::ObjectReferences(
                crate::ObjectReferencesRejection::NativeIdentityPreparationAlreadyShared,
            ),
        ))?;
        if identity.handle != CK_INVALID_HANDLE
            || identity.slot != entry.slot
            || identity.generation != entry.generation
            || !matches!(&identity.initial_creator, ObjectCreator::Known(creator)
                if std::ptr::eq(creator.as_ptr(), entry))
        {
            return Err(Error::Rejected(crate::RejectionReason::ObjectReferences(
                crate::ObjectReferencesRejection::NativeIdentityPreparationMismatch,
            )));
        }
        let resource = ResourceIdentity {
            handle,
            ..identity.resource()
        };
        let activity = mutations::object_activity_at(
            inner,
            resource,
            crate::Observation::NotRequested,
            permit,
        )?;
        identity.handle = handle;
        identity.activity.set(activity).map_err(|_| {
            Error::Rejected(crate::RejectionReason::ObjectReferences(
                crate::ObjectReferencesRejection::NativeIdentityActivityAlreadyBound,
            ))
        })?;
        permit.insert(registry, prepared)
    }

    /// Reuse a published lifetime for a descriptive view, or register a newly
    /// discovered object. The caller validates the complete observation context
    /// before invoking this transition; no second quota is taken for a view.
    pub(crate) fn observed_object(
        session: &Session,
        state: &State,
        handle: CK_OBJECT_HANDLE,
        access: ObjectAccess,
        creator: ObjectCreator,
        activity: Arc<crate::registry::Activity>,
        existing: Option<&Arc<Self>>,
        permit: &mut crate::registry::Reservation<Self>,
    ) -> Result<Arc<Self>> {
        if let Some(existing) = existing {
            if existing.handle != handle
                || existing.session != session.uid
                || !Arc::ptr_eq(existing.activity()?, &activity)
            {
                return Err(Error::Rejected(crate::RejectionReason::ObjectReferences(
                    crate::ObjectReferencesRejection::ObjectObservationLifetimeChanged,
                )));
            }
            let _ = existing.observed.set(ObservedLifetime { access, creator });
            return Ok(existing.clone());
        }
        let identity = Arc::new(Self {
            _reference_lifetime: permit.reference_lifetime_for(&creator)?,
            _credit: None,
            slot: session.entry.slot,
            generation: session.snapshot.generation,
            session: session.uid,
            handle,
            revoked: AtomicBool::new(false),
            initial_access: access,
            initial_creator: creator,
            activity: OnceLock::from(activity),
            observed: OnceLock::new(),
        });
        permit.insert(&state.objects, &identity)?;
        Ok(identity)
    }

    pub(crate) fn resource(&self) -> ResourceIdentity {
        ResourceIdentity {
            slot: self.slot,
            generation: self.generation,
            session: self.session,
            handle: self.handle,
        }
    }

    pub(crate) fn access(&self) -> ObjectAccess {
        self.observed
            .get()
            .map_or(self.initial_access, |value| value.access)
    }

    pub(crate) fn creator(&self) -> &ObjectCreator {
        self.observed
            .get()
            .map_or(&self.initial_creator, |value| &value.creator)
    }

    pub(crate) fn activity(&self) -> Result<&Arc<crate::registry::Activity>> {
        self.activity
            .get()
            .ok_or(Error::Rejected(crate::RejectionReason::ObjectReferences(
                crate::ObjectReferencesRejection::NativeIdentityNotPublished,
            )))
    }
}

/// A native object whose class and other attributes need not be readable.
/// Dropping this reference releases local ownership; it does not destroy the
/// native object. Destruction and observation are explicit session operations.
/// Authentication and attributes are decided by the module at each invocation.
/// Local identity prevents mixing Fe11 owners; it cannot detect an invisible
/// external reset or guarantee that a numeric handle was never reused.
#[derive(Clone)]
pub struct NativeObjectRef {
    pub(crate) inner: Arc<Inner>,
    pub(crate) identity: Arc<NativeIdentity>,
    pub(crate) output_slot: Option<usize>,
}

impl NativeObjectRef {
    /// Native output slot of the creation that produced this reference.
    /// A borrowed view of an already described object has no creation slot.
    pub fn output_slot(&self) -> Option<usize> {
        self.output_slot
    }

    /// Visibility actually observed, or NotRequested before observation.
    pub fn visibility_observation(&self) -> crate::Observation<bool> {
        self.identity.access().observation()
    }

    /// Local creator knowledge, without querying or inferring CKA_TOKEN.
    pub fn creator_provenance(&self) -> ObjectCreatorProvenance {
        self.identity.creator().provenance()
    }
}

impl Session {
    /// Observe a typed administrative view without consuming the native owner.
    /// `class` is the requested view; a different observed class is a conversion
    /// failure, not failure of the earlier native creation. No object is destroyed.
    pub fn observe_native_object(
        &self,
        object: &NativeObjectRef,
        class: ManagedClass,
        admission: crate::ObjectAdmission,
        content: crate::ContentObservation,
    ) -> Result<ManagedObjectRef> {
        super::discovery::observe_native(self, object, class, admission, content)
    }
}
impl crate::AdvancedSession {
    /// Synchronous observation using the same borrowed native owner.
    pub fn observe_native_object(
        &self,
        object: &NativeObjectRef,
        class: ManagedClass,
        admission: crate::ObjectAdmission,
        content: crate::ContentObservation,
    ) -> Result<ManagedObjectRef> {
        self.session
            .observe_native_object(object, class, admission, content)
    }
}
