// SPDX-License-Identifier: Apache-2.0
use crate::{
    attributes::{self, Template},
    module::{Inner, State},
    Attribute, AttributeValue, Error, Result, SecretBytes, Session,
};
use fe11_sys::*;

use std::sync::{
    atomic::{AtomicBool, Ordering},
    Arc,
};
mod access;
mod creation_result;
mod native_identity;
pub use creation_result::{
    CreatedObjectSet, CreatedObjects, CreationObservationFailure, CreationRemainder,
    NativeObjectView,
};
pub use native_identity::NativeObjectRef;
pub(crate) use native_identity::{NativeIdentity, SinglePublication};
pub(crate) mod discovery;
mod inventory;
pub(crate) mod key_readmission;
pub(crate) use discovery::DiscoveryOwner;
mod metadata;
mod public_fingerprint;
pub(crate) use public_fingerprint::PublicFingerprintOwner;
mod size;
pub(crate) use access::ObjectAccess;
pub(crate) use inventory::InventoryOwner;
mod native_search;
pub use native_search::{NativeObjectIterator, NativeObjectMatches, NativeObjectSelection};
pub(crate) use native_search::{NativeSearchOwner, NativeSearchStreamOwner};
mod destruction;
pub(crate) use destruction::{
    prepare_destruction, revoke_returned_source, DestructionOwner, PreparedRevocations,
    RevocationRetention, RevocationRetentions, RevocationSetPlan, RevocationShape,
    RevocationStorage, RevocationTargets,
};
mod mutations;
pub(crate) use mutations::{
    check_creator, cleanup_prepared, forget_creator, forget_private_origins, object_activity,
    object_creator, reserve_key, reserve_recovery_batch, reserve_session_close,
    resource_activity_bytes, selection_activity_at_epoch, Catalog, InventoryGuard,
    ManagedSelectionStorage, OwnedSelectionGuard, PreparedManagedSelection,
};
pub(crate) use mutations::{
    create_public, create_public_prepared, create_public_with_publication,
    prepare_private_creation, prepare_rsa_creation, prepare_signing_creation, CopyOwner,
    CreationOwner, LabelOwner, OutputsOwner, SetAttributesOwner,
};
pub(crate) use mutations::{
    prepare_creation_grouped, wait_creation_destinations, CloseReservation, CreationTicket,
    DestinationRecipe, DestinationRetirement, DurableReservation, PreparedCreation,
    PreparedRetention, Reservation,
};
pub use mutations::{AttributeMutationReport, CertificateSpec, CopyTarget, DataSpec};
pub(crate) use mutations::{CloseParticipant, CloseParticipants, CloseResident};

mod classes;
pub use classes::ManagedClass;

/// Metadata only: never includes object values or private key components.
#[derive(Debug)]
pub struct ObjectMetadata {
    /// Exact class, retaining unknown classes.
    pub class: ManagedClass,
    /// Observed key type; unavailable/sensitive remain distinguishable.
    pub key_type: AttributeValue,
    /// CKA_ID for keys/certificates only.
    pub id: AttributeValue,
    /// Native label bytes; no automatic logging.
    pub label: AttributeValue,
    /// Provider-assigned identity when available.
    pub unique_id: AttributeValue,
    /// Visibility policy.
    pub private: AttributeValue,
    /// Persistence policy.
    pub persistent: AttributeValue,
    /// Application tag for data, otherwise unavailable.
    pub application: AttributeValue,
    /// Type OID for data, otherwise unavailable.
    pub object_type: AttributeValue,
    /// More than one inventoried object shares its selection tuple.
    pub ambiguous: bool,
}
/// Exact native selector. The result carries observations and exposes its
/// native reference for explicit cryptographic operations decided by the module.
pub enum ManagedSelector {
    /// Search one standard class without imposing an application identity.
    /// ObjectAdmission supplies the search bounds and explicit selection rule.
    Class {
        /// Standard class to search. Other requires a separate extension contract.
        class: ManagedClass,
        /// Explicit content observation, independent of the class.
        content: crate::ContentObservation,
    },
    /// Select a key by class/ID, with an independently selected content observation.
    Key {
        /// Public, private, secret or OTP key.
        class: ManagedClass,
        /// Exact CKA_ID.
        id: Vec<u8>,
        /// Explicit observation for this lookup only; no expected value is imposed.
        content: crate::ContentObservation,
    },
    /// Select X.509 storage by ID and an explicit content observation.
    Certificate {
        /// Exact CKA_ID.
        id: Vec<u8>,
        /// Explicit observation for this lookup only; no expected value is imposed.
        content: crate::ContentObservation,
    },
    /// Search data by the exact application/type/label tuple and observe content.
    /// ObjectAdmission selects an explicit result; the tuple need not be unique.
    Data {
        /// Exact CKA_APPLICATION bytes.
        application: Vec<u8>,
        /// Exact DER type OID; empty means unspecified.
        object_type: Vec<u8>,
        /// Exact label bytes.
        label: Vec<u8>,
        /// Explicit observation for this lookup only; no expected value is imposed.
        content: crate::ContentObservation,
    },
}
/// Opaque, session- and generation-bound administrative reference.
/// No raw handle is exposed. `native_object` and `Deref` provide a native
/// reference for operations whose permissions are decided by the module.
/// Attributes and fingerprints describe completed observations, not a lock on
/// the token's current contents. Other participants can change native state.
/// Re-observation is explicit; Fe11 never replaces an object by label or ID.
pub struct ManagedObjectRef {
    pub(crate) native: NativeObjectRef,
    pub(crate) inner: Arc<Inner>,
    pub(crate) handle: CK_OBJECT_HANDLE,
    pub(crate) identity: Arc<ManagedIdentity>,
    pub(crate) mutation_report: Option<crate::ObjectMutationReport>,
    pub(crate) content_report: Option<crate::ContentReport>,
    pub(crate) destination_report: Option<crate::DestinationReport>,
    pub(crate) search_report: Option<crate::ObjectSearchReport>,
}
/// Local knowledge of the creator, independent of the object's application ID.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ObjectCreatorProvenance {
    /// CKA_TOKEN was observed as true; no creating-session lifetime is asserted.
    TokenObject,
    /// Creation returned this handle in the same session as this reference.
    /// This fact alone does not establish whether the object is persistent.
    KnownCreationSession,
    /// CKA_TOKEN was false, but the creating session has not been established.
    UnknownSessionCreator,
    /// CKA_TOKEN is not established and no matching local creation is known.
    UnknownPersistence,
}
#[derive(Clone)]
pub(crate) enum ObjectCreator {
    TokenObject,
    // The session ledger owns the creator lifetime. An identity can itself be
    // resident in that session's recovery registry, so it must not own the entry.
    Known(std::sync::Weak<crate::module::SessionEntry>),
    UnknownSessionCreator,
    UnknownPersistence,
}
impl ObjectCreator {
    pub(crate) fn provenance(&self) -> ObjectCreatorProvenance {
        match self {
            Self::TokenObject => ObjectCreatorProvenance::TokenObject,
            Self::Known(_) => ObjectCreatorProvenance::KnownCreationSession,
            Self::UnknownSessionCreator => ObjectCreatorProvenance::UnknownSessionCreator,
            Self::UnknownPersistence => ObjectCreatorProvenance::UnknownPersistence,
        }
    }
}
pub(crate) struct ManagedIdentity {
    pub(crate) native: Arc<NativeIdentity>,
    pub class: ManagedClass,
    pub key_type: Option<CK_ULONG>,
    pub access: ObjectAccess,
    pub properties: crate::ObjectObservationReport,
    pub creator: ObjectCreator,
    pub activity: Arc<crate::registry::Activity>,
}
impl std::ops::Deref for ManagedIdentity {
    type Target = NativeIdentity;
    fn deref(&self) -> &Self::Target {
        &self.native
    }
}
// A reference remains bound to its admitting session. Native object handles
// are shared by the application sessions (PKCS#11 3.2 section 3.4).
// Registries belong to one module instance; generations exclude replaced tokens.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub(crate) struct ResourceIdentity {
    pub slot: CK_SLOT_ID,
    pub generation: u64,
    pub session: u64,
    pub handle: CK_OBJECT_HANDLE,
}
/// Native handle scope, distinct from the session binding of a Rust reference.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub(crate) struct NativeObjectIdentity {
    pub slot: CK_SLOT_ID,
    pub generation: u64,
    pub handle: CK_OBJECT_HANDLE,
}
impl ResourceIdentity {
    pub(crate) fn native(self) -> NativeObjectIdentity {
        NativeObjectIdentity {
            slot: self.slot,
            generation: self.generation,
            handle: self.handle,
        }
    }
}
impl ManagedIdentity {
    pub(crate) fn id_observation(&self) -> &AttributeValue {
        self.properties.attribute_observation(Attribute::Id)
    }

    pub(crate) fn label_observation(&self) -> &AttributeValue {
        self.properties.attribute_observation(Attribute::Label)
    }

    pub(crate) fn application_observation(&self) -> &AttributeValue {
        self.properties
            .attribute_observation(Attribute::Application)
    }

    pub(crate) fn object_type_observation(&self) -> &AttributeValue {
        self.properties.attribute_observation(Attribute::ObjectType)
    }

    pub(crate) fn resource(&self) -> ResourceIdentity {
        ResourceIdentity {
            slot: self.slot,
            generation: self.generation,
            session: self.session,
            handle: self.handle,
        }
    }
}
// Describing a native object adds metadata; borrowing its native owner does
// not query the module, change the handle or create another registry entry.
impl std::ops::Deref for ManagedObjectRef {
    type Target = NativeObjectRef;
    fn deref(&self) -> &Self::Target {
        &self.native
    }
}
impl ManagedObjectRef {
    /// Borrow the same native lifetime without allocating another registry slot.
    /// The descriptive view and this reference share revocation and activity.
    pub fn native_object(&self) -> NativeObjectRef {
        self.native.clone()
    }

    /// Initial enumeration evidence, when this reference came from discovery.
    /// Creation and operations that do not enumerate return None.
    pub fn search_report(&self) -> Option<&crate::ObjectSearchReport> {
        self.search_report.as_ref()
    }

    pub(crate) fn with_search_report(mut self, report: crate::ObjectSearchReport) -> Self {
        self.search_report = Some(report);
        self
    }
    /// Destination observations for the call that created this reference only.
    /// Later rebindings do not inherit this report; getters perform no query.
    pub fn destination_report(&self) -> Option<&crate::DestinationReport> {
        self.destination_report.as_ref()
    }
    /// Content choices evaluated for this publication only; no inherited expectation.
    pub fn content_report(&self) -> Option<&crate::ContentReport> {
        self.content_report.as_ref()
    }
    /// Evidence of the individual mutation that returned this reference, if any.
    /// Earlier aliases and subsequent rebindings do not inherit this report.
    pub fn mutation_report(&self) -> Option<&crate::ObjectMutationReport> {
        self.mutation_report.as_ref()
    }

    /// Retained native observations and their read selections; no native call.
    pub fn object_observations(&self) -> &crate::ObjectObservationReport {
        &self.identity.properties
    }

    /// Observed native class; no native call.
    pub fn class(&self) -> ManagedClass {
        self.identity.class
    }
    /// Actual CKA_PRIVATE observation; an unknown value is neither public nor private.
    /// A reference with unknown visibility remains bound to its original context.
    pub fn visibility_observation(&self) -> crate::Observation<bool> {
        self.identity.access.observation()
    }
    /// Actual CKA_TOKEN observation. Missing evidence does not imply a session object.
    pub fn persistence_observation(&self) -> crate::Observation<bool> {
        self.identity
            .properties
            .observation(crate::ObjectBooleanAttribute::Token)
    }
    /// Exact admission-time CKA_UNIQUE_ID evidence, including the unavailable
    /// cause. This borrowed public value makes no native call and proves no
    /// secret-key identity. Later native observations may differ.
    pub fn unique_id_observation(&self) -> &AttributeValue {
        self.identity
            .properties
            .attribute_observation(Attribute::UniqueId)
    }
    /// Report local creator knowledge without making a native call.
    /// Unknown provenance does not identify the finding session as the creator.
    pub fn creator_provenance(&self) -> ObjectCreatorProvenance {
        self.identity.creator.provenance()
    }
}

fn id_valid(id: &[u8]) -> Result<()> {
    crate::bounds::ck_length(id.len()).map(|_| ())
}
fn label_valid(label: &str) -> Result<()> {
    crate::bounds::ck_length(label.len()).map(|_| ())
}

/// Resource choices for each native object enumeration; no implicit ceiling.
/// Results and the duplicate index use linear memory. None imposes no bound on
/// CPU, memory or provider progress; allocation success is not a physical-memory
/// guarantee on operating systems that overcommit memory.
/// Native batches, template storage and collected handles also consume the
/// caller-selected aggregate byte budget while owned by the library.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SearchPlan {
    /// Maximum complete result count. None removes the application ceiling;
    /// allocation, arithmetic and native ABI limits remain enforced.
    pub maximum_objects: Option<usize>,
    /// Nonzero native batch capacity. Zero cannot progress a complete search.
    pub batch_size: std::num::NonZeroUsize,
}

pub(crate) mod search;

impl Session {
    /// Inventory metadata without values, with explicit byte budget and clarification.
    /// Unknown classes remain visible; an over-limit inventory returns no partial result.
    /// Search capacity and result limit are selected independently of metadata bytes.
    pub fn inventory(
        &self,
        plan: crate::AttributeReadPlan,
        search_plan: SearchPlan,
    ) -> Result<Vec<ObjectMetadata>> {
        inventory::observe(self, plan, search_plan)
    }
    /// Observe a public-key management fingerprint, not an independent trust decision.
    /// Hash format: domain tag, key type, then attribute tag/length/value, u64 big-endian.
    /// RSA uses modulus/exponent; EC uses params/point; standardized PQC uses parameter/value;
    /// other families require CKA_PUBLIC_KEY_INFO. No private key value is ever read.
    pub fn management_public_fingerprint(
        &self,
        id: &[u8],
        search_plan: SearchPlan,
        read: crate::AttributeReadPlan,
        selection: crate::ObjectSearchSelection,
    ) -> Result<(SecretBytes, crate::ObjectSearchReport)> {
        public_fingerprint::observe(self, id, search_plan, read, selection)
    }
    /// Resolve exactly one managed object and bind its observed policy/identity.
    pub fn find_managed(
        &self,
        selector: ManagedSelector,
        admission: crate::ObjectAdmission,
    ) -> Result<ManagedObjectRef> {
        discovery::find(self, selector, admission)
    }
    /// Pure publication after completed observations. The caller retains the
    /// original catalogue protection and prepaid publication quota.
    fn publish_managed_observation(
        &self,
        s: &crate::session::SessionAccess<'_>,
        o: CK_OBJECT_HANDLE,
        class: ManagedClass,
        key_type: Option<CK_KEY_TYPE>,
        properties: crate::ObjectObservationReport,
        authentication: u64,
        existing: Option<&Arc<NativeIdentity>>,
        permit: &mut crate::registry::Reservation<crate::managed::NativeIdentity>,
    ) -> Result<Arc<ManagedIdentity>> {
        let entry = self.entry(s)?;
        let persistence = properties.observation(crate::ObjectBooleanAttribute::Token);
        let visibility = properties.observation(crate::ObjectBooleanAttribute::Private);
        let access = ObjectAccess::bind(&self.snapshot, visibility, authentication)?;
        let activity = match existing {
            Some(native) => {
                self.native_identity_handle(s, native)?;
                if native.handle != o {
                    return Err(Error::Rejected(crate::RejectionReason::ObjectReferences(
                        crate::ObjectReferencesRejection::ObservationNativeHandleChanged,
                    )));
                }
                native.activity()?.clone()
            }
            None => object_activity(self, o, visibility, permit)?,
        };
        let creator = object_creator(self, o, persistence, visibility)?;
        let native = match existing {
            Some(native) => native.clone(),
            None => Arc::new(NativeIdentity {
                _reference_lifetime: permit.reference_lifetime_for(&creator)?,
                _credit: None,
                slot: entry.slot,
                session: self.uid,
                generation: self.snapshot.generation,
                handle: o,
                revoked: AtomicBool::new(false),
                initial_access: access,
                initial_creator: creator.clone(),
                observed: std::sync::OnceLock::new(),
                activity: std::sync::OnceLock::from(activity.clone()),
            }),
        };

        let identity = ManagedIdentity {
            native,

            class,
            key_type,
            access,
            properties,
            creator,

            activity,
        };
        let identity = Arc::new(identity);
        self.entry(s)?;
        identity.access.check(&self.snapshot)?;
        // Register the lifetime owner before any optional caller content check.
        // A refused check drops its transient reference; the weak registry entry
        // can then expire. Concurrent revocation still sees the real lifetime.
        if existing.is_none() {
            permit.insert(&s.managed, &identity.native)?;
        } else {
            // One observation may relax an unknown lifetime only after the
            // complete native metadata pass and its original context checks.
            let _ = identity
                .native
                .observed
                .set(native_identity::ObservedLifetime {
                    access: identity.access,
                    creator: identity.creator.clone(),
                });
        }
        Ok(identity)
    }

    // Visibility is retained as descriptive evidence. An already completed
    // result does not need fresh authorization from the recorded login state.
    pub(crate) fn managed_result<T>(
        &self,
        state: &State,
        object: &ManagedObjectRef,
        result: Result<T>,
    ) -> Result<T> {
        object.identity.access.result(self, state, result)
    }

    pub(crate) fn managed_handle(
        &self,
        s: &State,
        o: &NativeObjectRef,
    ) -> Result<CK_OBJECT_HANDLE> {
        self.entry(s)?;
        self.managed_handle_for_owned_operation(s, o)
    }

    // Caller holds the registered operation and session possession. This entry
    // keeps the same reference checks while allowing its own active operation.
    pub(crate) fn managed_handle_for_owned_operation(
        &self,
        s: &State,
        o: &NativeObjectRef,
    ) -> Result<CK_OBJECT_HANDLE> {
        // Descriptive references dereference to the same native owner. A
        // missing optional observation must not prevent use of that owner.
        self.native_object_handle(s, o)
    }

    pub(crate) fn native_object_handle(
        &self,
        state: &State,
        object: &NativeObjectRef,
    ) -> Result<CK_OBJECT_HANDLE> {
        if !Arc::ptr_eq(&self.inner, &object.inner) {
            return Err(Error::Rejected(crate::RejectionReason::ObjectReferences(
                crate::ObjectReferencesRejection::ForeignNativeObject,
            )));
        }
        self.native_identity_handle(state, &object.identity)
    }

    pub(crate) fn native_identity_handle(
        &self,
        state: &State,
        identity: &NativeIdentity,
    ) -> Result<CK_OBJECT_HANDLE> {
        let entry = self.entry_common(state)?;
        if identity.handle == CK_INVALID_HANDLE
            || self.uid != identity.session
            || entry.slot != identity.slot
            || self.snapshot.generation != identity.generation
            || identity.revoked.load(Ordering::Acquire)
        {
            return Err(Error::Rejected(crate::RejectionReason::ObjectReferences(
                crate::ObjectReferencesRejection::ForeignOrStaleNativeObject,
            )));
        }
        check_creator(identity.creator())?;
        // Authentication observations can be stale while the numeric native
        // handle is still an operand the caller wishes to submit. The module
        // decides its current validity and login requirements. Do not rebind
        // it by label/ID or reuse the old observations as current authority.
        self.snapshot.check()?;
        Ok(identity.handle)
    }

    // Internal continuations bind module membership before publication and
    // validate the original identity without constructing a public module owner.
    pub(crate) fn managed_identity_handle(
        &self,
        s: &State,
        identity: &ManagedIdentity,
    ) -> Result<CK_OBJECT_HANDLE> {
        let e = self.entry_common(s)?;
        if self.uid != identity.session
            || e.slot != identity.slot
            || self.snapshot.generation != identity.generation
            || identity.revoked.load(Ordering::Acquire)
        {
            return Err(Error::Rejected(crate::RejectionReason::ObjectReferences(
                crate::ObjectReferencesRejection::ForeignOrStaleManagedObject,
            )));
        }
        check_creator(&identity.creator)?;
        identity.access.check(&self.snapshot)?;
        Ok(identity.handle)
    }
    // Publication from a completed owned attribute read. No synchronous helper
    // or native dispatch is allowed here; the caller holds session admission
    // and a durable read permit on this class/ID throughout the native search.
    pub(crate) fn observed_secret_reference(
        &self,
        s: &State,
        handle: CK_OBJECT_HANDLE,
        values: &attributes::RequiredAttributes,
        properties: crate::ObjectObservationReport,
        authentication: u64,
        existing: Option<&Arc<NativeIdentity>>,
        permit: &mut crate::registry::Reservation<crate::managed::NativeIdentity>,
    ) -> Result<ManagedObjectRef> {
        self.observed_key_reference(
            s,
            handle,
            values,
            properties,
            authentication,
            ManagedClass::SecretKey,
            existing,
            permit,
        )
    }
    pub(crate) fn observed_public_key_reference(
        &self,
        s: &State,
        handle: CK_OBJECT_HANDLE,
        values: &attributes::RequiredAttributes,
        expected_key_type: CK_KEY_TYPE,
        properties: crate::ObjectObservationReport,
        authentication: u64,
        existing: Option<&Arc<NativeIdentity>>,
        permit: &mut crate::registry::Reservation<crate::managed::NativeIdentity>,
    ) -> Result<ManagedObjectRef> {
        values.integer(CKA_KEY_TYPE, expected_key_type)?;
        self.observed_key_reference(
            s,
            handle,
            values,
            properties,
            authentication,
            ManagedClass::PublicKey,
            existing,
            permit,
        )
    }
    pub(crate) fn observed_private_key_reference(
        &self,
        s: &State,
        handle: CK_OBJECT_HANDLE,
        values: &attributes::RequiredAttributes,
        expected_key_type: CK_KEY_TYPE,
        properties: crate::ObjectObservationReport,
        authentication: u64,
        existing: Option<&Arc<NativeIdentity>>,
        permit: &mut crate::registry::Reservation<crate::managed::NativeIdentity>,
    ) -> Result<ManagedObjectRef> {
        values.integer(CKA_KEY_TYPE, expected_key_type)?;
        self.observed_key_reference(
            s,
            handle,
            values,
            properties,
            authentication,
            ManagedClass::PrivateKey,
            existing,
            permit,
        )
    }
    fn observed_key_reference(
        &self,
        s: &State,
        handle: CK_OBJECT_HANDLE,
        values: &attributes::RequiredAttributes,
        properties: crate::ObjectObservationReport,
        authentication: u64,
        class: ManagedClass,
        existing: Option<&Arc<NativeIdentity>>,
        permit: &mut crate::registry::Reservation<crate::managed::NativeIdentity>,
    ) -> Result<ManagedObjectRef> {
        let entry = self.entry_common(s)?;
        if handle == CK_INVALID_HANDLE {
            return Err(Error::Rejected(crate::RejectionReason::ObjectReferences(
                crate::ObjectReferencesRejection::InvalidAdmittedHandle,
            )));
        }
        values.integer(CKA_CLASS, class.raw())?;
        let visibility = properties.observation(crate::ObjectBooleanAttribute::Private);
        let access = ObjectAccess::bind(&self.snapshot, visibility, authentication)?;
        let persistence = properties.observation(crate::ObjectBooleanAttribute::Token);
        let key_type =
            CK_ULONG::from_ne_bytes(values.bytes(CKA_KEY_TYPE)?.try_into().map_err(|_| {
                Error::Rejected(crate::RejectionReason::ObjectReferences(
                    crate::ObjectReferencesRejection::KeyTypeWidth,
                ))
            })?);
        let activity = match existing {
            Some(native) => {
                self.native_identity_handle(s, native)?;
                native.activity()?.clone()
            }
            None => object_activity(self, handle, visibility, permit)?,
        };
        let creator = object_creator(self, handle, persistence, visibility)?;
        let native = match existing {
            Some(native) => native.clone(),
            None => Arc::new(NativeIdentity {
                _reference_lifetime: permit.reference_lifetime_for(&creator)?,
                _credit: None,
                slot: entry.slot,
                session: self.uid,
                generation: self.snapshot.generation,
                handle: handle,
                revoked: AtomicBool::new(false),
                initial_access: access,
                initial_creator: creator.clone(),
                observed: std::sync::OnceLock::new(),
                activity: std::sync::OnceLock::from(activity.clone()),
            }),
        };
        let identity = Arc::new(ManagedIdentity {
            native,

            class,
            key_type: Some(key_type),
            access,
            properties,
            creator,

            activity,
        });
        self.entry_common(s)?;
        identity.access.check(&self.snapshot)?;
        if existing.is_none() {
            permit.insert(&s.managed, &identity.native)?;
        } else {
            let _ = identity
                .native
                .observed
                .set(native_identity::ObservedLifetime {
                    access,
                    creator: identity.creator.clone(),
                });
        }
        Ok(ManagedObjectRef {
            native: NativeObjectRef {
                inner: self.inner.clone(),
                identity: identity.native.clone(),
                output_slot: None,
            },
            inner: self.inner.clone(),
            handle,
            identity,
            mutation_report: None,
            content_report: None,
            destination_report: None,
            search_report: None,
        })
    }
    /// Read only the closed set of public/policy attributes, never object values.
    /// Resource waits between native passes release session possession while
    /// retaining this object's read permission and the completed observations.
    /// Resumption checks the original context; it does not repeat a completed pass.
    pub fn managed_attributes(
        &self,
        o: &ManagedObjectRef,
        fields: &[Attribute],
        plan: crate::AttributeReadPlan,
    ) -> Result<Vec<AttributeValue>> {
        attributes::owned::resident::observe(
            self,
            attributes::owned::resident::Source::Managed(o),
            fields,
            plan,
        )
    }
    /// Observe/evaluate reference identity using exactly the caller's plan.
    /// This snapshot is not a promise about external changes after return.
    /// Search, metadata and content retain the same object read permission.
    /// Resource waits release coordination guards and preserve completed native
    /// replies; they do not repeat a search or an already completed observation.
    pub fn observe_managed_reference(
        &self,
        object: &ManagedObjectRef,
        plan: crate::ObjectReferencePlan,
        content: crate::ContentObservation,
    ) -> Result<crate::ObjectReferenceReport> {
        crate::reference_controls::resident::observe(self, object, plan, content)
    }
    /// Observe/evaluate the selected public boolean properties of this reference.
    /// Reads and reactions are independent; unrequested values remain unknown.
    pub fn observe_managed_properties(
        &self,
        object: &ManagedObjectRef,
        admission: crate::ObjectAdmission,
    ) -> Result<crate::ObjectObservationReport> {
        attributes::owned::resident::observe_controls(self, object, &admission)
    }
    /// Observe content into protected storage using the exact caller-selected budget.
    /// Readability of native values, including key values, is decided by the module.
    /// A management reference therefore provides an export path for readable
    /// CKA_VALUE of extractable non-sensitive keys; returned bytes stay protected.
    /// For Value reads, the returned allocation retains its module byte credit
    /// until the protected bytes are dropped. Waiting for that allocation does
    /// not retain session guards or repeat the native length query.
    pub fn observe_managed_content(
        &self,
        o: &ManagedObjectRef,
        plan: crate::ContentReadPlan,
    ) -> Result<crate::ProtectedContent> {
        match plan {
            crate::ContentReadPlan::Value { maximum_bytes } => {
                crate::content_controls::owned::resident::value(self, o, maximum_bytes)
            }
            crate::ContentReadPlan::PublicFingerprintV1 { read } => {
                crate::content_controls::fingerprint_observation::resident::observe(
                    self, o, read, Ok,
                )
            }
        }
    }
    /// Consume an available protected observation; unavailable content is a local error.
    pub fn read_managed_content(
        &self,
        o: &ManagedObjectRef,
        plan: crate::ContentReadPlan,
    ) -> Result<SecretBytes> {
        self.observe_managed_content(o, plan)?.into_bytes()
    }
    /// Observe the requested content; no expected value or comparison is retained.
    pub fn check_managed_content(
        &self,
        o: &ManagedObjectRef,
        check: crate::ContentObservation,
    ) -> Result<crate::ContentReport> {
        let read = match &check {
            crate::ContentObservation::Observe(read) => Some(*read),
            crate::ContentObservation::NotRequested => None,
        };
        if let Some(crate::ContentReadPlan::Value { maximum_bytes }) = read {
            return crate::content_controls::owned::resident::value_with(
                self,
                o,
                maximum_bytes,
                |observed| check.observe_with(|_| Ok(observed)),
            );
        }
        if let Some(crate::ContentReadPlan::PublicFingerprintV1 { read }) = read {
            return crate::content_controls::fingerprint_observation::resident::observe(
                self,
                o,
                read,
                |observed| check.observe_with(|_| Ok(observed)),
            );
        }

        let (s, mut object_readers) = self.managed_read_access([Some(o)], false)?;
        s.retain_prepared_reader(object_readers[0].take().expect("prepared object reader"))?;
        self.managed_handle(&s, o)?;
        let result = check.observe_local();
        o.identity.access.result(self, &s, result)
    }
}

/// Revoke every affected administrative/crypto alias while the lifecycle guard is held.
/// Failure to enumerate a registry withdraws the token, so no stale handle remains usable.
pub(crate) fn revoke_token(s: &State, slot: CK_SLOT_ID) -> Result<()> {
    revoke_context(s, slot, None)
}
pub(crate) fn revoke_generation(s: &State, slot: CK_SLOT_ID, generation: u64) -> Result<()> {
    revoke_context(s, slot, Some(generation))
}
fn revoke_context(s: &State, slot: CK_SLOT_ID, generation: Option<u64>) -> Result<()> {
    let result = (|| {
        for id in s.objects.live()? {
            if id.slot == slot && generation.map_or(true, |g| g == id.generation) {
                id.revoked.store(true, Ordering::Release);
            }
        }
        for id in s.managed.live()? {
            if id.slot == slot && generation.map_or(true, |g| g == id.generation) {
                id.revoked.store(true, Ordering::Release);
            }
        }
        Ok(())
    })();
    if result.is_err() {
        withdraw_token(s, slot);
    }
    result
}
fn withdraw_token(s: &State, slot: CK_SLOT_ID) {
    let retired = s.retire_slot(slot);
    let withdrawn = s.session_ledger.withdraw_slot(slot);
    // Keep both withdrawal attempts and preserve the caller's original error.
    // If either fails, incomplete cleanup must not leave native access usable.
    if retired.is_err() || withdrawn.is_err() {
        s.native.mark_uncertain();
    }
}

impl crate::AdvancedSession {
    /// Resolve a managed reference with the same caller-selected search and
    /// admission contract as Session. This is a synchronous metadata operation;
    /// it does not use cooperative pacing or PKCS#11 native asynchronous mode.
    pub fn find_managed(
        &self,
        selector: ManagedSelector,
        admission: crate::ObjectAdmission,
    ) -> Result<ManagedObjectRef> {
        self.session.find_managed(selector, admission)
    }
}

pub(crate) use mutations::restoration;

pub(crate) use mutations::kem_creation;
