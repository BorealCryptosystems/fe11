// SPDX-License-Identifier: Apache-2.0
use crate::{
    attributes::{self, Template},
    module::{Inner, State},
    Error, Result, Session,
};
use fe11_sys::*;
use sha2::{Digest, Sha256};
use std::sync::{atomic::Ordering, Arc};

mod pair_observation;
pub(crate) mod resident;

/// RSA public/private cryptographic classes, independent of usage policies.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ObjectClass {
    /// Public RSA key.
    PublicKey,
    /// Private RSA key.
    PrivateKey,
}
impl ObjectClass {
    pub(crate) fn raw(self) -> CK_OBJECT_CLASS {
        match self {
            Self::PublicKey => CKO_PUBLIC_KEY as _,
            Self::PrivateKey => CKO_PRIVATE_KEY as _,
        }
    }
}
/// Native RSA key-generation request with separately selected observations.
pub struct KeySpec {
    /// Native public-object visibility request, independent of key class.
    pub public_visibility: crate::ObjectVisibility,
    /// Native private-key-object visibility request, independent of key class.
    pub private_visibility: crate::ObjectVisibility,
    /// Exact private protection attributes requested from the module.
    pub private_protection: crate::CurrentKeyProtection,
    /// Explicit native public-key usage requests; None omits an attribute.
    pub public_usages: crate::KeyUsageRequest,
    /// Explicit native private-key usage requests; None omits an attribute.
    pub private_usages: crate::KeyUsageRequest,

    /// Explicit observation and control choices for the public object.
    pub public_admission: crate::ObjectAdmission,
    /// Independent observation and control choices for the private object.
    pub private_admission: crate::ObjectAdmission,
    /// Requested modulus size in bits; native support is decided by the module.
    pub bits: u32,
    /// Requested unsigned public exponent.
    pub exponent: u64,
    /// Native CKA_ID bytes; destination observations are selected independently.
    pub id: Vec<u8>,
    /// UTF-8 native label; no library-defined presentation policy.
    pub label: String,
    /// True for token objects, false for session objects.
    pub persistent: bool,
}
/// Native RSA key-generation request used by OAEP consumers; usage is caller selected.
pub struct OaepKeySpec {
    /// Native public-object visibility request, independent of key class.
    pub public_visibility: crate::ObjectVisibility,
    /// Native private-key-object visibility request, independent of key class.
    pub private_visibility: crate::ObjectVisibility,
    /// Exact private protection attributes requested from the module.
    pub private_protection: crate::CurrentKeyProtection,
    /// Explicit native public-key usage requests; None omits an attribute.
    pub public_usages: crate::KeyUsageRequest,
    /// Explicit native private-key usage requests; None omits an attribute.
    pub private_usages: crate::KeyUsageRequest,

    /// Explicit observation and control choices for the public object.
    pub public_admission: crate::ObjectAdmission,
    /// Independent observation and control choices for the private object.
    pub private_admission: crate::ObjectAdmission,
    /// Requested modulus size in bits.
    pub bits: u32,
    /// Requested unsigned public exponent.
    pub exponent: u64,
    /// Native CKA_ID bytes; destination observations are selected independently.
    pub id: Vec<u8>,
    /// UTF-8 native label; no library-defined presentation policy.
    pub label: String,
    /// True for token objects, false for session objects.
    pub persistent: bool,
}
/// Search selection and explicitly requested object observations.
/// CKA_ID selects candidates; the returned public fingerprint is an observation,
/// not a comparison with an independently supplied expected identity.
pub struct ObjectSelector {
    /// Independent selection for the opposite class inspected by the pair API.
    pub companion_selection: crate::ObjectSearchSelection,
    /// Explicit properties to observe and controls for the returned reference.
    pub admission: crate::ObjectAdmission,
    /// Public or private key.
    pub class: ObjectClass,
    /// Exact binary CKA_ID.
    pub id: Vec<u8>,
}
/// SHA-256 of canonical DER SubjectPublicKeyInfo, retained outside token storage.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PublicKeyFingerprint(pub [u8; 32]);
/// Opaque revocable resource reference. No handle or serialization is exposed.
pub struct ObjectRef {
    destination_report: Option<crate::DestinationReport>,
    pair_search: Option<[crate::ObjectSearchReport; 2]>,
    pub(crate) inner: Arc<Inner>,
    pub(crate) session: u64,
    pub(crate) handle: CK_OBJECT_HANDLE,
    pub(crate) identity: Arc<ObjectIdentity>,
}
impl ObjectRef {
    /// Borrow this object's native lifetime without requiring another observation.
    pub fn native_object(&self) -> crate::NativeObjectRef {
        crate::NativeObjectRef {
            inner: self.inner.clone(),
            identity: self.identity.native.clone(),
            output_slot: None,
        }
    }

    /// Destination evidence for the call that created this object.
    pub fn destination_report(&self) -> Option<&crate::DestinationReport> {
        self.destination_report.as_ref()
    }
    /// Initial public/private enumeration reports, in that order. None for generation.
    pub fn pair_search_reports(&self) -> Option<&[crate::ObjectSearchReport; 2]> {
        self.pair_search.as_ref()
    }
    /// Retained admission-time choices, observations and evaluations; no native call.
    pub fn object_observations(&self) -> &crate::ObjectObservationReport {
        &self.identity.properties
    }
    /// Actual CKA_PRIVATE observation, with absence or encoding failure preserved.
    pub fn visibility_observation(&self) -> crate::Observation<bool> {
        self.identity.access.observation()
    }
    /// Actual CKA_TOKEN observation, without substituting the creation request.
    pub fn persistence_observation(&self) -> crate::Observation<bool> {
        self.identity
            .properties
            .observation(crate::ObjectBooleanAttribute::Token)
    }
    /// Local creator knowledge; application identifiers are not creator evidence.
    pub fn creator_provenance(&self) -> crate::ObjectCreatorProvenance {
        self.identity.creator.provenance()
    }
}
pub(crate) struct ObjectIdentity {
    pub(crate) native: Arc<crate::managed::NativeIdentity>,
    pub class: ObjectClass,
    pub id: Vec<u8>,
    pub modulus_bits: usize,
    pub activity: Arc<crate::registry::Activity>,
    pub creator: crate::managed::ObjectCreator,
    pub access: crate::managed::ObjectAccess,
    pub properties: crate::ObjectObservationReport,
}
impl std::ops::Deref for ObjectIdentity {
    type Target = crate::managed::NativeIdentity;
    fn deref(&self) -> &Self::Target {
        &self.native
    }
}
impl ObjectIdentity {
    pub(crate) fn resource(&self) -> crate::managed::ResourceIdentity {
        crate::managed::ResourceIdentity {
            slot: self.slot,
            generation: self.generation,
            session: self.session,
            handle: self.handle,
        }
    }
}
/// Generated RSA pair with requested observation reports and no exported private material.
pub struct KeyPair {
    /// Public key reference bound to the generating session.
    pub public: ObjectRef,
    /// Private key reference bound to the generating session.
    pub private: ObjectRef,
    /// Expected identity to store independently of the token.
    pub fingerprint: PublicKeyFingerprint,
    /// DER SubjectPublicKeyInfo for independent verification.
    pub public_der: Vec<u8>,
}
impl Session {
    pub(crate) fn object(
        &self,
        s: &State,
        o: &ObjectRef,
        class: Option<ObjectClass>,
    ) -> Result<CK_OBJECT_HANDLE> {
        // This complete local gate precedes every attribute/crypto/destroy call.
        if !Arc::ptr_eq(&self.inner, &o.inner)
            || self.uid != o.session
            || o.session != o.identity.session
            || o.handle != o.identity.handle
            || o.identity.revoked.load(Ordering::Acquire)
        {
            return Err(Error::Rejected(crate::RejectionReason::ObjectObservation(
                crate::ObjectObservationRejection::ForeignOrStaleObject,
            )));
        }
        crate::managed::check_creator(&o.identity.creator)?;
        let entry = self.entry(s)?;
        if entry.slot != o.identity.slot
            || entry.generation != o.identity.generation
            || class.is_some_and(|c| c != o.identity.class)
        {
            return Err(Error::Rejected(crate::RejectionReason::ObjectObservation(
                crate::ObjectObservationRejection::ObjectContextOrClass,
            )));
        }
        o.identity.access.check(&self.snapshot)?;
        Ok(o.handle)
    }
    /// Generate RSA keys with the supplied native requests and selected controls.
    /// The module decides whether later signing operations are permitted.
    /// A post-generation error reports
    /// that objects may remain and require explicit reconciliation.
    pub fn generate_rsa_signing_key_pair(
        &self,
        spec: KeySpec,
    ) -> Result<crate::CreatedObjects<KeyPair>> {
        let mut diagnostics = None;
        self.generate_pair(spec, &mut diagnostics)
    }
    /// Generate RSA keys for OAEP callers with independent native usage requests.
    /// Admission observes only selected properties. Failures can leave native objects.
    pub fn generate_rsa_oaep_key_pair(
        &self,
        spec: OaepKeySpec,
    ) -> Result<crate::CreatedObjects<KeyPair>> {
        let mut diagnostics = None;
        self.generate_pair(
            KeySpec {
                public_visibility: spec.public_visibility,
                private_visibility: spec.private_visibility,
                private_protection: spec.private_protection,
                public_usages: spec.public_usages,
                private_usages: spec.private_usages,
                public_admission: spec.public_admission,
                private_admission: spec.private_admission,
                bits: spec.bits,
                exponent: spec.exponent,
                id: spec.id,
                label: spec.label,
                persistent: spec.persistent,
            },
            &mut diagnostics,
        )
    }
    fn generate_pair(
        &self,
        spec: KeySpec,
        diagnostics: &mut resident::GenerationDiagnostics,
    ) -> Result<crate::CreatedObjects<KeyPair>> {
        resident::generate(self, spec, diagnostics)
    }
    /// Select a public/private pair using the selector's explicit selection and
    /// observations, then return the requested reference and observed fingerprint.
    /// This method does not compare that fingerprint with an expected identity.
    pub fn find_exact(&self, selector: ObjectSelector) -> Result<ObjectRef> {
        self.find_profile(selector)
    }
    /// Find an RSA pair for an OAEP caller using the selector's explicit
    /// admission and observed SPKI fingerprint. This follows the same
    /// selection path as `find_exact`; no OAEP-only usage policy is added.
    pub fn find_oaep_exact(&self, selector: ObjectSelector) -> Result<ObjectRef> {
        self.find_profile(selector)
    }
    fn find_profile(&self, selector: ObjectSelector) -> Result<ObjectRef> {
        resident::find(self, selector)
    }
    fn publish_rsa_object_observation(
        &self,
        s: &crate::session::SessionAccess<'_>,
        handle: CK_OBJECT_HANDLE,
        class: ObjectClass,
        id: &[u8],
        modulus_bits: usize,
        properties: crate::ObjectObservationReport,
        authentication: u64,
        permits: &mut crate::registry::Reservation<crate::managed::NativeIdentity>,
        existing: Option<&Arc<crate::managed::NativeIdentity>>,
    ) -> Result<Arc<ObjectIdentity>> {
        self.entry(s)?;
        let visibility = properties.observation(crate::ObjectBooleanAttribute::Private);
        let access =
            crate::managed::ObjectAccess::bind(&self.snapshot, visibility, authentication)?;
        let persistence = properties.observation(crate::ObjectBooleanAttribute::Token);
        let activity = match existing {
            Some(identity) => identity.activity()?.clone(),
            None => crate::managed::object_activity(self, handle, visibility, permits)?,
        };
        let creator = crate::managed::object_creator(self, handle, persistence, visibility)?;
        self.entry(s)?;
        access.check(&self.snapshot)?;
        let native = crate::managed::NativeIdentity::observed_object(
            self,
            s,
            handle,
            access,
            creator.clone(),
            activity.clone(),
            existing,
            permits,
        )?;
        let identity = Arc::new(ObjectIdentity {
            native,
            class,
            id: id.to_vec(),
            access,
            properties,
            creator,
            modulus_bits,
            activity,
        });
        Ok(identity)
    }
    /// Read only explicitly allowed public/policy attributes. Values/statuses
    /// are distinct; budget and clarification are explicitly chosen for this call.
    /// Resource waits release session possession between native passes while
    /// retaining the object read permission and already completed observations.
    pub fn attributes(
        &self,
        object: &ObjectRef,
        fields: &[crate::Attribute],
        plan: crate::AttributeReadPlan,
    ) -> Result<Vec<crate::AttributeValue>> {
        attributes::owned::resident::observe(
            self,
            attributes::owned::resident::Source::Object(object),
            fields,
            plan,
        )
    }
    /// Destroy this native resource and revoke its known aliases across application sessions.
    /// ACTION_PROHIBITED preserves references; uncertainty revokes them.
    /// Matching application identifiers alone do not prove aliases.
    /// OperationCompleted means native destruction succeeded but local completion failed;
    /// its cause is retained, destruction is not undone, and aliases remain revoked.
    pub fn destroy(&self, object: &ObjectRef) -> Result<()> {
        let class = if object.identity.class == ObjectClass::PublicKey {
            crate::ManagedClass::PublicKey
        } else {
            crate::ManagedClass::PrivateKey
        };
        let epoch = self.snapshot.authentication_stamp();
        let admission_progress = crate::session::AdmissionProgress::default();
        {
            let access = self.access_progress_at_epoch(&admission_progress, epoch)?;
            self.object(&access, object, None)?;
            access.native.table.C_DestroyObject.ok_or(Error::Rejected(
                crate::RejectionReason::ObjectObservation(
                    crate::ObjectObservationRejection::CDestroyObjectUnavailable,
                ),
            ))?;
        }
        let recipe = crate::managed::DestinationRecipe::new(self, class, &[&object.identity.id])?;
        let native = object.native_object();
        let (mut diagnostic, targets, _reservation, s) = crate::managed::prepare_destruction(
            self,
            &[recipe],
            &native,
            &admission_progress,
            epoch,
            |access| self.object(access, object, None).map(|_| ()),
        )?;
        self.object(&s, object, None)?;
        let h = self.entry(&s)?.handle;
        self.destroy_resource_reserved(
            &s,
            h,
            object.identity.resource(),
            object.identity.native.activity()?,
            &_reservation,
            targets,
            diagnostic.take()?,
        )
        .map(|_| ())
    }
}
fn validate_id(id: &[u8]) -> Result<()> {
    crate::bounds::ck_length(id.len()).map(|_| ())
}

fn template<T: attributes::TemplateSink>(spec: &KeySpec, class: ObjectClass) -> T {
    let mut t = T::empty();
    t.integer(CKA_CLASS as _, class.raw());
    t.integer(CKA_KEY_TYPE as _, CKK_RSA as _);
    t.bytes(CKA_ID as _, &spec.id);
    t.bytes(CKA_LABEL as _, spec.label.as_bytes());
    t.boolean(CKA_TOKEN as _, spec.persistent);
    match class {
        ObjectClass::PublicKey => {
            t.boolean(CKA_PRIVATE, spec.public_visibility.is_private());
            spec.public_usages.apply(&mut t);
            t.integer(CKA_MODULUS_BITS as _, spec.bits as _);
            let exponent = spec.exponent.to_be_bytes();
            let first = exponent
                .iter()
                .position(|value| *value != 0)
                .unwrap_or(exponent.len() - 1);
            t.bytes(CKA_PUBLIC_EXPONENT as _, &exponent[first..]);
        }
        ObjectClass::PrivateKey => {
            t.boolean(CKA_PRIVATE, spec.private_visibility.is_private());
            t.boolean(CKA_SENSITIVE, spec.private_protection.sensitive);
            t.boolean(CKA_EXTRACTABLE, spec.private_protection.extractable);
            spec.private_usages.apply(&mut t);
        }
    }
    t
}
