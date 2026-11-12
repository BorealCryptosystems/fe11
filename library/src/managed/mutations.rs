// SPDX-License-Identifier: Apache-2.0
use super::*;
mod copy;
pub(crate) use copy::CopyOwner;
mod create;
mod native_object;
pub(crate) use create::{
    create_public, create_public_prepared, create_public_with_publication,
    prepare_private_creation, prepare_rsa_creation, prepare_signing_creation, CreationOwner,
};
mod derivation;
mod generation;
pub(super) mod outputs;
pub(crate) use outputs::OutputsOwner;
mod generic;
mod label;
mod recovery;
pub(crate) use label::LabelOwner;
mod identity_parts;
mod input_identity;

use identity_parts::SharedBytes;
mod close_storage;
mod closing;
mod kea;
mod key_material;
mod native_transport;
mod origins;
mod possession;
mod reservation_preparation;
pub(crate) use close_storage::{CloseParticipant, CloseParticipants, CloseResident};
pub(crate) use closing::{reserve_recovery_batch, reserve_session_close, CloseReservation};
pub(crate) use possession::PreparedRetention;
pub(crate) use reservation_preparation::{
    prepare_grouped as prepare_creation_grouped, wait_available as wait_creation_destinations,
    DestinationRecipe, DestinationRetirement,
};
mod sp800;
mod storage;

// Borrowed operands support sizing and allocation before destination credit is
// acquired. Template and observation preparation share this exact projection.
impl DestinationRecipe<'_> {
    fn with_identity<T>(
        &self,
        label: &str,
        visit: impl FnOnce(crate::destination_controls::DestinationIdentity<'_>) -> Result<T>,
    ) -> Result<T> {
        use crate::{destination_controls::DestinationIdentity, IdentityAttribute};
        if self.class == Some(CKO_DATA) {
            let fields = [
                (IdentityAttribute::Application, self.parts[0].as_deref()),
                (IdentityAttribute::ObjectId, self.parts[1].as_deref()),
                (IdentityAttribute::Label, self.parts[2].as_deref()),
            ];
            visit(DestinationIdentity::Metadata {
                class: ManagedClass::Data,
                fields: &fields,
            })
        } else {
            let fields = [
                (IdentityAttribute::Id, self.parts[0].as_deref()),
                (IdentityAttribute::Label, Some(label.as_bytes())),
            ];
            visit(DestinationIdentity::Metadata {
                class: ManagedClass::from_raw(self.class.ok_or(Error::Rejected(
                    crate::RejectionReason::ObjectMutation(
                        crate::ObjectMutationRejection::UnobservedDestinationClass,
                    ),
                ))?),
                fields: &fields,
            })
        }
    }
    fn part(&self, index: usize) -> Result<&[u8]> {
        self.parts
            .get(index)
            .and_then(Option::as_deref)
            .ok_or(Error::Rejected(crate::RejectionReason::ObjectMutation(
                crate::ObjectMutationRejection::RequestedDestinationOperandUnavailable,
            )))
    }
    fn template<T: crate::attributes::TemplateSink>(&self) -> Result<T> {
        let mut t = T::empty();
        t.integer(
            CKA_CLASS,
            self.class
                .ok_or(Error::Rejected(crate::RejectionReason::ObjectMutation(
                    crate::ObjectMutationRejection::UnobservedDestinationClass,
                )))?,
        );
        if self.class == Some(CKO_DATA) {
            for (k, v) in [CKA_APPLICATION, CKA_OBJECT_ID, CKA_LABEL]
                .into_iter()
                .zip(&self.parts)
            {
                t.bytes(
                    k,
                    v.as_deref()
                        .ok_or(Error::Rejected(crate::RejectionReason::ObjectMutation(
                            crate::ObjectMutationRejection::RequestedDestinationOperandUnavailable,
                        )))?,
                );
            }
        } else {
            t.bytes(CKA_ID, self.part(0)?);
        }
        Ok(t)
    }
}
pub use generic::AttributeMutationReport;
pub(crate) use generic::SetAttributesOwner;
pub(crate) use origins::{
    check_creator, forget_creator, forget_private_origins, object_creator, CreationTicket,
    PreparedCreation,
};
pub use storage::{CertificateSpec, DataSpec};

/// Explicit destination in the source token. A copy never changes usage or protection.
pub enum CopyTarget {
    /// Keys and certificates take an explicit CKA_ID and label, including the source ID.
    KeyOrCertificate {
        /// Requested exact identifier, possibly unchanged.
        id: Vec<u8>,
        /// Requested UTF-8 label.
        label: String,
        /// Session object or persistent token object.
        persistent: bool,
    },
    /// Data keeps its type OID and takes an explicit application/label tuple.
    Data {
        /// Requested application tag.
        application: String,
        /// Requested label.
        label: String,
        /// Session object or persistent token object.
        persistent: bool,
    },
}
#[derive(Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub(crate) struct Destination {
    slot: CK_SLOT_ID,
    generation: u64,
    class: Option<CK_OBJECT_CLASS>,
    parts: [Option<SharedBytes>; 3],
}
impl Destination {
    /// Compare the same identity tuple used to construct a destination, without
    /// allocating a duplicate resident while mutation possession is held.
    fn matches_identity(&self, session: &Session, identity: &ManagedIdentity) -> bool {
        self.slot == session.entry.slot
            && self.generation == session.snapshot.generation
            && self.class == Some(identity.class.raw())
            && self
                .parts
                .iter()
                .map(Option::as_deref)
                .eq(identity_parts(identity))
    }

    // Cloning a catalogue key shares immutable credited bytes. It does not
    // duplicate storage, change content equality or establish native aliasing.
    fn try_clone(&self) -> Result<Self> {
        Ok(self.clone())
    }
    // Unknown components broaden only local exclusion, never a native query.
    fn overlaps(&self, other: &Self) -> bool {
        self.slot == other.slot
            && self.generation == other.generation
            && (self.class.is_none() || other.class.is_none() || self.class == other.class)
            && self
                .parts
                .iter()
                .zip(&other.parts)
                .all(|(a, b)| match (a, b) {
                    (Some(a), Some(b)) => a == b,
                    _ => true,
                })
    }
}
// Coordination knowledge is separate from each reference's actual report.
// A caller omitting PRIVATE must not erase another reference's observed value.
fn remember_visibility(
    known: &mut Option<crate::Observation<bool>>,
    observed: crate::Observation<bool>,
) {
    if matches!(observed, crate::Observation::Observed(_))
        || !matches!(known, Some(crate::Observation::Observed(_)))
    {
        *known = Some(observed);
    }
}
struct ResourceActivity {
    activity: std::sync::Weak<crate::registry::Activity>,
    // None is preparation before an observation, distinct from an unavailable read.
    visibility: Option<crate::Observation<bool>>,
    creation: Option<CreationEpoch>,
}
#[derive(Clone, Copy)]
struct CreationEpoch {
    session: u64,
    authentication: u64,
}
pub(crate) struct Catalog {
    scan_wake: Arc<crate::admission_wait::Wake>,
    // Mutations supply prepaid resource credits.
    maximum_destinations: Option<usize>,
    occupied: std::collections::HashSet<Destination>,
    owned: std::collections::HashMap<Destination, (u64, usize)>,
    scans: std::collections::HashMap<(CK_SLOT_ID, u64), usize>,
    owned_scans: Vec<InventoryRecord>,
    selected: std::collections::HashMap<Destination, usize>,
    owned_selections: Vec<std::sync::Weak<SelectionOwner>>,
    destination_activities:
        std::collections::HashMap<Destination, std::sync::Weak<crate::registry::Activity>>,
    resource_activities: std::collections::HashMap<NativeObjectIdentity, ResourceActivity>,
    origins: std::collections::HashMap<NativeObjectIdentity, origins::Origin>,
    pending_creations: std::collections::HashMap<Destination, origins::PendingCreation>,
    pending_reserved: usize,
    publication_reserved: usize,
    unknown_closing: std::collections::HashMap<(CK_SLOT_ID, u64), usize>,
    broken: bool,
}

struct InventoryOwner {
    // A retained child must keep the exclusion, without cycling through Inner.
    inner: std::sync::Weak<Inner>,
    key: (CK_SLOT_ID, u64),
    session: u64,
    // Set only during publication while the preallocated Arc is uniquely owned.
    // Dropping a preparation must not remove another live inventory exclusion.
    registered: bool,
    _credit: crate::symmetric::memory::Credit,
}
/// Immutable catalogue identity. Inspecting it never upgrades a weak owner:
/// dropping a final temporary Arc while holding Catalog would reenter its lock.
struct InventoryRecord {
    owner: std::sync::Weak<InventoryOwner>,
    key: (CK_SLOT_ID, u64),
    session: u64,
}

#[derive(Clone)]
pub(crate) struct InventoryGuard {
    owner: Arc<InventoryOwner>,
}
/// A credited shared owner with no catalogue exclusion until publication.
pub(crate) struct PreparedInventory {
    owner: Arc<InventoryOwner>,
}

pub(crate) struct SelectionGuard {
    inner: Arc<Inner>,
    keys: Vec<Destination>,
    session: u64,
}
struct SelectionOwner {
    session: u64,
    keys: Vec<Destination>,
}
pub(crate) struct OwnedSelectionGuard {
    inner: std::sync::Weak<Inner>,
    owner: Arc<SelectionOwner>,
}
impl OwnedSelectionGuard {
    pub(crate) fn belongs_to(&self, inner: &Arc<Inner>, session: u64) -> bool {
        self.inner.ptr_eq(&Arc::downgrade(inner)) && self.owner.session == session
    }
}
impl Drop for OwnedSelectionGuard {
    fn drop(&mut self) {
        if let Some(inner) = self.inner.upgrade() {
            let mut catalog = inner.reservations.lock().unwrap_or_else(|e| e.into_inner());
            catalog.end_select(&self.owner.keys);
            let owner = Arc::downgrade(&self.owner);
            catalog
                .owned_selections
                .retain(|entry| !entry.ptr_eq(&owner));
        }
    }
}
impl SelectionGuard {
    pub(crate) fn into_owned(
        mut self,
        inner: &Arc<Inner>,
        entry: &crate::module::SessionEntry,
    ) -> Result<OwnedSelectionGuard> {
        self.into_owned_retained(inner, entry)
    }

    /// On refusal, the original selection remains responsible for exclusion.
    /// The enclosing candidate releases its session access before this guard.
    pub(crate) fn into_owned_retained(
        &mut self,
        inner: &Arc<Inner>,
        entry: &crate::module::SessionEntry,
    ) -> Result<OwnedSelectionGuard> {
        if !Arc::ptr_eq(&self.inner, inner) || self.session != entry.credit.uid() {
            return Err(Error::Rejected(crate::RejectionReason::ObjectMutation(
                crate::ObjectMutationRejection::ForeignOperationSelection,
            )));
        }
        let mut catalog = self
            .inner
            .reservations
            .lock()
            .map_err(|_| Error::Poisoned)?;
        if catalog.broken {
            return Err(Error::Poisoned);
        }
        catalog.owned_selections.try_reserve(1).map_err(|_| {
            Error::Rejected(crate::RejectionReason::ObjectMutation(
                crate::ObjectMutationRejection::OperationSelectionAllocation,
            ))
        })?;
        let owner = Arc::new(SelectionOwner {
            session: self.session,
            keys: std::mem::take(&mut self.keys),
        });
        catalog.owned_selections.push(Arc::downgrade(&owner));
        Ok(OwnedSelectionGuard {
            inner: Arc::downgrade(&self.inner),
            owner,
        })
    }

    fn new_retained(session: &Session, keys: &mut Vec<Destination>) -> Result<Self> {
        session.snapshot.check()?;
        // A selection excludes competing destinations but creates no native
        // resource. Creation/unknown-reference paths prepare close participants
        // at their actual publication boundary, not on a discarded local loan.
        session
            .inner
            .reservations
            .lock()
            .map_err(|_| Error::Poisoned)?
            .begin_select(keys)?;
        Ok(Self {
            inner: session.inner.clone(),
            keys: std::mem::take(keys),
            session: session.uid,
        })
    }
}
impl Drop for SelectionGuard {
    fn drop(&mut self) {
        self.inner
            .reservations
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .end_select(&self.keys);
    }
}
pub(crate) struct ManagedSelectionStorage<'a> {
    class: ManagedClass,
    parts: identity_parts::PreparedParts<'a>,
}

pub(crate) struct PreparedManagedSelection {
    keys: Vec<Destination>,
}

impl<'a> ManagedSelectionStorage<'a> {
    pub(crate) fn requested_key_bytes(id: &[u8]) -> Result<usize> {
        identity_parts::PreparedParts::requested([Some(id), None, None])
    }

    pub(crate) fn allocate_key(class: ManagedClass, id: &'a [u8]) -> Result<Self> {
        if !matches!(
            class,
            ManagedClass::PublicKey | ManagedClass::PrivateKey | ManagedClass::SecretKey
        ) {
            return Err(Error::Rejected(crate::RejectionReason::ObjectMutation(
                crate::ObjectMutationRejection::KeySelectionClass,
            )));
        }
        Ok(Self {
            class,
            parts: identity_parts::PreparedParts::allocate([Some(id), None, None])?,
        })
    }

    fn components(selector: &'a ManagedSelector) -> Result<(ManagedClass, [Option<&'a [u8]>; 3])> {
        Ok(match selector {
            ManagedSelector::Class { class, .. } => {
                if matches!(class, ManagedClass::Other(_)) {
                    return Err(Error::Rejected(crate::RejectionReason::ObjectMutation(
                        crate::ObjectMutationRejection::UnknownClassSelectionContract,
                    )));
                }
                (*class, [None, None, None])
            }
            ManagedSelector::Key { class, id, .. } => (*class, [Some(id), None, None]),
            ManagedSelector::Certificate { id, .. } => {
                (ManagedClass::Certificate, [Some(id), None, None])
            }
            ManagedSelector::Data {
                application,
                object_type,
                label,
                ..
            } => (
                ManagedClass::Data,
                [Some(application), Some(object_type), Some(label)],
            ),
        })
    }

    pub(crate) fn requested_bytes(selector: &'a ManagedSelector) -> Result<usize> {
        identity_parts::PreparedParts::requested(Self::components(selector)?.1)
    }

    pub(crate) fn allocate(selector: &'a ManagedSelector) -> Result<Self> {
        let (class, parts) = Self::components(selector)?;
        Ok(Self {
            class,
            parts: identity_parts::PreparedParts::allocate(parts)?,
        })
    }

    pub(crate) fn allocated_bytes(&self) -> usize {
        self.parts.allocated_bytes()
    }

    /// Called before possession. All immutable components share the aggregate
    /// prepaid reservation, including any observed allocator excess.
    pub(crate) fn bind(
        self,
        session: &Session,
        prepaid: &mut crate::symmetric::memory::Credit,
    ) -> Result<PreparedManagedSelection> {
        let mut keys = Vec::new();
        keys.try_reserve_exact(1).map_err(|_| {
            Error::Rejected(crate::RejectionReason::ObjectMutation(
                crate::ObjectMutationRejection::ManagedSelectionAllocation,
            ))
        })?;
        keys.push(Destination {
            slot: session.entry.slot,
            generation: session.snapshot.generation,
            class: Some(self.class.raw()),
            parts: self.parts.bind(prepaid)?,
        });
        Ok(PreparedManagedSelection { keys })
    }
}

impl PreparedManagedSelection {
    /// RSA pair discovery selects both classes with the same immutable ID.
    /// Sharing its credited bytes changes no native-object identity or aliasing.
    /// This storage extension is performed before acquiring session possession.
    pub(crate) fn for_key_pair(mut self) -> Result<Self> {
        if self.keys.len() != 1 || self.keys[0].class != Some(CKO_PUBLIC_KEY) {
            return Err(Error::Rejected(crate::RejectionReason::ObjectMutation(
                crate::ObjectMutationRejection::PublicPairSelectionPreparation,
            )));
        }
        self.keys.try_reserve_exact(1).map_err(|_| {
            Error::Rejected(crate::RejectionReason::ObjectMutation(
                crate::ObjectMutationRejection::PairSelectionAllocation,
            ))
        })?;
        let mut private = self.keys[0].clone();
        private.class = Some(CKO_PRIVATE_KEY);
        self.keys.push(private);
        Ok(self)
    }

    /// Binding installs exclusion only; it does not reserve bytes or wait for
    /// capacity. Caller revalidates its access/epoch before this publication.
    pub(crate) fn select(mut self, session: &Session) -> Result<SelectionGuard> {
        self.select_retained(session)
    }

    /// Retain credited identity components if selection cannot be installed.
    pub(crate) fn select_retained(&mut self, session: &Session) -> Result<SelectionGuard> {
        if self.keys.iter().any(|key| {
            key.slot != session.entry.slot || key.generation != session.snapshot.generation
        }) {
            return Err(Error::Rejected(crate::RejectionReason::ObjectMutation(
                crate::ObjectMutationRejection::ForeignPreparedSelection,
            )));
        }
        SelectionGuard::new_retained(session, &mut self.keys)
    }
}
fn identity_parts(id: &ManagedIdentity) -> [Option<&[u8]>; 3] {
    fn available(value: &crate::AttributeValue) -> Option<&[u8]> {
        match value {
            crate::AttributeValue::Available(bytes) => Some(bytes),
            _ => None,
        }
    }
    if id.class == ManagedClass::Data {
        [
            available(id.application_observation()),
            available(id.object_type_observation()),
            available(id.label_observation()),
        ]
    } else {
        [available(id.id_observation()), None, None]
    }
}
pub(super) fn identity_recipe<'a>(
    session: &Session,
    id: &'a ManagedIdentity,
) -> Result<DestinationRecipe<'a>> {
    DestinationRecipe::with_parts(session, id.class, identity_parts(id))
}

pub(crate) fn reserve_key(
    session: &Session,
    class: ManagedClass,
    id: &[u8],
) -> Result<Reservation> {
    Reservation::new(session, &[DestinationRecipe::new(session, class, &[id])?])
}

/// Selection shares attribution with other live owners, but keeps the start's
/// authentication epoch and maintenance progress through any preparation wait.
pub(crate) fn selection_activity_at_epoch(
    session: &Session,
    class: ManagedClass,
    parts: &[&[u8]],
    progress: &crate::session::AdmissionProgress,
    epoch: u64,
) -> Result<Arc<crate::registry::Activity>> {
    let activity = reservation_preparation::selection_activity_in_context(
        session,
        DestinationRecipe::new(session, class, parts)?,
        progress,
        Some(epoch),
    )?;
    let wake = session
        .inner
        .reservations
        .lock()
        .map_err(|_| Error::Poisoned)?
        .scan_wake();
    activity.bind_context_wake(&wake)?;
    Ok(activity)
}

pub(crate) fn resource_activity_bytes() -> Result<usize> {
    crate::registry::Activity::allocation_bytes(
        std::mem::size_of::<NativeObjectIdentity>() + std::mem::size_of::<ResourceActivity>(),
    )
}
pub(crate) fn object_activity<T>(
    session: &Session,
    handle: CK_OBJECT_HANDLE,
    visibility: crate::Observation<bool>,
    permit: &mut crate::registry::Reservation<T>,
) -> Result<Arc<crate::registry::Activity>> {
    if handle == CK_INVALID_HANDLE {
        return Err(Error::Rejected(crate::RejectionReason::ObjectMutation(
            crate::ObjectMutationRejection::InvalidResourceActivityHandle,
        )));
    }
    let resource = ResourceIdentity {
        slot: session.entry.slot,
        generation: session.snapshot.generation,
        session: session.uid,
        handle,
    };
    object_activity_at(&session.inner, resource, visibility, permit)
}

pub(crate) fn object_activity_at<T>(
    inner: &Inner,
    resource: ResourceIdentity,
    visibility: crate::Observation<bool>,
    permit: &mut crate::registry::Reservation<T>,
) -> Result<Arc<crate::registry::Activity>> {
    inner
        .reservations
        .lock()
        .map_err(|_| Error::Poisoned)?
        .resource_activity_prepared(resource, visibility, || {
            permit.activity_credit(resource_activity_bytes()?)
        })
}
pub(crate) struct Reservation {
    close: std::sync::Mutex<CloseParticipants>,
    creation: std::sync::Mutex<Option<origins::CreationPreparation>>,
    inner: Arc<Inner>,
    keys: Vec<Destination>,
    activities: Vec<Arc<crate::registry::Activity>>,
    metadata: Option<crate::symmetric::memory::Credit>,
}
// The closing session may retain this in its ledger entry. Weak ownership is
// essential: Inner -> session ledger -> entry -> reservation must not cycle.
pub(crate) struct DurableReservation {
    inner: std::sync::Weak<Inner>,
    keys: Vec<Destination>,
    // Catalogue entries are weak. Retaining only the permits' lock state would
    // permit a new Activity for the same identity while native use survives.
    _activities: Vec<Arc<crate::registry::Activity>>,
    _metadata: Option<crate::symmetric::memory::Credit>,
}

pub(crate) fn cleanup_prepared(
    session: &Session,
    s: &State,
    h: CK_SESSION_HANDLE,
    created: CK_OBJECT_HANDLE,
    cause: Error,
    storage: &mut crate::error::CleanupStorage,
) -> Error {
    match cleanup_disposition(session, s, created, &cause) {
        CleanupDisposition::Keep => cause,
        CleanupDisposition::Uncertain => storage.mark_remaining(cause),
        CleanupDisposition::Destroy => match destroy_created(session, s, h, created) {
            Ok(()) => cause,
            Err(failure) => storage.object_failure(cause, failure),
        },
    }
}

enum CleanupDisposition {
    Keep,
    Uncertain,
    Destroy,
}

fn cleanup_disposition(
    session: &Session,
    s: &State,
    created: CK_OBJECT_HANDLE,
    cause: &Error,
) -> CleanupDisposition {
    // A compound failure never authorizes repeating its failed cleanup.
    let original = cause.without_object_marker();
    if matches!(original, Error::CleanupFailed { .. }) {
        return CleanupDisposition::Keep;
    }
    let unsafe_session = matches!(original,Error::Native {code,..} if *code==CKR_SESSION_HANDLE_INVALID as u64 || *code==CKR_SESSION_CLOSED as u64 || *code==CKR_OPERATION_ACTIVE as u64);
    if s.native.is_uncertain()
        || session.entry.poisoned.load(Ordering::Acquire)
        || session.snapshot.check().is_err()
        || unsafe_session
    {
        return CleanupDisposition::Uncertain;
    }
    // Only a distinct handle returned by successful creation/copy is eligible.
    if created == CK_INVALID_HANDLE as fe11_sys::CK_ULONG {
        s.native.mark_uncertain();
        return CleanupDisposition::Uncertain;
    }
    CleanupDisposition::Destroy
}

fn destroy_created(
    session: &Session,
    s: &State,
    h: CK_SESSION_HANDLE,
    created: CK_OBJECT_HANDLE,
) -> Result<()> {
    origins::check_creation_for_cleanup(session, created)?;
    let destroy = s.native.table.C_DestroyObject.ok_or(Error::Rejected(
        crate::RejectionReason::ObjectObservation(
            crate::ObjectObservationRejection::CDestroyObjectUnavailable,
        ),
    ))?;
    if let Err(error) = s.native.record("C_DestroyObject") {
        s.native.mark_uncertain();
        return Err(error);
    }
    // SAFETY: live protected session, handle owned only by this creation/copy.
    let rv = unsafe { destroy(h, created) };
    if rv == CKR_PENDING {
        session.entry.recovery.mark_pending_call();
    }
    session.mutation_result(s, crate::native_return::MutationCall::Destroy, rv)?;
    // After native success, a different creator may have reused the number.
    // Catalogue cleanup compares ownership atomically; it must not treat that
    // legitimate replacement as uncertainty of this completed destruction.
    // The caller retains SessionAccess and its shared token activity throughout:
    // Logout cannot change authentication between the precheck and this cleanup.
    // This does not exclude Unknown observations from native context loss or
    // last-session close; cleanup still compares the exact creation identity.
    if let Err(error) = origins::forget_created_handle(session, created) {
        s.native.mark_uncertain();
        return Err(error);
    }
    Ok(())
}

impl Session {
    /// Change only the label. Success or an uncertain native result revokes aliases.
    /// ACTION_PROHIBITED, SESSION_READ_ONLY and TOKEN_WRITE_PROTECTED preserve
    /// references and retain the native refusal; no revoked reference is restored.
    /// Source and destination observations are explicitly selected in the mutation plan.
    /// The fixed class-observation storage is reserved before dispatch using the
    /// target ABI's CK_OBJECT_CLASS width. After native success, a failed read or
    /// admission returns OperationCompleted; the label change is not undone and
    /// must not be retried. Revoked aliases stay unusable. A caller may discover
    /// and admit a fresh reference explicitly; unrelated references and the
    /// session remain usable unless a native or registry failure invalidates them.
    pub fn set_label(
        &self,
        o: &ManagedObjectRef,
        label: &str,
        admission: crate::ObjectAdmission,
        mutation: crate::ObjectMutationPlan,
        content: crate::ContentMutationPlan,
    ) -> Result<ManagedObjectRef> {
        label::set(self, o, label, admission, mutation, content)
    }
    /// Copy one object with explicit destination and before/after observations.
    /// No atomic pair-copy or unselected policy preservation is implied.
    /// Stateful private signing keys (HSS, XMSS, XMSSMT) require lifecycle care:
    /// copying their state can reuse one-time signing keys and enable forgery.
    /// This operation does not coordinate state between copies. CKA_COPYABLE
    /// permits a native copy; true does not prove safe independent signing state.
    /// PKCS#11 3.2 requires CKA_COPYABLE=false for HSS private keys, so a conforming
    /// module refuses their copy. Native refusals are preserved. Any additional
    /// observation is explicitly selected by the caller. After publication, the
    /// result retains the native object independently of a failed observation.
    /// An intrinsic publication failure keeps its cleanup diagnostic and possible
    /// object effect. Never repeat the native copy to repair an observation.
    pub fn copy_object(
        &self,
        o: &ManagedObjectRef,
        target: CopyTarget,
        admission: crate::ObjectAdmission,
        mutation: crate::ObjectMutationPlan,
        content: crate::ContentMutationPlan,
    ) -> Result<crate::CreatedObjects<ManagedObjectRef>> {
        let mut diagnostics = None;
        copy::resident::public(
            self,
            o,
            target,
            admission,
            mutation,
            content,
            &mut diagnostics,
        )
    }
}

pub(crate) use create::restoration;

pub(crate) use create::kem_creation;

mod inventory;
mod reservation;
