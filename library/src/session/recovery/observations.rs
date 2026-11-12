// SPDX-License-Identifier: Apache-2.0
//! Nonexclusive observations retained by the session while their caller waits.
//!
//! Only a session possession holder may inspect an owner's operands. Terminal
//! native-search detachment reads only its pending state under the owner mutex; it
//! neither accesses handles nor authorizes native work. A waiter retains the
//! separate coordination cell, never an owner Arc or a second object permit.
//! Linked, prepaid nodes avoid growing a shared vector while holding possession.
use crate::{
    attribute_values::read::owner::FlatOwner,
    symmetric::memory::{Budget, Credit},
    Error, Result,
};
use std::sync::{
    atomic::{AtomicBool, Ordering},
    Arc, Mutex,
};
mod waiting;
pub(crate) use waiting::{context, Waiting};

pub(crate) enum Owner {
    Flat(FlatOwner),
    Inventory(Box<crate::managed::InventoryOwner>),
    NativeSearch(Box<crate::managed::NativeSearchOwner>),
    NativeSearchStream(Box<crate::managed::NativeSearchStreamOwner>),
    PublicFingerprint(Box<crate::managed::PublicFingerprintOwner>),
    Discovery(Box<crate::managed::DiscoveryOwner>),
    Destruction(Box<crate::managed::DestructionOwner>),
    SetAttributes(Box<crate::managed::SetAttributesOwner>),
    Label(Box<crate::managed::LabelOwner>),
    Copy(Box<crate::managed::CopyOwner>),
    Creation(Box<crate::managed::CreationOwner>),
    NativeOutputs(Box<crate::managed::OutputsOwner>),
    RsaObjects(Box<crate::objects::resident::Owner>),
    KeyReadmission(Box<crate::managed::key_readmission::Owner>),
    Derivation(Box<crate::crypto::derivation::resident::DerivationOwner>),
    PqcExport(Box<crate::crypto::PqcExportOwner>),
    Policy(Box<crate::mechanism_controls::resident::PolicyOwner>),

    Reference(Box<crate::reference_controls::resident::ReferenceOwner>),
    Legacy(crate::attributes::owned::resident::LegacyOwner),
    Content(crate::content_controls::owned::resident::ContentOwner),
    // A compound protocol owns its child states in a separately credited
    // allocation; its size does not inflate every simple observation slot.
    Fingerprint(Box<crate::content_controls::fingerprint_observation::resident::FingerprintOwner>),
}
impl Owner {
    fn pending(&self) -> bool {
        match self {
            Self::Flat(owner) => owner.pending(),
            Self::Inventory(owner) => owner.pending(),
            Self::NativeSearch(owner) => owner.pending(),
            Self::NativeSearchStream(owner) => owner.pending(),
            Self::PublicFingerprint(owner) => owner.pending(),
            Self::Discovery(owner) => owner.pending(),
            Self::Destruction(owner) => owner.pending(),
            Self::SetAttributes(owner) => owner.pending(),
            Self::Label(owner) => owner.pending(),
            Self::Copy(owner) => owner.pending(),
            Self::Creation(owner) => owner.pending(),
            Self::NativeOutputs(owner) => owner.pending(),
            Self::RsaObjects(owner) => owner.pending(),
            Self::KeyReadmission(owner) => owner.pending(),
            Self::Derivation(owner) => owner.pending(),
            Self::PqcExport(owner) => owner.pending(),
            Self::Policy(owner) => owner.pending(),

            Self::Reference(owner) => owner.pending(),
            Self::Legacy(owner) => owner.pending(),
            Self::Content(owner) => owner.pending(),
            Self::Fingerprint(owner) => owner.pending(),
        }
    }
    pub(crate) fn flat_mut(&mut self) -> Result<&mut FlatOwner> {
        match self {
            Self::Flat(owner) => Ok(owner),
            _ => Err(Error::Rejected(crate::RejectionReason::SessionLifecycle(
                crate::SessionLifecycleRejection::AttributeOwnerKind,
            ))),
        }
    }
    pub(crate) fn into_flat(self) -> Result<FlatOwner> {
        match self {
            Self::Flat(owner) => Ok(owner),
            _ => Err(Error::Rejected(crate::RejectionReason::SessionLifecycle(
                crate::SessionLifecycleRejection::AttributeOwnerKind,
            ))),
        }
    }
    pub(crate) fn content_mut(
        &mut self,
    ) -> Result<&mut crate::content_controls::owned::resident::ContentOwner> {
        match self {
            Self::Content(owner) => Ok(owner),
            _ => Err(Error::Rejected(crate::RejectionReason::SessionLifecycle(
                crate::SessionLifecycleRejection::AttributeOwnerKind,
            ))),
        }
    }
    pub(crate) fn into_content(
        self,
    ) -> Result<crate::content_controls::owned::resident::ContentOwner> {
        match self {
            Self::Content(owner) => Ok(owner),
            _ => Err(Error::Rejected(crate::RejectionReason::SessionLifecycle(
                crate::SessionLifecycleRejection::AttributeOwnerKind,
            ))),
        }
    }
    pub(crate) fn legacy_mut(
        &mut self,
    ) -> Result<&mut crate::attributes::owned::resident::LegacyOwner> {
        match self {
            Self::Legacy(owner) => Ok(owner),
            _ => Err(Error::Rejected(crate::RejectionReason::SessionLifecycle(
                crate::SessionLifecycleRejection::AttributeOwnerKind,
            ))),
        }
    }
    pub(crate) fn into_legacy(self) -> Result<crate::attributes::owned::resident::LegacyOwner> {
        match self {
            Self::Legacy(owner) => Ok(owner),
            _ => Err(Error::Rejected(crate::RejectionReason::SessionLifecycle(
                crate::SessionLifecycleRejection::AttributeOwnerKind,
            ))),
        }
    }
}

pub(crate) struct Coordination {
    live: AtomicBool,
    withdrawn: AtomicBool,
    budget: Arc<Budget>,
    _credit: Credit,
}
impl Coordination {
    pub(crate) fn check(&self) -> Result<()> {
        if !self.live.load(Ordering::Acquire) || self.withdrawn.load(Ordering::Acquire) {
            return Err(Error::Rejected(crate::RejectionReason::SessionLifecycle(
                crate::SessionLifecycleRejection::AttributeObservationRetired,
            )));
        }
        Ok(())
    }
    pub(crate) fn withdraw(&self) {
        self.withdrawn.store(true, Ordering::Release);
        self.budget.notify_progress();
    }
    fn retire(&self) {
        self.live.store(false, Ordering::Release);
        self.budget.notify_progress();
    }
}

pub(crate) struct Slot {
    pub(crate) owner: Mutex<Option<Owner>>,
    coordination: Arc<Coordination>,
    _credit: Credit,
}
impl Drop for Slot {
    fn drop(&mut self) {
        if let Some(owner) = self
            .owner
            .get_mut()
            .unwrap_or_else(|e| e.into_inner())
            .take()
        {
            // Rust unwind is not proof of native completion. Successful close
            // extracts this owner first; otherwise its permissions stay pinned.
            if owner.pending() {
                std::mem::forget(owner);
            }
        }
    }
}
struct Node {
    slot: Arc<Slot>,
    next: Option<Box<Node>>,
    _credit: Credit,
}
#[derive(Default)]
pub(crate) struct ClosedObservations(Option<Box<Node>>);
impl Drop for ClosedObservations {
    fn drop(&mut self) {
        while let Some(mut node) = self.0.take() {
            self.0 = node.next.take();
            node.slot.coordination.retire();
            let owner = node
                .slot
                .owner
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .take();
            // Only take_closed creates a nonempty ClosedObservations. Native
            // close is its proof, including an owner interrupted in dispatch.
            drop(owner);
        }
    }
}

#[derive(Default)]
pub(crate) struct Registry {
    head: Mutex<Option<Box<Node>>>,
    cleanup: AtomicBool,
    // Only session possession may publish/retire this identity. It names the
    // stable call allocation, never a native handle or an authorization token.
    native_search: std::sync::atomic::AtomicUsize,
}
impl Registry {
    /// Session possession excludes publication of a new native owner. Merely
    /// keeping observation metadata alive does not retain a native call.
    pub(crate) fn is_empty_for_close(&self) -> Result<bool> {
        if self.native_search.load(Ordering::Acquire) != 0 {
            return Ok(false);
        }
        let head = self.head.lock().map_err(|_| Error::Poisoned)?;
        let mut current = head.as_deref();
        while let Some(node) = current {
            if node.slot.owner.lock().map_err(|_| Error::Poisoned)?.is_some() {
                return Ok(false);
            }
            current = node.next.as_deref();
        }
        Ok(true)
    }

    pub(crate) fn search_initialized(&self, owner: usize) -> Result<()> {
        self.native_search
            .compare_exchange(0, owner, Ordering::AcqRel, Ordering::Acquire)
            .map(|_| ())
            .map_err(|_| {
                Error::Rejected(crate::RejectionReason::SessionLifecycle(
                    crate::SessionLifecycleRejection::ModuleAcceptedACompetingObjectSearch,
                ))
            })
    }

    pub(crate) fn search_terminated(&self, owner: usize) -> Result<()> {
        self.native_search
            .compare_exchange(owner, 0, Ordering::AcqRel, Ordering::Acquire)
            .map(|_| ())
            .map_err(|_| {
                Error::Rejected(crate::RejectionReason::SessionLifecycle(
                    crate::SessionLifecycleRejection::NativeSearchOwnershipChanged,
                ))
            })
    }
}
pub(crate) struct Prepared(Box<Node>);
impl Prepared {
    pub(crate) fn allocation_bytes() -> usize {
        // Count both Arc headers and the complete slot, node and independent
        // waiter metadata. Slot credit survives consumption of its owner.
        std::mem::size_of::<Node>()
            + std::mem::size_of::<Slot>()
            + std::mem::size_of::<Coordination>()
            + 4 * std::mem::size_of::<usize>()
            + Budget::observation_bytes()
    }
    pub(crate) fn allocate(budget: &Arc<Budget>, credit: &mut Credit) -> Result<Self> {
        if !budget.same_account(credit.budget()) {
            return Err(Error::Rejected(crate::RejectionReason::SessionLifecycle(
                crate::SessionLifecycleRejection::ForeignObservationCredit,
            )));
        }
        let budget = credit.observation_budget()?;
        let coordination_bytes =
            std::mem::size_of::<Coordination>() + 2 * std::mem::size_of::<usize>();
        let slot_bytes = std::mem::size_of::<Slot>() + 2 * std::mem::size_of::<usize>();
        let coordination = Arc::new(Coordination {
            live: AtomicBool::new(true),
            withdrawn: AtomicBool::new(false),
            budget,
            _credit: credit.split(coordination_bytes)?,
        });
        Ok(Self(Box::new(Node {
            slot: Arc::new(Slot {
                owner: Mutex::new(None),
                coordination,
                _credit: credit.split(slot_bytes)?,
            }),
            next: None,
            _credit: credit.split(std::mem::size_of::<Node>())?,
        })))
    }
    pub(crate) fn bind(self, owner: FlatOwner) -> Self {
        *self.0.slot.owner.lock().unwrap_or_else(|e| e.into_inner()) = Some(Owner::Flat(owner));
        self
    }
    pub(crate) fn bind_legacy(
        self,
        owner: crate::attributes::owned::resident::LegacyOwner,
    ) -> Self {
        *self.0.slot.owner.lock().unwrap_or_else(|e| e.into_inner()) = Some(Owner::Legacy(owner));
        self
    }
}
impl Prepared {
    pub(crate) fn bind_content(
        self,
        owner: crate::content_controls::owned::resident::ContentOwner,
    ) -> Self {
        *self.0.slot.owner.lock().unwrap_or_else(|e| e.into_inner()) = Some(Owner::Content(owner));
        self
    }
}
impl Owner {
    pub(crate) fn fingerprint_mut(
        &mut self,
    ) -> Result<&mut crate::content_controls::fingerprint_observation::resident::FingerprintOwner>
    {
        match self {
            Self::Fingerprint(owner) => Ok(owner),
            _ => Err(Error::Rejected(crate::RejectionReason::SessionLifecycle(
                crate::SessionLifecycleRejection::AttributeOwnerKind,
            ))),
        }
    }
    pub(crate) fn into_fingerprint(
        self,
    ) -> Result<crate::content_controls::fingerprint_observation::resident::FingerprintOwner> {
        match self {
            Self::Fingerprint(owner) => Ok(*owner),
            _ => Err(Error::Rejected(crate::RejectionReason::SessionLifecycle(
                crate::SessionLifecycleRejection::AttributeOwnerKind,
            ))),
        }
    }
}
impl Prepared {
    pub(crate) fn bind_fingerprint(
        self,
        owner: crate::content_controls::fingerprint_observation::resident::FingerprintOwner,
    ) -> Self {
        *self.0.slot.owner.lock().unwrap_or_else(|e| e.into_inner()) =
            Some(Owner::Fingerprint(Box::new(owner)));
        self
    }
}
impl Registry {
    pub(crate) fn publish(&self, mut prepared: Prepared) -> Result<Arc<Coordination>> {
        let mut head = self.head.lock().map_err(|_| Error::Poisoned)?;
        let coordination = prepared.0.slot.coordination.clone();
        prepared.0.next = head.take();
        *head = Some(prepared.0);
        Ok(coordination)
    }
    pub(crate) fn get(&self, coordination: &Arc<Coordination>) -> Result<Arc<Slot>> {
        coordination.check()?;
        let head = self.head.lock().map_err(|_| Error::Poisoned)?;
        let mut cursor = head.as_deref();
        while let Some(node) = cursor {
            if Arc::ptr_eq(&node.slot.coordination, coordination) {
                return Ok(node.slot.clone());
            }
            cursor = node.next.as_deref();
        }
        Err(Error::Rejected(crate::RejectionReason::SessionLifecycle(
            crate::SessionLifecycleRejection::AttributeObservationAbsent,
        )))
    }
    pub(crate) fn mark_cleanup(&self) {
        self.cleanup.store(true, Ordering::Release);
    }
    pub(crate) fn cleanup_hint(&self) -> bool {
        self.cleanup.load(Ordering::Acquire)
    }
    /// The caller owns session possession. Extraction releases the leaf lock
    /// before destroying a payload, its permits, or its budget credits.
    pub(crate) fn maintain(&self) -> Result<()> {
        if !self.cleanup.swap(false, Ordering::AcqRel) {
            return Ok(());
        }
        loop {
            let retired = {
                let mut head = self.head.lock().map_err(|_| Error::Poisoned)?;
                let mut cursor = &mut *head;
                loop {
                    let Some(node) = cursor.as_ref() else {
                        break None;
                    };
                    let eligible = node.slot.coordination.withdrawn.load(Ordering::Acquire)
                        && node
                            .slot
                            .owner
                            .lock()
                            .unwrap_or_else(|e| e.into_inner())
                            .as_ref()
                            .map_or(true, |owner| !owner.pending());
                    if eligible {
                        let mut node = cursor.take().expect("observed node");
                        *cursor = node.next.take();
                        break Some(node);
                    }
                    cursor = &mut cursor.as_mut().expect("observed node").next;
                }
            };
            let Some(node) = retired else { break };
            node.slot.coordination.retire();
            drop(node);
        }
        Ok(())
    }
    pub(super) fn take_closed(&self) -> ClosedObservations {
        ClosedObservations(self.head.lock().unwrap_or_else(|e| e.into_inner()).take())
    }
}
impl Drop for Registry {
    fn drop(&mut self) {
        // Iterative destruction also handles a long chain without stack growth.
        // Slot::drop retains uncertain native owners unless close was proved.
        let mut head = self
            .head
            .get_mut()
            .unwrap_or_else(|e| e.into_inner())
            .take();
        while let Some(mut node) = head.take() {
            head = node.next.take();
            node.slot.coordination.retire();
        }
    }
}

impl Owner {
    pub(crate) fn inventory_mut(&mut self) -> Result<&mut crate::managed::InventoryOwner> {
        match self {
            Self::Inventory(owner) => Ok(owner),
            _ => Err(Error::Rejected(crate::RejectionReason::SessionLifecycle(
                crate::SessionLifecycleRejection::InventoryOwnerKind,
            ))),
        }
    }
    pub(crate) fn into_inventory(self) -> Result<crate::managed::InventoryOwner> {
        match self {
            Self::Inventory(owner) => Ok(*owner),
            _ => Err(Error::Rejected(crate::RejectionReason::SessionLifecycle(
                crate::SessionLifecycleRejection::InventoryOwnerKind,
            ))),
        }
    }
    fn search_claimed(&self) -> bool {
        match self {
            Self::Inventory(owner) => owner.search_claimed(),
            Self::NativeSearch(owner) => owner.search_claimed(),
            Self::NativeSearchStream(owner) => owner.search_claimed(),
            Self::PublicFingerprint(owner) => owner.search_claimed(),
            Self::Discovery(owner) => owner.search_claimed(),
            Self::Destruction(owner) => owner.search_claimed(),
            Self::SetAttributes(owner) => owner.search_claimed(),
            Self::Label(owner) => owner.search_claimed(),
            Self::Copy(owner) => owner.search_claimed(),
            Self::Creation(owner) => owner.search_claimed(),
            Self::NativeOutputs(owner) => owner.search_claimed(),
            Self::RsaObjects(owner) => owner.search_claimed(),
            Self::KeyReadmission(owner) => owner.search_claimed(),
            Self::Derivation(owner) => owner.search_claimed(),
            Self::Reference(owner) => owner.search_claimed(),
            _ => false,
        }
    }
}
impl Prepared {
    pub(crate) fn bind_inventory(self, owner: crate::managed::InventoryOwner) -> Self {
        *self.0.slot.owner.lock().unwrap_or_else(|e| e.into_inner()) =
            Some(Owner::Inventory(Box::new(owner)));
        self
    }
}
impl Registry {
    /// Caller owns session possession. A second Find cannot replace the native
    /// search retained by a suspended inventory. This is a logical operation
    /// conflict, not a byte-credit wait or a global ban on metadata observations.
    pub(crate) fn check_search_available(&self) -> Result<()> {
        self.check_search_available_except(None)
    }
    /// The caller holds session possession and no observation-owner mutex.
    /// A compound mutation can move from one completed Find to the next without
    /// treating its own dormant child as a competing native operation.
    pub(crate) fn check_search_available_except(
        &self,
        own: Option<&Arc<Coordination>>,
    ) -> Result<()> {
        let head = self.head.lock().map_err(|_| Error::Poisoned)?;
        let mut cursor = head.as_deref();
        while let Some(node) = cursor {
            if own.is_some_and(|own| Arc::ptr_eq(own, &node.slot.coordination)) {
                cursor = node.next.as_deref();
                continue;
            }
            let owner = node.slot.owner.lock().map_err(|_| Error::Poisoned)?;
            if owner.as_ref().is_some_and(Owner::search_claimed) {
                return Err(Error::Busy(crate::BusyReason::SessionLifecycle(
                    crate::SessionLifecycleBusy::ObjectSearchActive,
                )));
            }
            cursor = node.next.as_deref();
        }
        Ok(())
    }
}

impl Owner {
    pub(crate) fn reference_mut(
        &mut self,
    ) -> Result<&mut crate::reference_controls::resident::ReferenceOwner> {
        match self {
            Self::Reference(owner) => Ok(owner),
            _ => Err(Error::Rejected(crate::RejectionReason::SessionLifecycle(
                crate::SessionLifecycleRejection::ReferenceOwnerKind,
            ))),
        }
    }
    pub(crate) fn into_reference(
        self,
    ) -> Result<crate::reference_controls::resident::ReferenceOwner> {
        match self {
            Self::Reference(owner) => Ok(*owner),
            _ => Err(Error::Rejected(crate::RejectionReason::SessionLifecycle(
                crate::SessionLifecycleRejection::ReferenceOwnerKind,
            ))),
        }
    }
}
impl Prepared {
    pub(crate) fn bind_reference(
        self,
        owner: crate::reference_controls::resident::ReferenceOwner,
    ) -> Self {
        *self.0.slot.owner.lock().unwrap_or_else(|e| e.into_inner()) =
            Some(Owner::Reference(Box::new(owner)));
        self
    }
}

impl Owner {
    pub(crate) fn public_fingerprint_mut(
        &mut self,
    ) -> Result<&mut crate::managed::PublicFingerprintOwner> {
        match self {
            Self::PublicFingerprint(owner) => Ok(owner),
            _ => Err(Error::Rejected(crate::RejectionReason::SessionLifecycle(
                crate::SessionLifecycleRejection::PublicFingerprintOwnerKind,
            ))),
        }
    }
    pub(crate) fn into_public_fingerprint(self) -> Result<crate::managed::PublicFingerprintOwner> {
        match self {
            Self::PublicFingerprint(owner) => Ok(*owner),
            _ => Err(Error::Rejected(crate::RejectionReason::SessionLifecycle(
                crate::SessionLifecycleRejection::PublicFingerprintOwnerKind,
            ))),
        }
    }
}
impl Prepared {
    pub(crate) fn bind_public_fingerprint(
        self,
        owner: crate::managed::PublicFingerprintOwner,
    ) -> Self {
        *self.0.slot.owner.lock().unwrap_or_else(|e| e.into_inner()) =
            Some(Owner::PublicFingerprint(Box::new(owner)));
        self
    }
}

impl Owner {
    pub(crate) fn discovery_mut(&mut self) -> Result<&mut crate::managed::DiscoveryOwner> {
        match self {
            Self::Discovery(owner) => Ok(owner),
            _ => Err(Error::Rejected(crate::RejectionReason::SessionLifecycle(
                crate::SessionLifecycleRejection::ManagedDiscoveryOwnerKind,
            ))),
        }
    }
    pub(crate) fn into_discovery(self) -> Result<crate::managed::DiscoveryOwner> {
        match self {
            Self::Discovery(owner) => Ok(*owner),
            _ => Err(Error::Rejected(crate::RejectionReason::SessionLifecycle(
                crate::SessionLifecycleRejection::ManagedDiscoveryOwnerKind,
            ))),
        }
    }
}
impl Prepared {
    pub(crate) fn bind_discovery(self, owner: crate::managed::DiscoveryOwner) -> Self {
        *self.0.slot.owner.lock().unwrap_or_else(|e| e.into_inner()) =
            Some(Owner::Discovery(Box::new(owner)));
        self
    }
}

impl Owner {
    pub(crate) fn destruction_mut(&mut self) -> Result<&mut crate::managed::DestructionOwner> {
        match self {
            Self::Destruction(owner) => Ok(owner),
            _ => Err(Error::Rejected(crate::RejectionReason::SessionLifecycle(
                crate::SessionLifecycleRejection::ManagedDestructionOwnerKind,
            ))),
        }
    }
}
impl Prepared {
    pub(crate) fn bind_destruction(self, owner: crate::managed::DestructionOwner) -> Self {
        *self.0.slot.owner.lock().unwrap_or_else(|e| e.into_inner()) =
            Some(Owner::Destruction(Box::new(owner)));
        self
    }
}

impl Owner {
    pub(crate) fn set_attributes_mut(&mut self) -> Result<&mut crate::managed::SetAttributesOwner> {
        match self {
            Self::SetAttributes(owner) => Ok(owner),
            _ => Err(Error::Rejected(crate::RejectionReason::SessionLifecycle(
                crate::SessionLifecycleRejection::ManagedSetAttributesOwnerKind,
            ))),
        }
    }
    pub(crate) fn into_set_attributes(self) -> Result<crate::managed::SetAttributesOwner> {
        match self {
            Self::SetAttributes(owner) => Ok(*owner),
            _ => Err(Error::Rejected(crate::RejectionReason::SessionLifecycle(
                crate::SessionLifecycleRejection::ManagedSetAttributesOwnerKind,
            ))),
        }
    }
}
impl Prepared {
    pub(crate) fn bind_set_attributes(self, owner: crate::managed::SetAttributesOwner) -> Self {
        *self.0.slot.owner.lock().unwrap_or_else(|e| e.into_inner()) =
            Some(Owner::SetAttributes(Box::new(owner)));
        self
    }
}

impl Owner {
    pub(crate) fn label_mut(&mut self) -> Result<&mut crate::managed::LabelOwner> {
        match self {
            Self::Label(owner) => Ok(owner),
            _ => Err(Error::Rejected(crate::RejectionReason::SessionLifecycle(
                crate::SessionLifecycleRejection::ManagedLabelOwnerKind,
            ))),
        }
    }
    pub(crate) fn into_label(self) -> Result<crate::managed::LabelOwner> {
        match self {
            Self::Label(owner) => Ok(*owner),
            _ => Err(Error::Rejected(crate::RejectionReason::SessionLifecycle(
                crate::SessionLifecycleRejection::ManagedLabelOwnerKind,
            ))),
        }
    }
}
impl Prepared {
    pub(crate) fn bind_label(self, owner: crate::managed::LabelOwner) -> Self {
        *self.0.slot.owner.lock().unwrap_or_else(|e| e.into_inner()) =
            Some(Owner::Label(Box::new(owner)));
        self
    }
}

impl Owner {
    pub(crate) fn copy_mut(&mut self) -> Result<&mut crate::managed::CopyOwner> {
        match self {
            Self::Copy(owner) => Ok(owner),
            _ => Err(Error::Rejected(crate::RejectionReason::SessionLifecycle(
                crate::SessionLifecycleRejection::ManagedCopyOwnerKind,
            ))),
        }
    }
}
impl Prepared {
    pub(crate) fn bind_copy(self, owner: crate::managed::CopyOwner) -> Self {
        *self.0.slot.owner.lock().unwrap_or_else(|e| e.into_inner()) =
            Some(Owner::Copy(Box::new(owner)));
        self
    }
}

impl Owner {
    pub(crate) fn pqc_export_mut(&mut self) -> Result<&mut crate::crypto::PqcExportOwner> {
        match self {
            Self::PqcExport(owner) => Ok(owner),
            _ => Err(Error::Rejected(crate::RejectionReason::SessionLifecycle(
                crate::SessionLifecycleRejection::PqcExportOwnerKind,
            ))),
        }
    }
    pub(crate) fn into_pqc_export(self) -> Result<crate::crypto::PqcExportOwner> {
        match self {
            Self::PqcExport(owner) => Ok(*owner),
            _ => Err(Error::Rejected(crate::RejectionReason::SessionLifecycle(
                crate::SessionLifecycleRejection::PqcExportOwnerKind,
            ))),
        }
    }
}
impl Owner {
    pub(crate) fn policy_mut(
        &mut self,
    ) -> Result<&mut crate::mechanism_controls::resident::PolicyOwner> {
        match self {
            Self::Policy(owner) => Ok(owner),
            _ => Err(Error::Rejected(crate::RejectionReason::SessionLifecycle(
                crate::SessionLifecycleRejection::PolicyObservationOwnerKind,
            ))),
        }
    }
    pub(crate) fn into_policy(self) -> Result<crate::mechanism_controls::resident::PolicyOwner> {
        match self {
            Self::Policy(owner) => Ok(*owner),
            _ => Err(Error::Rejected(crate::RejectionReason::SessionLifecycle(
                crate::SessionLifecycleRejection::PolicyObservationOwnerKind,
            ))),
        }
    }
}
impl Prepared {
    pub(crate) fn bind_policy(
        self,
        owner: crate::mechanism_controls::resident::PolicyOwner,
    ) -> Self {
        *self.0.slot.owner.lock().unwrap_or_else(|e| e.into_inner()) =
            Some(Owner::Policy(Box::new(owner)));
        self
    }
}
impl Prepared {
    pub(crate) fn bind_pqc_export(self, owner: crate::crypto::PqcExportOwner) -> Self {
        *self.0.slot.owner.lock().unwrap_or_else(|e| e.into_inner()) =
            Some(Owner::PqcExport(Box::new(owner)));
        self
    }
}

impl Owner {
    pub(crate) fn creation_mut(&mut self) -> Result<&mut crate::managed::CreationOwner> {
        match self {
            Self::Creation(owner) => Ok(owner),
            _ => Err(Error::Rejected(crate::RejectionReason::SessionLifecycle(
                crate::SessionLifecycleRejection::CreationOwnerKind,
            ))),
        }
    }
    pub(crate) fn key_readmission_mut(
        &mut self,
    ) -> Result<&mut crate::managed::key_readmission::Owner> {
        match self {
            Self::KeyReadmission(owner) => Ok(owner),
            _ => Err(Error::Rejected(crate::RejectionReason::SessionLifecycle(
                crate::SessionLifecycleRejection::SigningSelectionOwnerKind,
            ))),
        }
    }
    pub(crate) fn into_key_readmission(self) -> Result<crate::managed::key_readmission::Owner> {
        match self {
            Self::KeyReadmission(owner) => Ok(*owner),
            _ => Err(Error::Rejected(crate::RejectionReason::SessionLifecycle(
                crate::SessionLifecycleRejection::SigningSelectionOwnerKind,
            ))),
        }
    }
}
impl Owner {}
impl Prepared {}
impl Prepared {
    pub(crate) fn bind_creation(self, owner: crate::managed::CreationOwner) -> Self {
        *self.0.slot.owner.lock().unwrap_or_else(|e| e.into_inner()) =
            Some(Owner::Creation(Box::new(owner)));
        self
    }
    pub(crate) fn bind_key_readmission(
        self,
        owner: crate::managed::key_readmission::Owner,
    ) -> Self {
        *self.0.slot.owner.lock().unwrap_or_else(|e| e.into_inner()) =
            Some(Owner::KeyReadmission(Box::new(owner)));
        self
    }
}

impl Owner {
    pub(crate) fn derivation_mut(
        &mut self,
    ) -> Result<&mut crate::crypto::derivation::resident::DerivationOwner> {
        match self {
            Self::Derivation(owner) => Ok(owner),
            _ => Err(Error::Rejected(crate::RejectionReason::SessionLifecycle(
                crate::SessionLifecycleRejection::DerivationOwnerKind,
            ))),
        }
    }
}
impl Prepared {
    pub(crate) fn bind_derivation(
        self,
        owner: crate::crypto::derivation::resident::DerivationOwner,
    ) -> Self {
        *self.0.slot.owner.lock().unwrap_or_else(|e| e.into_inner()) =
            Some(Owner::Derivation(Box::new(owner)));
        self
    }
}

impl Owner {
    pub(crate) fn outputs_mut(&mut self) -> Result<&mut crate::managed::OutputsOwner> {
        match self {
            Self::NativeOutputs(owner) => Ok(owner),
            _ => Err(Error::Rejected(crate::RejectionReason::SessionLifecycle(
                crate::SessionLifecycleRejection::NativeOutputsOwnerKind,
            ))),
        }
    }
}
impl Prepared {
    pub(crate) fn bind_outputs(self, owner: crate::managed::OutputsOwner) -> Self {
        *self.0.slot.owner.lock().unwrap_or_else(|e| e.into_inner()) =
            Some(Owner::NativeOutputs(Box::new(owner)));
        self
    }
}

impl Owner {
    pub(crate) fn rsa_objects_mut(&mut self) -> Result<&mut crate::objects::resident::Owner> {
        match self {
            Self::RsaObjects(owner) => Ok(owner),
            _ => Err(Error::Rejected(crate::RejectionReason::SessionLifecycle(
                crate::SessionLifecycleRejection::RsaObjectsOwnerKind,
            ))),
        }
    }
}
impl Prepared {
    pub(crate) fn bind_rsa_objects(self, owner: crate::objects::resident::Owner) -> Self {
        *self.0.slot.owner.lock().unwrap_or_else(|e| e.into_inner()) =
            Some(Owner::RsaObjects(Box::new(owner)));
        self
    }
}

impl Owner {
    pub(crate) fn native_search_mut(&mut self) -> Result<&mut crate::managed::NativeSearchOwner> {
        match self {
            Self::NativeSearch(owner) => Ok(owner),
            _ => Err(Error::Rejected(crate::RejectionReason::SessionLifecycle(
                crate::SessionLifecycleRejection::NativeSearchOwnerKind,
            ))),
        }
    }
}
impl Prepared {
    pub(crate) fn bind_native_search(self, owner: crate::managed::NativeSearchOwner) -> Self {
        *self.0.slot.owner.lock().unwrap_or_else(|e| e.into_inner()) =
            Some(Owner::NativeSearch(Box::new(owner)));
        self
    }
}

impl Owner {
    pub(crate) fn native_search_stream_mut(
        &mut self,
    ) -> Result<&mut crate::managed::NativeSearchStreamOwner> {
        match self {
            Self::NativeSearchStream(owner) => Ok(owner),
            _ => Err(Error::Rejected(crate::RejectionReason::SessionLifecycle(
                crate::SessionLifecycleRejection::NativeSearchStreamOwnerKind,
            ))),
        }
    }
}
impl Prepared {
    pub(crate) fn bind_native_search_stream(
        self,
        owner: crate::managed::NativeSearchStreamOwner,
    ) -> Self {
        *self.0.slot.owner.lock().unwrap_or_else(|e| e.into_inner()) =
            Some(Owner::NativeSearchStream(Box::new(owner)));
        self
    }
}
impl Registry {
    /// Consume a prepared node only after publication can no longer fail.
    /// Its caller keeps the preparation outside possession on every refusal.
    pub(crate) fn publish_retained(
        &self,
        prepared: &mut Option<Prepared>,
    ) -> Result<Arc<Coordination>> {
        let mut head = self.head.lock().map_err(|_| Error::Poisoned)?;
        let mut prepared =
            prepared
                .take()
                .ok_or(Error::Rejected(crate::RejectionReason::SessionLifecycle(
                    crate::SessionLifecycleRejection::ObservationPreparationAbsent,
                )))?;
        let coordination = prepared.0.slot.coordination.clone();
        prepared.0.next = head.take();
        *head = Some(prepared.0);
        Ok(coordination)
    }
}

/// Complete returned node, detached without running any destructor under the
/// registry locks. Its caller must drop it outside session possession.
pub(crate) struct ReturnedSearch(Box<Node>);
impl Drop for ReturnedSearch {
    fn drop(&mut self) {
        self.0.slot.coordination.retire();
    }
}
pub(crate) enum SearchRetirement {
    Returned(ReturnedSearch),
    Pending,
    Absent,
}
impl Registry {
    /// Metadata-only extraction by the sole search caller, outside
    /// session possession. The owner mutex serializes the pending check with
    /// every native transition; the head mutex serializes extraction with
    /// maintenance and proven-close transfer. No operand is read or mutated.
    pub(crate) fn retire_native_search(
        &self,
        coordination: &Arc<Coordination>,
    ) -> Result<SearchRetirement> {
        let mut head = self.head.lock().map_err(|_| Error::Poisoned)?;
        let mut cursor = &mut *head;
        loop {
            let Some(node) = cursor.as_ref() else {
                // Only maintenance or proven-close extraction removes a node.
                // An active search caller has not withdrawn it for maintenance.
                return Ok(SearchRetirement::Absent);
            };
            if Arc::ptr_eq(&node.slot.coordination, coordination) {
                {
                    let payload = node.slot.owner.lock().map_err(|_| Error::Poisoned)?;
                    match payload.as_ref() {
                        Some(Owner::NativeSearchStream(owner)) if owner.pending() => {
                            return Ok(SearchRetirement::Pending);
                        }
                        Some(Owner::NativeSearch(owner)) if owner.pending() => {
                            return Ok(SearchRetirement::Pending);
                        }
                        Some(Owner::NativeSearchStream(_))
                        | Some(Owner::NativeSearch(_))
                        | None => {}
                        _ => {
                            return Err(Error::Rejected(crate::RejectionReason::SessionLifecycle(
                                crate::SessionLifecycleRejection::SearchRetirementOwnerKind,
                            )))
                        }
                    }
                }
                let mut node = cursor.take().expect("matched stream node");
                *cursor = node.next.take();
                return Ok(SearchRetirement::Returned(ReturnedSearch(node)));
            }
            cursor = &mut cursor.as_mut().expect("observed stream node").next;
        }
    }
}
