// SPDX-License-Identifier: Apache-2.0
//! One lifecycle authority, with ordinary clients of the same native generation.
//!
//! Keeping `Inner` alive grants access to its resources, not authority to end
//! the application's initialization. Clients and their children retain that
//! same kernel; neither a second table nor a second admission domain is made.

use super::Module;
use crate::{Error, Result};
use std::sync::atomic::{AtomicU64, Ordering};

mod succession;
pub(super) use succession::SuccessorContext;

/// Runtime-local participation identity. Zero belongs to the original owner;
/// other values are never recycled while any child can still retain this Inner.
#[derive(Clone, Copy, PartialEq, Eq)]
pub(crate) struct ClientId(u64);

impl ClientId {
    pub(crate) const OWNER: Self = Self(0);

    pub(crate) fn value(self) -> u64 {
        self.0
    }

    pub(super) fn allocate(next: &AtomicU64) -> Result<Self> {
        let mut previous = next.load(Ordering::Acquire);
        loop {
            let allocated = previous.checked_add(1).ok_or(Error::Rejected(
                crate::RejectionReason::ModuleLifecycle(
                    crate::ModuleLifecycleRejection::RuntimeClientIdentityExhausted,
                ),
            ))?;
            // Keep the checked update compatible with the Rust 1.81 minimum.
            // A lost race retries from the observed value, never reuses an ID.
            match next.compare_exchange_weak(
                previous,
                allocated,
                Ordering::AcqRel,
                Ordering::Acquire,
            ) {
                Ok(_) => return Ok(Self(allocated)),
                Err(observed) => previous = observed,
            }
        }
    }
}

/// Authority carried by a public view, independently of its strong image lease.
/// This is immutable after publication, including in derived token contexts.
#[derive(Clone, Copy)]
pub(super) enum LifecycleAccess {
    Owner,
    Client(ClientId),
}

impl LifecycleAccess {
    pub(super) fn require_owner(self) -> Result<()> {
        match self {
            Self::Owner => Ok(()),
            Self::Client(_) => Err(Error::Rejected(crate::RejectionReason::ModuleLifecycle(
                crate::ModuleLifecycleRejection::RuntimeOwnerRequired,
            ))),
        }
    }

    pub(super) fn client_id(self) -> ClientId {
        match self {
            Self::Owner => ClientId::OWNER,
            Self::Client(client) => client,
        }
    }
}

/// Unique lifecycle owner returned by [`super::ModuleBuilder::open_shared`].
///
/// All clients use the same initialization, budgets, session ledger, dispatch
/// and notifications. They open distinct sessions; this does not make a native
/// session shareable concurrently. No client can finalize the runtime.
///
/// Use [`Self::module`] for explicit global actions, including drainage and
/// finalization. These retain their application-wide PKCS#11 scope. Dropping
/// this owner withdraws all clients without calling C_Finalize or closing their
/// sessions. Unproven native resources stay retained; dropping is not successful
/// shutdown. Close explicitly before discarding the owner to release resources.
///
/// Foreign adapters enroll through register_foreign and its unsafe ownership
/// contract. They must not bypass admission or finalize this initialization.
/// Other processes may use the token under the native concurrency contract.
pub struct RuntimeOwner {
    module: Module,
}

impl RuntimeOwner {
    /// Only a freshly opened, unpublished module can be split. Converting an
    /// arbitrary public Module would leave earlier contexts with owner access.
    pub(super) fn from_opened(module: Module) -> Result<(Self, Module)> {
        let client = module.client_view()?;
        Ok((Self { module }, client))
    }

    /// Administrative view of this generation. Its close and drain methods
    /// remain explicit global operations; no native call is made by this getter.
    /// Contexts obtained from this view retain the owner's administrative access.
    pub fn module(&self) -> &Module {
        &self.module
    }

    /// Create an ordinary view of the same live runtime, without Initialize,
    /// discovery or new budgets. Existing children keep their participation
    /// after their originating view is detached or dropped.
    pub fn client(&self) -> Result<Module> {
        let state = self.module.inner.read()?;
        let client = self.module.client_view()?;
        drop(state);
        Ok(client)
    }
}

impl Drop for RuntimeOwner {
    fn drop(&mut self) {
        // Withdrawal is atomic and wakes waiters without borrowing State. In
        // particular, a destructor on a callback thread must never wait for its
        // own native invocation. State/Native Drop already quarantine a withdrawn
        // generation; outstanding children and native loans retain their graphs.
        // A completed explicit Finalize remains recorded independently and is
        // never reissued by this destructor, even after publication failure.
        self.module.inner.availability.withdraw_owner();
    }
}

impl Module {
    pub(crate) fn require_lifecycle_owner(&self) -> Result<()> {
        self.lifecycle_access.require_owner()
    }

    fn client_view(&self) -> Result<Self> {
        let client_id = ClientId::allocate(&self.inner.next_client)?;
        Ok(Self {
            inner: self.inner.clone(),
            info: self.info.clone(),
            initial_discovery: self.initial_discovery.clone(),
            lifecycle_access: LifecycleAccess::Client(client_id),
        })
    }

    /// Detach an ordinary shared view without a native call. Its sessions and
    /// contexts remain attached until they are explicitly closed or dropped.
    ///
    /// An owning Module cannot be detached this way: it is returned intact in
    /// `Err`, so a mistaken request does not destroy its lifecycle authority.
    pub fn detach(self) -> std::result::Result<(), Self> {
        match self.lifecycle_access {
            LifecycleAccess::Client(_) => Ok(()),
            LifecycleAccess::Owner => Err(self),
        }
    }

    /// The owner may reap all deferred entries. Ordinary views may select only
    /// their own children; explicit session methods still require that Session.
    pub(super) fn cleanup_client(&self) -> Option<ClientId> {
        match self.lifecycle_access {
            LifecycleAccess::Owner => None,
            LifecycleAccess::Client(client) => Some(client),
        }
    }
}
