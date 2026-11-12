// SPDX-License-Identifier: Apache-2.0
//! Context publication wakes every independent resource admission domain.
use super::{Attempt, Wake};
use crate::{Error, ResourceAdmission, Result};
use std::sync::{Arc, OnceLock, Weak};

pub(crate) struct ContextWakes {
    // Fixed domains, not a capacity limit: sessions, owned bytes, ordinary
    // references, managed references, catalog scans, and module access. Weak
    // links retain no resource owner; invalidation wakes every wait domain.
    wakes: [Weak<Wake>; 6],
}
impl ContextWakes {
    pub(crate) fn new(wakes: [Arc<Wake>; 6]) -> Self {
        Self {
            wakes: wakes.map(|wake| Arc::downgrade(&wake)),
        }
    }
    pub(crate) fn notify(&self) {
        // Call only after publishing the context transition. Each wake checks
        // its original predicate again; a notification grants no permission.
        for wake in &self.wakes {
            if let Some(wake) = wake.upgrade() {
                wake.notify();
            }
        }
    }
}

/// A private admission wake with one fixed context-notification destination.
///
/// Ordinary callers keep their private wait domain. Epoch-aware callers wait
/// on the module domain; every actual release must therefore notify both.
/// Links target a plain Wake, never another notifier, so forwarding cannot
/// recurse. No list or per-request registration is retained here.
pub(crate) struct AdmissionWake {
    private: Arc<Wake>,
    context: OnceLock<Weak<Wake>>,
}

impl Default for AdmissionWake {
    fn default() -> Self {
        Self {
            private: Arc::new(Wake::default()),
            context: OnceLock::new(),
        }
    }
}

impl AdmissionWake {
    pub(crate) fn private(&self) -> &Arc<Wake> {
        &self.private
    }

    /// An initialized alias waits in the owner's context when it is bound, so
    /// withdrawal wakes its predicate as well as ordinary dispatch release.
    /// Initial discovery precedes context binding; dispatch release also wakes
    /// the private domain used by loaders admitted during that transition.
    pub(crate) fn context_or_private(&self) -> Arc<Wake> {
        self.context
            .get()
            .and_then(Weak::upgrade)
            .unwrap_or_else(|| self.private.clone())
    }

    /// Bind before checking a wait predicate, never while a Wake is held.
    /// The module root uses its own private domain and has no outgoing link.
    pub(crate) fn bind_context(&self, context: &Arc<Wake>) -> Result<()> {
        if Arc::ptr_eq(&self.private, context) {
            return Ok(());
        }
        let registered = self.context.get_or_init(|| Arc::downgrade(context));
        if !registered.ptr_eq(&Arc::downgrade(context)) {
            return Err(Error::Rejected(crate::RejectionReason::LocalAdmission(
                crate::LocalAdmissionRejection::AdmissionContextOwnerMismatch,
            )));
        }
        Ok(())
    }

    pub(crate) fn notify(&self) {
        // Each call releases its Wake mutex before the next notification.
        // The resource owner must already have released its own raw lock.
        self.private.notify();
        if let Some(context) = self.context.get().and_then(Weak::upgrade) {
            context.notify();
        }
    }

    pub(crate) fn acquire<T>(
        &self,
        admission: &ResourceAdmission,
        reserve: impl FnMut() -> Result<Attempt<T>>,
    ) -> Result<T> {
        self.private.acquire(admission, reserve)
    }
}
