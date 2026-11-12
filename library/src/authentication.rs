// SPDX-License-Identifier: Apache-2.0
//! Bounded authentication observations, never authority to use native handles.
use crate::{Error, LoginRole, Result};

use std::sync::{
    atomic::{AtomicU64, Ordering},
    Mutex,
};

pub(crate) struct Authentication {
    role: Mutex<RecordedAuthentication>,
    epoch: AtomicU64,
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum RecordedAuthentication {
    Unknown,
    Public,
    Role(LoginRole),
}

impl Authentication {
    pub fn new() -> Self {
        Self {
            role: Mutex::new(RecordedAuthentication::Unknown),
            epoch: AtomicU64::new(0),
        }
    }
    // This stamp grants no role or authority. Checks below serialize with role
    // publication; compound observations and captures validate their own stamp.
    // A completed native result does not acquire a new freshness requirement.
    pub fn stamp(&self) -> u64 {
        self.epoch.load(Ordering::Acquire)
    }

    /// A recorded observation is not a current native authorization. Unknown
    /// must not be reported as a successful observation of a public session.
    pub(crate) fn recorded_user(&self) -> Result<crate::Observation<bool>> {
        Ok(match *self.role.lock().map_err(|_| Error::Poisoned)? {
            RecordedAuthentication::Unknown => {
                crate::Observation::Unavailable(crate::AttributeUnavailableCause::Unspecified)
            }
            RecordedAuthentication::Public => crate::Observation::Observed(false),
            RecordedAuthentication::Role(role) => {
                crate::Observation::Observed(role == LoginRole::User)
            }
        })
    }
    pub fn transition(&self, role: Option<LoginRole>) -> Result<()> {
        if let Some(role) = role {
            role.native()?;
        }
        self.publish(
            role.map_or(RecordedAuthentication::Public, RecordedAuthentication::Role),
            false,
        )
    }
    /// Local population changes and incomplete/refused authentication calls
    /// withdraw evidence without claiming that the module logged anyone out.
    pub(crate) fn forget(&self) -> Result<()> {
        self.publish(RecordedAuthentication::Unknown, false)
    }
    pub(crate) fn observe_session_state(&self, state: fe11_sys::CK_STATE) -> Result<()> {
        use fe11_sys::*;
        let observed = match state {
            CKS_RO_PUBLIC_SESSION | CKS_RW_PUBLIC_SESSION => RecordedAuthentication::Public,
            CKS_RO_USER_FUNCTIONS | CKS_RW_USER_FUNCTIONS => {
                RecordedAuthentication::Role(LoginRole::User)
            }
            CKS_RW_SO_FUNCTIONS => RecordedAuthentication::Role(LoginRole::SecurityOfficer),
            _ => RecordedAuthentication::Unknown,
        };
        self.publish(observed, true)
    }
    fn publish(&self, observed: RecordedAuthentication, only_if_changed: bool) -> Result<()> {
        let mut current = self.role.lock().map_err(|_| Error::Poisoned)?;
        if only_if_changed && *current == observed {
            return Ok(());
        }
        let next = self.stamp().checked_add(1).ok_or(Error::Rejected(
            crate::RejectionReason::Authentication(
                crate::AuthenticationRejection::AuthenticationEpochExhausted,
            ),
        ))?;
        // No fallible work or user/native code between these publications.
        // Role readers and freshness checks share the mutex. The atomic stamp
        // can be sampled independently, but never establishes access by itself.
        *current = observed;
        self.epoch.store(next, Ordering::Release);
        Ok(())
    }
    pub fn check_unchanged(&self, stamp: u64) -> Result<()> {
        let _role = self.role.lock().map_err(|_| Error::Poisoned)?;
        if self.stamp() != stamp {
            return Err(Error::Rejected(crate::RejectionReason::Authentication(
                crate::AuthenticationRejection::AuthenticationEpochChanged,
            )));
        }
        Ok(())
    }
    /// Routing observation for a resource predicate running under Wake. It
    /// takes no role mutex and grants no possession or native-call authority.
    /// The caller must perform check_unchanged again under its normal guards.
    pub(crate) fn observe_unchanged(&self, stamp: u64) -> Result<()> {
        if self.role.is_poisoned() {
            return Err(Error::Poisoned);
        }
        if self.stamp() != stamp {
            return Err(Error::Rejected(crate::RejectionReason::Authentication(
                crate::AuthenticationRejection::AuthenticationEpochChanged,
            )));
        }
        Ok(())
    }
    pub fn check_private(&self, stamp: u64) -> Result<()> {
        // Freshness of a descriptive observation only. Native handle dispatch
        // must not use this as an access check; the module decides access.
        self.check_unchanged(stamp)
    }
}
