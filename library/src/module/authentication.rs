// SPDX-License-Identifier: Apache-2.0
//! Exact-session authentication over the existing token-wide native owner.
use super::{LoginRole, SessionEntry, TokenAccess, TokenContext};
use crate::{Error, PinRequest, Result, Session};
use std::sync::atomic::Ordering;
use std::sync::Arc;

impl TokenContext {
    /// Logout must remain reachable after a stopped or failed operation. The
    /// writer excludes every native call on this token while these observations
    /// are made. Occupation and a withdrawn crypto state are not handle closure.
    pub(super) fn logout_entry(
        &self,
        access: &TokenAccess<'_>,
        selected: Option<&Session>,
    ) -> Result<Arc<SessionEntry>> {
        if let Some(session) = selected {
            if !Arc::ptr_eq(&session.inner, &self.inner)
                || !Arc::ptr_eq(&session.snapshot, &self.snapshot)
            {
                return Err(Error::Rejected(crate::RejectionReason::Authentication(
                    crate::AuthenticationRejection::ForeignAuthenticationSession,
                )));
            }
        }
        if self.snapshot.domain.has_pending_token_call() {
            return Err(Error::Busy(crate::BusyReason::ModuleLifecycle(
                crate::ModuleLifecycleBusy::NativeTokenCallPending,
            )));
        }
        self.inner
            .foreign
            .logout_ready(self.snapshot.capabilities.identity.slot)?;
        let entries = access
            .session_ledger
            .logout_entries(&self.snapshot.domain)?;
        for entry in entries.all() {
            if entry.recovery.has_pending_call() {
                return Err(Error::Busy(crate::BusyReason::ModuleLifecycle(
                    crate::ModuleLifecycleBusy::NativeSessionCallPending,
                )));
            }
            access.operations.logout_ready(entry)?;
        }
        let entry = entries
            .iter()
            .find(|entry| {
                selected.map_or(true, |session| Arc::ptr_eq(entry, &session.entry))
                    && (selected.is_some()
                        || entry.credit.client_id() == self.lifecycle_access.client_id())
                    && Arc::ptr_eq(&entry.snapshot, &self.snapshot)
                    && entry.mode == crate::AdvancedSessionMode::Synchronous
                    && !entry.closed.load(Ordering::Acquire)
                    && !entry.close_attempted.load(Ordering::Acquire)
                    && !entry.close_pending.load(Ordering::Acquire)
                    && !entry.deferred_close.load(Ordering::Acquire)
            })
            .cloned()
            .ok_or(Error::Rejected(crate::RejectionReason::Authentication(
                crate::AuthenticationRejection::LogoutRequiresLiveSession,
            )))?;
        // No registry guard crosses notification inspection or native dispatch.
        // The selected entry is an existing Arc, not a new allocation.
        drop(entries);
        if let Some(notification) = &entry.notification {
            notification.check()?;
        }
        Ok(entry)
    }

    /// Called under token possession so close, authentication and native use
    /// cannot race the selected entry's validation. The cloned entry is retained
    /// by the same native frame as the PIN; no borrowed handle escapes.
    pub(super) fn authentication_entry(
        &self,
        access: &TokenAccess<'_>,
        selected: Option<&Session>,
    ) -> Result<Arc<SessionEntry>> {
        match selected {
            Some(session) => {
                if !Arc::ptr_eq(&session.inner, &self.inner)
                    || !Arc::ptr_eq(&session.snapshot, &self.snapshot)
                {
                    return Err(Error::Rejected(crate::RejectionReason::Authentication(
                        crate::AuthenticationRejection::ForeignAuthenticationSession,
                    )));
                }
                session.entry(access)?;
                Ok(session.entry.clone())
            }
            None => access.session_ledger.usable_for(
                &self.snapshot,
                false,
                self.lifecycle_access.client_id(),
            ),
        }
    }
}

impl Session {
    fn authentication_context(&self) -> TokenContext {
        TokenContext {
            inner: self.inner.clone(),
            snapshot: self.snapshot.clone(),
            // This private view serves authentication only; a session does not
            // acquire authority over other participants' native lifecycle.
            lifecycle_access: super::LifecycleAccess::Client(self.entry.credit.client_id()),
        }
    }

    /// Invoke C_Login through this exact session, with the requested role and
    /// owned PIN source. Raw bytes, provided empty PIN and protected path stay
    /// distinct through PinRequest. No local role/session-mode policy is added.
    ///
    /// Login changes token-wide authentication, so active token operations can
    /// prevent admission. CKU_CONTEXT_SPECIFIC instead uses ContextAuthentication
    /// attached to the operation that requires it. A native already-logged-in
    /// result does not verify the supplied PIN and remains an error.
    pub fn login_as(&self, role: LoginRole, pin: impl Into<PinRequest>) -> Result<()> {
        let mut diagnostic = None;
        self.authentication_context().login_on(
            role,
            pin.into(),
            None,
            false,
            Some(self),
            &mut diagnostic,
        )
    }

    /// Invoke C_LoginUser through this exact session. The owned user name and
    /// PIN retain the same lifetime/erasure rules as token-context login. A native
    /// refusal or missing function never falls back to C_Login.
    pub fn login_user(
        &self,
        role: LoginRole,
        pin: impl Into<PinRequest>,
        user_name: Vec<u8>,
    ) -> Result<()> {
        let mut diagnostic = None;
        self.authentication_context().login_on(
            role,
            pin.into(),
            Some(user_name),
            false,
            Some(self),
            &mut diagnostic,
        )
    }

    /// Invoke C_Logout through this exact session. Its authentication effects
    /// remain token-wide; a suspended operation does not prevent dispatch.
    /// Native execution must have returned. Logout does not free retained
    /// operation buffers or establish completion of those operations.
    pub fn logout(&self) -> Result<()> {
        let mut diagnostics = None;
        self.authentication_context()
            .logout_on(false, Some(self), &mut diagnostics)
    }
}

use super::*;

impl LoginRole {
    pub(crate) fn native(self) -> Result<CK_USER_TYPE> {
        match self {
            Self::User => Ok(CKU_USER),
            Self::SecurityOfficer => Ok(CKU_SO),
            Self::VendorExtension(value) => {
                let native = CK_USER_TYPE::try_from(value).map_err(|_| {
                    Error::Rejected(crate::RejectionReason::ModuleLifecycle(
                        crate::ModuleLifecycleRejection::LoginRoleIdentifierConversion,
                    ))
                })?;
                if matches!(native, CKU_USER | CKU_SO | CKU_CONTEXT_SPECIFIC) {
                    return Err(Error::Rejected(crate::RejectionReason::ModuleLifecycle(
                        crate::ModuleLifecycleRejection::StandardLoginRoleRequiresDedicatedVariant,
                    )));
                }
                Ok(native)
            }
        }
    }
}
