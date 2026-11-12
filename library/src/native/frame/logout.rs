// SPDX-License-Identifier: Apache-2.0
//! Allocation-free ownership for C_Logout, whose only argument is a value.
use super::{CallPhase, CallScope, Cell, Disposition, FrameReturn, CKR_PENDING};
use crate::module::{SessionEntry, TokenAccess};
use std::sync::Arc;

struct Body<'a> {
    entry: Arc<SessionEntry>,
    access: TokenAccess<'a>,
}

/// This owner must never expose an address to C. Unlike PIN/output frames,
/// Logout passes only a copied handle; its existing Arc referents are stable.
/// No new heap storage or resource admission is needed to end authentication.
pub(crate) struct LogoutFrame<'a> {
    // new installs Some; only Drop takes it. No method transfers the body,
    // including on a native refusal or an unwind. Option controls quarantine
    // and destruction order rather than whether a live frame has an owner.
    body: Option<Body<'a>>,
    disposition: Cell<Disposition>,
    call: Cell<CallPhase>,
}
impl<'a> LogoutFrame<'a> {
    pub(crate) fn new(access: TokenAccess<'a>, entry: Arc<SessionEntry>) -> Self {
        Self {
            body: Some(Body { entry, access }),
            disposition: Cell::new(Disposition::Owned),
            call: Cell::new(CallPhase::Prepared),
        }
    }

    pub(crate) fn parts(&self) -> (FrameReturn<'_>, &TokenAccess<'a>, &SessionEntry) {
        let body = self.body.as_ref().expect("logout owner present");
        (
            FrameReturn {
                disposition: &self.disposition,
                call: &self.call,
                scope: CallScope::Unscoped,
            },
            &body.access,
            &body.entry,
        )
    }
}
impl Drop for LogoutFrame<'_> {
    fn drop(&mut self) {
        if self.disposition.get() == Disposition::Owned {
            return;
        }
        let body = self.body.take().expect("logout owner present");
        match self.call.get() {
            CallPhase::Returned(rv) => {
                // Same token-wide quarantine as an addressed token frame:
                // keep entry/image/snapshot, mark pending, release coordination.
                body.access
                    .quarantine_returned(body.entry, rv == CKR_PENDING);
            }
            CallPhase::Prepared | CallPhase::Issued => {
                // No recorded return proves execution stopped. Keep the writer
                // and its referents; no pointer targets this stack-only owner.
                body.access.native.mark_uncertain();
                std::mem::forget(body);
            }
        }
    }
}
