// SPDX-License-Identifier: Apache-2.0
//! Metadata-only lifetime of a synchronous observation caller.
use super::Coordination;
use crate::{Result, Session};
use std::sync::{atomic::Ordering, Arc};

pub(crate) struct Waiting<'a> {
    session: &'a Session,
    pub(crate) coordination: Arc<Coordination>,
    authentication: Option<u64>,
    epoch: u64,
}
impl<'a> Waiting<'a> {
    pub(crate) fn new(
        session: &'a Session,
        coordination: Arc<Coordination>,
        authentication: Option<u64>,
        epoch: u64,
    ) -> Self {
        Self {
            session,
            coordination,
            authentication,
            epoch,
        }
    }
    pub(crate) fn check(&self) -> Result<()> {
        self.coordination.check()?;
        context(self.session, self.authentication, self.epoch)
    }
    /// Preparation uses this continuation's account, including its retained
    /// child buffers, while sharing the module's existing aggregate ceiling.
    pub(crate) fn budget(&self) -> &Arc<crate::symmetric::memory::Budget> {
        &self.coordination.budget
    }
}
// Only pure/atomic checks: Budget may invoke this while owning its wake lock.
pub(crate) fn context(session: &Session, authentication: Option<u64>, epoch: u64) -> Result<()> {
    crate::session::activity::context(session)?;
    session.snapshot.observe_authentication_unchanged(epoch)?;
    if let Some(stamp) = authentication {
        session.snapshot.observe_authentication_unchanged(stamp)?;
    }
    Ok(())
}
impl Drop for Waiting<'_> {
    fn drop(&mut self) {
        self.coordination.withdraw();
        self.session.entry.recovery.observations.mark_cleanup();
        self.session
            .snapshot
            .domain
            .needs_local_cleanup
            .store(true, Ordering::Release);
        // Cleanup does not wait or issue a native call. If possession is busy,
        // the session's next maintenance or proven close reclaims the owner.
        let _ = self.session.maintain_local();
    }
}
