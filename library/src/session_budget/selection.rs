// SPDX-License-Identifier: Apache-2.0
//! Select ledger records for collective closure or logout observation.
//! Selection retains existing identities rather than deriving ownership from a handle.

use super::*;

impl LogoutEntries<'_> {
    /// A lost handle does not establish that its retained execution finished.
    pub(crate) fn all(&self) -> impl Iterator<Item = &Arc<crate::module::SessionEntry>> {
        self.state
            .records
            .values()
            .filter_map(Record::entry)
            .filter(|entry| Arc::ptr_eq(&entry.snapshot.domain, self.domain))
    }

    pub(crate) fn iter(&self) -> impl Iterator<Item = &Arc<crate::module::SessionEntry>> {
        self.state
            .records
            .values()
            .filter(|record| record.live_native())
            .filter_map(Record::entry)
            .filter(|entry| Arc::ptr_eq(&entry.snapshot.domain, self.domain))
    }
}

impl SessionLedger {
    /// Snapshot only this token's live native sessions under its writer. Logout
    /// may use an occupied or locally poisoned session, but never a closed or
    /// unproven-open handle. Other tokens are not retained by this snapshot.
    pub(crate) fn logout_entries<'a>(
        &'a self,
        domain: &'a Arc<crate::module::SlotDomain>,
    ) -> Result<LogoutEntries<'a>> {
        let state = self.state.lock().map_err(|_| Error::Poisoned)?;
        Ok(LogoutEntries { state, domain })
    }
}
