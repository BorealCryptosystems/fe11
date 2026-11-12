// SPDX-License-Identifier: Apache-2.0
//! Validate caller-selected session ceilings against announced native limits.
//! Effective limits retain the distinction between unavailable and explicit bounds.

use super::*;

impl SessionPolicy {
    pub(crate) fn validate(&self) -> Result<()> {
        for (i, entry) in self.tokens.iter().enumerate() {
            if self.tokens[..i]
                .iter()
                .any(|other| other.identity == entry.identity)
            {
                return Err(Error::Rejected(crate::RejectionReason::SessionAccounting(
                    crate::SessionAccountingRejection::DuplicateSessionPolicyToken,
                )));
            }
        }
        Ok(())
    }

    pub(crate) fn effective(&self, cap: &Capabilities) -> SessionLimit {
        let configured = self
            .tokens
            .iter()
            .find(|v| v.identity == cap.identity)
            .map(|v| v.limit)
            .unwrap_or(self.default_token);
        match self.announced_limits {
            AnnouncedSessionLimits::Ignore => configured,
            AnnouncedSessionLimits::IntersectWithAnnounced => SessionLimit {
                total: announced_limit(configured.total, cap.maximum_sessions),
                read_write: announced_limit(configured.read_write, cap.maximum_read_write_sessions),
            },
        }
    }
}

pub(super) fn announced_limit(local: usize, announced: u64) -> usize {
    if announced == CK_EFFECTIVELY_INFINITE as u64 || announced == CK_UNAVAILABLE_INFORMATION as u64
    {
        local
    } else {
        local.min(usize::try_from(announced).unwrap_or(usize::MAX))
    }
}
