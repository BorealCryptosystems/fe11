// SPDX-License-Identifier: Apache-2.0
//! A native key lease keeps either a reader or an explicit stateful writer.
use crate::advanced::key_roles::Roles;
use crate::managed::RevocationTargets;
use crate::registry::ReadPermit;
use crate::{Error, Result};

pub(super) enum Permission {
    Read(ReadPermit),
    Write {
        roles: Roles,
        revocation: Revocation,
    },
}
pub(in crate::advanced) enum Revocation {
    Prepared(RevocationTargets),
    Armed,
}
impl Permission {
    pub(super) fn writer_roles(&self) -> Option<&Roles> {
        match self {
            Self::Read(_) => None,
            Self::Write { roles, .. } => Some(roles),
        }
    }
    pub(super) fn duplicate(&self) -> Result<Self> {
        match self {
            Self::Read(permit) => permit.duplicate().map(Self::Read),
            Self::Write {
                roles,
                revocation: Revocation::Armed,
            } => Ok(Self::Write {
                roles: roles.clone(),
                revocation: Revocation::Armed,
            }),
            Self::Write {
                revocation: Revocation::Prepared(_),
                ..
            } => Err(Error::Rejected(crate::RejectionReason::OperationKeys(
                crate::OperationKeysRejection::UnsubmittedNativeWriterCannotBeDuplicated,
            ))),
        }
    }
    pub(super) fn owns_revocation(&self) -> bool {
        matches!(
            self,
            Self::Write {
                revocation: Revocation::Armed,
                ..
            }
        )
    }
    /// Preserve authority already exercised by another binding of this exact
    /// identity. This does not revoke aliases again or upgrade a read permit.
    pub(super) fn retain_armed(&mut self) {
        if let Self::Write { revocation, .. } = self {
            *revocation = Revocation::Armed;
        }
    }
    /// Called after local preparation and immediately before a native Init or
    /// SetOperationState. A refusal never releases the writer prematurely.
    pub(super) fn arm(&mut self) {
        if let Self::Write { revocation, .. } = self {
            if let Revocation::Prepared(targets) = std::mem::replace(revocation, Revocation::Armed)
            {
                drop(targets.arm());
            }
        }
    }
}

impl crate::symmetric::memory::RetainedStorage for Permission {
    fn retain_credits(
        &self,
        retained: &mut crate::symmetric::memory::RetainedBytes,
    ) -> crate::Result<()> {
        match self {
            Self::Write {
                revocation: Revocation::Prepared(targets),
                ..
            } => targets.retain_credits(retained),
            Self::Read(_)
            | Self::Write {
                revocation: Revocation::Armed,
                ..
            } => Ok(()),
        }
    }
}
