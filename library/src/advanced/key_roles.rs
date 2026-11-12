// SPDX-License-Identifier: Apache-2.0
//! Transfer an exclusive native-key role without waiting for its own capture.
use crate::registry::{Activity, PreparedReader, TransferredWritePermit};
use crate::session::{AdmissionProgress, ObjectRoleLease};
use crate::symmetric::memory::Credit;
use crate::{Error, Result, Session};
use std::sync::{Arc, OnceLock};

#[derive(Clone)]
pub(super) enum Roles {
    Original(ObjectRoleLease),
    Transferred(Arc<TransferOwner>),
}
impl Roles {
    fn same_owner(&self, other: &Self) -> bool {
        match (self, other) {
            (Self::Original(left), Self::Original(right)) => left.same_owner(right),
            (Self::Transferred(left), Self::Transferred(right)) => Arc::ptr_eq(left, right),
            _ => false,
        }
    }

    fn retain_owner(&self, retained: &mut crate::symmetric::memory::RetainedBytes) -> Result<()> {
        match self {
            Self::Original(owner) => owner.retain_role_credits(retained),
            Self::Transferred(owner) => retained.add_credit(&owner._credit),
        }
    }

    /// Deduplicate the fixed key-role tuple of one cryptographic continuation.
    /// N comes from its typed composition (at most four auxiliary keys today),
    /// never from message/fragment counts. No scratch allocation or new limit is
    /// introduced. A shared owner's credit remains indispensable regardless of
    /// its strong count: the source itself keeps at least one reference alive.
    pub(super) fn retain_unique<const N: usize>(
        primary: Option<&Self>,
        auxiliary: [Option<&Self>; N],
        retained: &mut crate::symmetric::memory::RetainedBytes,
    ) -> Result<()> {
        if let Some(primary) = primary {
            primary.retain_owner(retained)?;
        }
        for (index, role) in auxiliary.iter().copied().enumerate() {
            let Some(role) = role else { continue };
            if primary.is_some_and(|owner| owner.same_owner(role))
                || auxiliary[..index]
                    .iter()
                    .flatten()
                    .any(|owner| owner.same_owner(role))
            {
                continue;
            }
            role.retain_owner(retained)?;
        }
        Ok(())
    }
}
pub(super) struct TransferOwner {
    permit: OnceLock<TransferredWritePermit>,
    _credit: Credit,
}
pub(super) struct PreparedTransfer {
    attribution: PreparedReader,
    activity: Arc<Activity>,
}
impl PreparedTransfer {
    pub(super) fn prepare(
        session: &Session,
        activity: &Arc<Activity>,
        progress: &AdmissionProgress,
        authentication: u64,
    ) -> Result<Self> {
        let policy = crate::admission_wait::current();
        let attribution = activity.prepare_reader_retaining(
            session.uid,
            &policy,
            progress.retained_source(),
            || {
                crate::advanced::preparation::context(session)?;
                session
                    .snapshot
                    .observe_authentication_unchanged(authentication)
            },
        )?;
        Ok(Self {
            attribution,
            activity: activity.clone(),
        })
    }
    pub(super) fn allocation_bytes() -> usize {
        std::mem::size_of::<TransferOwner>() + 2 * std::mem::size_of::<usize>()
    }
    pub(super) fn allocate_owner(prepaid: &mut Credit) -> Result<Arc<TransferOwner>> {
        Ok(Arc::new(TransferOwner {
            permit: OnceLock::new(),
            _credit: prepaid.split(Self::allocation_bytes())?,
        }))
    }
    pub(super) fn bind(&self, owner: &Arc<TransferOwner>, source: &Roles) -> Result<Roles> {
        if owner.permit.get().is_none() {
            let permit = match source {
                Roles::Original(owner) => {
                    owner.transfer_writer(&self.activity, &self.attribution)?
                }
                Roles::Transferred(owner) => owner
                    .permit
                    .get()
                    .ok_or(Error::Rejected(crate::RejectionReason::OperationKeys(
                        crate::OperationKeysRejection::UnboundNativeKeyWriter,
                    )))?
                    .share_for(&self.attribution)?,
            };
            owner.permit.set(permit).map_err(|_| {
                Error::Rejected(crate::RejectionReason::OperationKeys(
                    crate::OperationKeysRejection::NativeKeyWriterAlreadyTransferred,
                ))
            })?;
        }
        Ok(Roles::Transferred(owner.clone()))
    }
}
