// SPDX-License-Identifier: Apache-2.0
//! Unpublished destination metadata is admitted with the operation it protects.
use super::key_roles::{PreparedTransfer, TransferOwner};
use crate::managed::{PreparedRevocations, RevocationShape, RevocationStorage};
use crate::session::activity::{PermissionStorage, Permissions};
use crate::symmetric::memory::Credit;
use crate::{Error, Result};
use std::sync::Arc;

#[derive(Clone, Copy, Default)]
pub(super) struct Plan {
    pub(super) revocation: Option<RevocationShape>,
    // Primary plus the four fields of the existing typed message compositions.
    // Classic signatures/ciphers use slot zero only.
    pub(super) transfers: [bool; 5],
    pub(super) permissions: usize,
}
pub(super) struct Storage {
    revocation: Option<RevocationStorage>,
    transfers: [bool; 5],
    permissions: Option<PermissionStorage>,
}
#[derive(Default)]
pub(super) struct Ready {
    pub(super) revocation: Option<PreparedRevocations>,
    pub(super) transfers: [Option<Arc<TransferOwner>>; 5],
    pub(super) permissions: Option<Permissions>,
}
impl Plan {
    pub(super) fn allocation_bytes(self) -> Result<usize> {
        let permission_bytes = PermissionStorage::requested(self.permissions)?;
        self.revocation
            .as_ref()
            .map(RevocationShape::allocation_bytes)
            .transpose()?
            .unwrap_or(0)
            .checked_add(transfer_bytes(self.transfers)?)
            .and_then(|bytes| bytes.checked_add(permission_bytes))
            .ok_or(Error::Rejected(crate::RejectionReason::OperationKeys(
                crate::OperationKeysRejection::NativeDestinationStorageAccounting,
            )))
    }
    pub(super) fn allocate(self) -> Result<Storage> {
        Ok(Storage {
            revocation: self.revocation.map(RevocationShape::allocate).transpose()?,
            transfers: self.transfers,
            permissions: (self.permissions != 0)
                .then(|| PermissionStorage::allocate(self.permissions))
                .transpose()?,
        })
    }
}
impl Storage {
    pub(super) fn allocated_bytes(&self) -> Result<usize> {
        let permission_bytes = self
            .permissions
            .as_ref()
            .map(PermissionStorage::allocated_bytes)
            .transpose()?
            .unwrap_or(0);
        self.revocation
            .as_ref()
            .map(RevocationStorage::allocated_bytes)
            .transpose()?
            .unwrap_or(0)
            .checked_add(transfer_bytes(self.transfers)?)
            .and_then(|bytes| bytes.checked_add(permission_bytes))
            .ok_or(Error::Rejected(crate::RejectionReason::OperationKeys(
                crate::OperationKeysRejection::NativeDestinationStorageAccounting,
            )))
    }
    pub(super) fn bind(self, prepaid: &mut Credit) -> Result<Ready> {
        let mut transfers = std::array::from_fn(|_| None);
        for (index, requested) in self.transfers.into_iter().enumerate() {
            if requested {
                transfers[index] = Some(PreparedTransfer::allocate_owner(prepaid)?);
            }
        }
        Ok(Ready {
            revocation: self
                .revocation
                .map(|storage| storage.bind(prepaid))
                .transpose()?,
            transfers,
            permissions: self
                .permissions
                .map(|storage| storage.bind(prepaid))
                .transpose()?,
        })
    }
}

fn transfer_bytes(transfers: [bool; 5]) -> Result<usize> {
    transfers
        .into_iter()
        .filter(|requested| *requested)
        .count()
        .checked_mul(PreparedTransfer::allocation_bytes())
        .ok_or(Error::Rejected(crate::RejectionReason::OperationKeys(
            crate::OperationKeysRejection::NativeTransferStorageAccounting,
        )))
}
