// SPDX-License-Identifier: Apache-2.0
//! Borrowed reconstruction recipes and unpublished destination storage.
use super::PreparedBody;
use crate::advanced::{cipher, digest, dual, gcm, messages, record, recover};
use crate::{symmetric::memory::Credit, Error, Result};

pub(super) enum Plan<'a> {
    AeadStream(gcm::checkpoint::RecordPlan<'a>),
    NativeMessages(crate::advanced::native_messages::checkpoint::RecordPlan<'a>),
    AeadMessages(gcm::snapshot::RecordPlan<'a>),
    Dual(dual::snapshot::RecordPlan<'a>),
    Messages(messages::snapshot::RecordPlan<'a>),
    Cipher(cipher::checkpoint::RecordPlan<'a>),
    Digest(digest::snapshot::RecordPlan<'a>),
    Recover(recover::checkpoint::RecordPlan<'a>),
    Signature(crate::advanced::signature::checkpoint::RecordPlan<'a>),
}
pub(super) enum Storage<'a> {
    AeadStream(gcm::checkpoint::Storage<'a>),
    NativeMessages(crate::advanced::native_messages::checkpoint::Storage<'a>),
    AeadMessages(gcm::snapshot::Storage),
    Dual(dual::snapshot::Storage),
    Messages(messages::snapshot::Storage),
    Cipher(cipher::snapshot::Storage<'a>),
    Digest(digest::snapshot::RecordStorage<'a>),
    Recover(recover::checkpoint::SnapshotStorage),
    Signature(crate::advanced::signature::checkpoint::Storage<'a>),
}
impl<'a> Plan<'a> {
    pub(super) fn new(
        descriptor: record::Descriptor,
        messages: &record::Messages<'a>,
        ceilings: crate::CryptoLimits,
        pending: bool,
    ) -> Result<Self> {
        Ok(match descriptor.family {
            record::Family::NativeMessages => {
                return Err(Error::Rejected(crate::RejectionReason::Restoration(
                    crate::RestorationRejection::GenericMessageDestinationPreparationRequired,
                )));
            }
            record::Family::Signature => {
                Self::Signature(crate::advanced::signature::checkpoint::RecordPlan::new(
                    descriptor, messages, ceilings, pending,
                )?)
            }
            record::Family::DigestEncrypt
            | record::Family::DecryptDigest
            | record::Family::SignEncrypt
            | record::Family::DecryptVerify => Self::Dual(dual::snapshot::RecordPlan::new(
                descriptor, messages, ceilings, pending,
            )?),
            record::Family::MessageSign | record::Family::MessageVerify => Self::Messages(
                messages::snapshot::RecordPlan::new(descriptor, messages, ceilings, pending)?,
            ),
            record::Family::CipherEncrypt | record::Family::CipherDecrypt => Self::Cipher(
                cipher::checkpoint::RecordPlan::new(descriptor, messages, ceilings, pending)?,
            ),
            record::Family::Digest => Self::Digest(digest::snapshot::RecordPlan::new(
                descriptor, messages, ceilings, pending,
            )?),
            record::Family::SignRecover | record::Family::VerifyRecover => Self::Recover(
                recover::checkpoint::RecordPlan::new(descriptor, messages, ceilings, pending)?,
            ),
            record::Family::MessageEncrypt | record::Family::MessageDecrypt => {
                if let Some(record) = messages.aead() {
                    Self::AeadStream(gcm::checkpoint::RecordPlan::new(
                        descriptor, record, ceilings, pending,
                    )?)
                } else {
                    Self::AeadMessages(gcm::snapshot::RecordPlan::new(
                        descriptor, messages, ceilings, pending,
                    )?)
                }
            }
        })
    }
    pub(super) fn allocation_bytes(&self) -> Result<usize> {
        match self {
            Self::AeadStream(plan) => plan.allocation_bytes(),
            Self::AeadMessages(plan) => Ok(plan.allocation_bytes()),
            Self::Dual(plan) => Ok(plan.allocation_bytes()),
            Self::Messages(plan) => plan.allocation_bytes(),
            Self::Cipher(plan) => Ok(plan.allocation_bytes()),
            Self::Digest(plan) => Ok(plan.allocation_bytes()),
            Self::Recover(plan) => plan.allocation_bytes(),
            Self::Signature(plan) => plan.allocation_bytes(),
            Self::NativeMessages(plan) => plan.allocation_bytes(),
        }
    }
    pub(super) fn allocate(&self, prepaid: &mut Credit) -> Result<Storage<'a>> {
        match self {
            Self::AeadStream(plan) => plan.allocate().map(Storage::AeadStream),
            Self::AeadMessages(plan) => plan.allocate().map(Storage::AeadMessages),
            Self::Dual(plan) => plan.allocate(prepaid).map(Storage::Dual),
            Self::Messages(plan) => plan.allocate().map(Storage::Messages),
            Self::Cipher(plan) => plan.allocate(prepaid).map(Storage::Cipher),
            Self::Digest(plan) => plan.allocate().map(Storage::Digest),
            Self::Recover(plan) => plan.allocate().map(Storage::Recover),
            Self::Signature(plan) => plan.allocate().map(Storage::Signature),
            Self::NativeMessages(plan) => plan.allocate().map(Storage::NativeMessages),
        }
    }
    pub(super) fn bind(self, storage: Storage<'a>, prepaid: &mut Credit) -> Result<PreparedBody> {
        match (self, storage) {
            (Self::AeadStream(_), Storage::AeadStream(storage)) => {
                storage.bind(prepaid).map(PreparedBody::AeadMessages)
            }
            (Self::NativeMessages(plan), Storage::NativeMessages(storage)) => plan
                .bind(storage, prepaid)
                .map(PreparedBody::NativeMessages),
            (Self::Signature(plan), Storage::Signature(storage)) => {
                plan.bind(storage, prepaid).map(PreparedBody::Signature)
            }
            (Self::AeadMessages(plan), Storage::AeadMessages(storage)) => {
                plan.bind(storage, prepaid).map(PreparedBody::AeadMessages)
            }
            (Self::Dual(plan), Storage::Dual(storage)) => {
                plan.bind(storage, prepaid).map(PreparedBody::Dual)
            }
            (Self::Messages(plan), Storage::Messages(storage)) => {
                plan.bind(storage, prepaid).map(PreparedBody::Messages)
            }
            (Self::Cipher(plan), Storage::Cipher(storage)) => {
                plan.bind(storage, prepaid).map(PreparedBody::Cipher)
            }
            (Self::Digest(plan), Storage::Digest(storage)) => {
                plan.bind(storage, prepaid).map(PreparedBody::Digest)
            }
            (Self::Recover(plan), Storage::Recover(storage)) => {
                plan.bind(storage, prepaid).map(PreparedBody::Recover)
            }
            _ => Err(Error::Rejected(crate::RejectionReason::Restoration(
                crate::RestorationRejection::ReconstructionStorageFamilyChanged,
            ))),
        }
    }
}
impl Storage<'_> {
    pub(super) fn allocated_bytes(&self) -> Result<usize> {
        match self {
            Self::AeadStream(storage) => storage.allocated_bytes(),
            Self::AeadMessages(storage) => storage.allocated_bytes(),
            Self::Dual(storage) => storage.allocated_bytes(),
            Self::Messages(storage) => storage.allocated_bytes(),
            Self::Cipher(storage) => storage.allocated_bytes(),
            Self::Digest(storage) => storage.allocated_bytes(),
            Self::Recover(storage) => storage.allocated_bytes(),
            Self::Signature(storage) => storage.allocated_bytes(),
            Self::NativeMessages(storage) => storage.allocated_bytes(),
        }
    }
}
