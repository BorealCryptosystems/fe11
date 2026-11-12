// SPDX-License-Identifier: Apache-2.0
//! Cipher preparation chooses the native key role before copying private inputs.
use super::{api::CipherKey, CipherKeyReference, CipherLease, KeyLease};
use crate::advanced::{key_roles::Roles, keys::KeyReaders};
use crate::session::{activity::AccessMode, AdmissionProgress, ObjectRoleLease, SessionAccess};
use crate::{Error, NativeObjectRef, Result, Session};

pub(super) fn reference<'a>(key: &CipherKey<'a>) -> Option<&'a NativeObjectRef> {
    match key {
        CipherKey::Profiled(key) => Some(&key.managed),
        CipherKey::Native(CipherKeyReference::Secret(key)) => Some(key),
        CipherKey::Native(CipherKeyReference::NoKey) => None,
    }
}
pub(super) enum Grant {
    Readers([Option<crate::registry::ReadPermit>; 1]),
    Writer(ObjectRoleLease),
}
pub(super) fn prepare_with<'a, T>(
    session: &'a Session,
    key: &CipherKey<'_>,
    mutates: bool,
    progress: &AdmissionProgress,
    epoch: u64,
    mut prepare: impl FnMut(usize) -> Result<(T, crate::symmetric::memory::Credit)>,
) -> Result<(T, SessionAccess<'a>, Grant)> {
    let reference = reference(key);
    if mutates && reference.is_some() {
        let (candidate, access) = session.prepare_with_native_roles_prepaid_at_epoch(
            [(reference, AccessMode::Write)],
            false,
            epoch,
            progress,
            prepare,
        )?;
        let role = access.retain_role_lease();
        Ok((candidate, access, Grant::Writer(role)))
    } else {
        KeyReaders::prepare_at_epoch(session, [reference], epoch)?
            .prepare_with_at_epoch(session, progress, epoch, || {
                let (candidate, remainder) = prepare(0)?;
                // Read roles already use stack slots; no private permission
                // vector accompanies this branch. Release unused aggregate credit.
                drop(remainder);
                Ok(candidate)
            })
            .map(|(candidate, access, permits)| (candidate, access, Grant::Readers(permits)))
    }
}
impl Grant {
    pub(super) fn bind(
        &mut self,
        session: &Session,
        key: CipherKey<'_>,
        mechanism: fe11_sys::CK_MECHANISM_TYPE,
        revocation: &mut Option<crate::managed::RevocationTargets>,
        candidate: &mut Option<KeyLease>,
    ) -> Result<CipherLease> {
        match self {
            Self::Writer(roles) => {
                let reference = reference(&key).ok_or(Error::Rejected(
                    crate::RejectionReason::CipherContinuation(
                        crate::CipherContinuationRejection::NativeWriterKeyAbsent,
                    ),
                ))?;
                revocation.as_ref().ok_or(Error::Rejected(
                    crate::RejectionReason::OperationKeys(
                        crate::OperationKeysRejection::NativeWriterRevocationAbsent,
                    ),
                ))?;
                KeyLease::from_native_writer(
                    session,
                    reference,
                    mechanism,
                    Roles::Original(roles.clone()),
                    revocation,
                    candidate,
                )
                .map(CipherLease::WithKey)
            }
            Self::Readers(permits) => {
                if revocation.is_some() {
                    return Err(Error::Rejected(crate::RejectionReason::CipherContinuation(
                        crate::CipherContinuationRejection::RevocationWithoutNativeWriter,
                    )));
                }
                match key {
                    CipherKey::Profiled(key) => {
                        KeyLease::new_retained(session, key, permits, candidate)
                            .map(CipherLease::WithKey)
                    }
                    CipherKey::Native(CipherKeyReference::Secret(key)) => {
                        KeyLease::for_native_cipher_retained(
                            session, key, mechanism, permits, candidate,
                        )
                        .map(CipherLease::WithKey)
                    }
                    CipherKey::Native(CipherKeyReference::NoKey) => Ok(CipherLease::NoKey),
                }
            }
        }
    }
}
