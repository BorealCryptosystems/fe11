// SPDX-License-Identifier: Apache-2.0
//! Rebind AEAD continuation keys and accept results of a joined native call.
//! Restoration checks the destination before transferring retained message storage.

use super::*;

impl AeadMessageOperation {
    pub(in crate::advanced) fn check_rejoin_key(&self, entry: &SessionEntry) -> Result<()> {
        self.key.check(entry)
    }

    pub(in crate::advanced) fn restore_keys(
        &self,
        session: &Session,
        keys: StateRestoreKeys<'_>,
        permits: &mut [Option<crate::registry::ReadPermit>],
        bound: &mut restoration_keys::BoundKeys,
    ) -> Result<()> {
        if keys.authentication.is_some() {
            return Err(Error::Rejected(crate::RejectionReason::AeadMessages(
                crate::AeadMessagesRejection::UnexpectedRestorationAuthenticationKey,
            )));
        }
        let key =
            keys.encryption
                .ok_or(Error::Rejected(crate::RejectionReason::CombinedOperations(
                    crate::CombinedOperationsRejection::RestorationEncryptionKeyRequired,
                )))?;
        let lease = self.key.rebind_retained(
            session,
            key.reference,
            self.kind.mechanism(),
            permits,
            &mut bound.encryption,
        )?;
        bound.native_encryption = match key.encoding {
            crate::advanced::StateKeyEncoding::Supplied => lease.handle,
            crate::advanced::StateKeyEncoding::Embedded => fe11_sys::CK_INVALID_HANDLE,
        };
        bound.encryption = Some(lease);
        Ok(())
    }

    /// Return the previous lease for destruction after restore possession ends.
    pub(in crate::advanced) fn bind_restored(
        &mut self,
        mut keys: restoration_keys::BoundKeys,
    ) -> restoration_keys::BoundKeys {
        let replacement = keys
            .encryption
            .take()
            .expect("validated restoration encryption key");
        keys.encryption = Some(std::mem::replace(&mut self.key, replacement));
        keys
    }

    pub(in crate::advanced) fn joined_capacity(&self) -> Result<Option<usize>> {
        if !self.pending() || !self.decrypt {
            return Err(Error::Rejected(crate::RejectionReason::AeadMessages(
                crate::AeadMessagesRejection::AeadMessageOperationNotJoinable,
            )));
        }
        self.function()?;
        self.output_index()
            .map(|i| {
                self.outputs
                    .as_ref()
                    .ok_or(Error::Rejected(crate::RejectionReason::AeadMessages(
                        crate::AeadMessagesRejection::AeadMessageOutputsAbsent,
                    )))?
                    .entries[i]
                    .bytes
                    .capacity()
                    .checked_sub(self.frames[i].used)
                    .ok_or(Error::Rejected(crate::RejectionReason::AeadMessages(
                        crate::AeadMessagesRejection::AeadMessageOutputProgression,
                    )))
            })
            .transpose()
    }

    pub(in crate::advanced) fn accept_joined(
        &mut self,
        s: &State,
        entry: &SessionEntry,
        result: asynchronous::JoinedResult,
    ) -> Result<()> {
        self.joined_capacity()?;
        let name = self.function()?;
        self.activity = NativeActivity::Active;
        if let Err(error) = self.key.check(entry) {
            self.step = AeadStep::Failed;
            return Err(error);
        }
        let index = self.output_index();
        let target = index.map(|i| {
            &mut self.outputs.as_mut().unwrap().entries[i].bytes.as_mut()[self.frames[i].used..]
        });
        let observed = result.observed;
        let (_, length) = match result.project(name, target) {
            Ok(value) => value,
            Err(error) => {
                self.step = AeadStep::Failed;
                s.native.mark_uncertain();
                return Err(error);
            }
        };
        if let (Some(i), Some(length)) = (index, length) {
            *self.frames[i].length = length as CK_ULONG;
        }
        self.finish_step(
            s,
            entry,
            crate::native_return::protocol::PendingInspection::forwarded(observed),
            CompletionSource::Observation,
        )
    }
}
