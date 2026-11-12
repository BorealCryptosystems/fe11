// SPDX-License-Identifier: Apache-2.0
//! Explicit persistent boundary of an already detached native operation.

use super::{
    persistence, AdvancedSession, AdvancedSessionMode, CallerAssertedAuthenticatedRecord,
    DetachedOperation, RecordLimits, StateProvenance,
};

use crate::symmetric::memory::{Buffer, Credit};
use crate::{Error, Result};

#[doc = include_str!("../../docs/api/advanced/detached_persistence/DetachedOperationRecord.md")]
pub struct DetachedOperationRecord {
    bytes: Buffer,
    _credit: Credit,
}
impl DetachedOperationRecord {
    /// Borrow sensitive bytes. Consumer copies are not erased by this library.
    pub fn as_bytes(&self) -> &[u8] {
        self.bytes.as_slice()
    }
}
/// Local refusal preserves the original detached capability for an explicit
/// caller decision. No implicit Join, cancellation, retry or fallback occurs.
pub struct DetachedExportFailure {
    /// Exact local refusal.
    pub error: Error,
    /// Original operation, with its existing provenance and owned buffer.
    pub operation: DetachedOperation,
}
impl DetachedOperation {
    /// Consume this local capability and transfer its existing canonical buffer
    /// to the persistence service. It does not terminate the detached native job.
    /// Local refusal returns the original operation. Export does not change the
    /// continuation's native authentication state or release any retained output.
    pub fn export_detached(
        self,
        limits: RecordLimits,
    ) -> std::result::Result<DetachedOperationRecord, DetachedExportFailure> {
        let checked = (|| -> Result<()> {
            let limits = limits.checked()?;
            persistence::detached_context(self.record.as_slice(), limits).map(|_| ())
        })();
        if let Err(error) = checked {
            return Err(DetachedExportFailure {
                error,
                operation: self,
            });
        }
        // Keep the original (larger) metadata credit. Moving the same Buffer
        // cannot duplicate a native continuation or evade the shared budget.
        Ok(DetachedOperationRecord {
            bytes: self.record,
            _credit: self._credit,
        })
    }
}
impl AdvancedSession {
    /// This import requires the unsupported native asynchronous mode. Current synchronous
    /// sessions reject it; parsing a retained wire format does not enable Join.
    ///
    /// Import an exclusively owned, service-authenticated detached record into
    /// this compatible asynchronous context without native IO. The service must
    /// establish a successful original GetID and prevent duplicate Join/replay.
    /// The detached native job may remain pending; it must not be restarted.
    ///
    /// Structural/context checks grant no authentication or portability claim.
    /// Key re-admission and native session inspection still precede the explicit
    /// start_rejoin/poll_rejoin sequence. Imported provenance is never promoted.
    /// The record is consumed even on refusal, with no retry or implicit recovery fallback.
    pub fn import_detached(
        &self,
        record: CallerAssertedAuthenticatedRecord,
    ) -> Result<DetachedOperation> {
        let context = persistence::detached_context(record.bytes.as_slice(), record.limits)?;
        let access = self.session.advanced_access()?;
        if self.mode() != AdvancedSessionMode::Asynchronous {
            return Err(Error::Rejected(crate::RejectionReason::Persistence(
                crate::PersistenceRejection::AsynchronousRejoinSessionMode,
            )));
        }
        context.check_destination_binding(&self.session.inner, &self.session.snapshot)?;
        let authentication = self.session.snapshot.authentication_stamp();
        drop(access);
        let budget = &self.session.inner.symmetric_budget;
        let retained = record.retained_bytes(budget)?;
        let (mut bytes, credit) = Buffer::with_metadata_retained(
            budget,
            record.bytes.as_slice().len(),
            std::mem::size_of::<DetachedOperation>(),
            Some(&retained),
            || {
                super::preparation::context(&self.session)?;
                self.session
                    .snapshot
                    .observe_authentication_unchanged(authentication)
            },
        )?;
        bytes.as_mut().copy_from_slice(record.bytes.as_slice());
        let _access = self.session.advanced_access()?;
        context.check_destination_binding(&self.session.inner, &self.session.snapshot)?;
        self.session
            .snapshot
            .check_authentication_unchanged(authentication)?;
        Ok(DetachedOperation {
            provenance: Some(StateProvenance::Imported),
            record: bytes,
            limits: record.limits,
            _credit: credit,
        })
    }
}
