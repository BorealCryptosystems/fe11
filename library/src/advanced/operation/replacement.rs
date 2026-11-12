// SPDX-License-Identifier: Apache-2.0
//! Prevalidated resident slots for a classic signature reinitialization.
use super::{Operation, OperationBody};
use crate::advanced::{ownership, preparation::PreparedControl, signature, validation};

/// Prepared before C; after exchange these fields hold the retired resources.
/// Its caller declares it outside the access scope, so Drop cannot release
/// credits or key observations while session/body guards are still held.
pub(in crate::advanced) struct SignatureReplacement {
    pub(in crate::advanced) control: PreparedControl,
    pub(in crate::advanced) validation: Option<validation::Capture>,
    pub(in crate::advanced) provenance: Option<crate::advanced::StateProvenance>,
}

pub(in crate::advanced) struct SignatureTarget<'a> {
    body: &'a mut signature::SignatureOperation,
    id: &'a mut u64,
    authentication: &'a mut u64,
    cancel: &'a mut crate::advanced::cancellation::CancellationSlot,
    retirement: &'a mut crate::error::PreparedCleanupDiagnostic,
    validation: &'a mut Option<validation::Capture>,
    provenance: &'a mut Option<crate::advanced::StateProvenance>,
    cancellation: &'a mut ownership::CancellationState,
    continuation: &'a mut ownership::ContinuationStatus,
}

impl Operation {
    /// This borrows only already validated slots. The caller also checks the
    /// exact ticket/lease and Progress under the same possession before C.
    pub(in crate::advanced) fn signature_replacement_target(
        &mut self,
        kind: signature::Kind,
    ) -> Option<SignatureTarget<'_>> {
        if !matches!(kind, signature::Kind::Sign | signature::Kind::Verify)
            || self.execution_incomplete()
            || self.state.is_some()
            || self.transfer.is_some()
            || self.joined.is_some()
            || self.cancel.is_submitted()
            || self.cancellation.is_withdrawn()
            || self.continuation_status.is_frozen()
            || self.validation.as_ref().is_some_and(|v| v.pending() || v.retains_native_memory())
        {
            return None;
        }
        let OperationBody::Signature(body) = &mut self.body else {
            return None;
        };
        if body.replacement_kind() != kind {
            return None;
        }
        Some(SignatureTarget {
            body,
            id: &mut self.id,
            authentication: &mut self._token.authentication,
            cancel: &mut self.cancel,
            retirement: &mut self.retirement,
            validation: &mut self.validation,
            provenance: &mut self.provenance,
            cancellation: &mut self.cancellation,
            continuation: &mut self.continuation_status,
        })
    }
}

impl SignatureTarget<'_> {
    /// No check, allocation, destruction or guard acquisition follows the
    /// publication. Old controls remain in `prepared` until outside guards.
    pub(in crate::advanced) fn commit(
        self,
        candidate: &mut signature::SignatureOperation,
        transfer: crate::native::frame::AcceptedInitTransfer<'_>,
        prepared: &mut SignatureReplacement,
        id: u64,
    ) {
        let authentication = candidate.replacement_authentication();
        transfer.replace_into(candidate, self.body, || {
            std::mem::swap(self.cancel, &mut prepared.control.cancellation);
            std::mem::swap(self.retirement, &mut prepared.control.retirement);
            std::mem::swap(self.validation, &mut prepared.validation);
            std::mem::swap(self.provenance, &mut prepared.provenance);
            *self.id = id;
            *self.authentication = authentication;
            *self.cancellation = ownership::CancellationState::Uncancelled;
            *self.continuation = ownership::ContinuationStatus::Runnable;
        });
    }
}
