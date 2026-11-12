// SPDX-License-Identifier: Apache-2.0
//! Native object size is module-defined metadata, not the length of a key value.
use super::*;
use crate::error::CompletionStorage;
use crate::native::frame::{NativeFrame, SessionFrame};
use crate::symmetric::memory::Credit;
use std::mem::size_of;

struct SizeOutput {
    value: CK_ULONG,
    // The credit survives together with the native target on an uncertain return.
    _credit: Credit,
}

// The diagnostic never enters native retention. Its charge remains in the
// public-call scope after the scalar frame has been returned or quarantined.
struct PreparedSize {
    output: SizeOutput,
    diagnostic: crate::error::PreparedCompletionCell,
}

impl Session {
    /// Read C_GetObjectSize for this session's native object reference.
    ///
    /// PKCS#11 defines the unit as bytes but leaves its precise meaning to the
    /// module. Do not infer key length, CKA_VALUE length, or the amount of memory
    /// that deleting this object would free. Every returned CK_ULONG value is
    /// preserved, including the maximum value; this function does not define an
    /// unavailable-size sentinel. CKR_INFORMATION_SENSITIVE remains a native error.
    ///
    /// Performs one native observation with no attribute read, search or retry.
    /// A foreign, revoked or stale reference is rejected before dispatch. The
    /// session must be available under its caller-selected admission policy.
    pub fn managed_object_size(&self, object: &NativeObjectRef) -> Result<u64> {
        let mut diagnostic = None;
        self.managed_object_size_prepared(object, &mut diagnostic)
    }

    fn managed_object_size_prepared(
        &self,
        object: &NativeObjectRef,
        diagnostic_root: &mut Option<crate::error::PreparedCompletionCell>,
    ) -> Result<u64> {
        // Reserve before taking session guards: a resource wait must not hold
        // the very guards another operation needs to release its own resources.
        // Both stable allocation payloads are counted; allocator overhead is not.
        let bytes = size_of::<SizeOutput>()
            .checked_add(SessionFrame::<'_, SizeOutput>::allocation_bytes())
            .ok_or(Error::Rejected(crate::RejectionReason::ObjectReferences(
                crate::ObjectReferencesRejection::ObjectSizeMetadataAccountingOverflow,
            )))?;
        let epoch = self.snapshot.authentication_stamp();
        let progress = crate::session::AdmissionProgress::default();
        let (prepared, access) = self.prepare_with_native_roles_prepaid_at_epoch(
            [(Some(object), crate::session::activity::AccessMode::Read)],
            false,
            epoch,
            &progress,
            |overhead| {
                let total = bytes
                    .checked_add(overhead)
                    .and_then(|n| n.checked_add(CompletionStorage::allocation_bytes()))
                    .ok_or(Error::Rejected(crate::RejectionReason::ObjectReferences(
                        crate::ObjectReferencesRejection::ObjectSizeAggregateAccountingOverflow,
                    )))?;
                let mut credit =
                    crate::advanced::reserve_preparation_at_epoch(self, total, &progress, epoch)?;
                let prepared = PreparedSize {
                    output: SizeOutput {
                        value: CK_UNAVAILABLE_INFORMATION,
                        _credit: credit.split(bytes)?,
                    },
                    diagnostic: crate::error::PreparedCompletionCell::prepare(&mut credit)?,
                };
                Ok((prepared, credit))
            },
        )?;
        let object_handle = self.managed_handle(&access, object)?;
        let session_handle = self.entry(&access)?.handle;
        let call = access.native.table.C_GetObjectSize.ok_or(Error::Rejected(
            crate::RejectionReason::ObjectReferences(
                crate::ObjectReferencesRejection::CGetObjectSizeUnavailable,
            ),
        ))?;
        let diagnostic = diagnostic_root.insert(prepared.diagnostic).cell();
        let mut frame = NativeFrame::session(access, prepared.output)?;
        {
            let (returned, body) = frame.session_parts();
            let access = &body.access;
            access.native.record("C_GetObjectSize")?;
            let sequence =
                crate::session::Sequence::for_frame_prepared(access, self, returned, diagnostic);
            // SAFETY: the initialized scalar has a stable owned address. The
            // same frame retains the session, image and object activity until
            // this observation is known to have returned. PENDING retains it.
            let rv = returned.observe(
                unsafe { call(session_handle, object_handle, &mut body.data.value) },
                &access.native,
            );
            sequence.check(rv, "C_GetObjectSize", false)?;
        }
        let completed = frame.into_inner()?;
        diagnostic.finish(
            "C_GetObjectSize",
            object.identity.access().result(
                self,
                &completed.access,
                Ok(completed.data.value as u64),
            ),
        )
    }
}

impl crate::AdvancedSession {
    /// Read module-defined object size through the same owner as Session.
    /// This single synchronous observation does not create an operation ticket,
    /// change local pacing, or complete another tracked operation. Native native asynchronous mode
    /// remains outside the implemented scope. See Session::managed_object_size.
    pub fn managed_object_size(&self, object: &NativeObjectRef) -> Result<u64> {
        let mut diagnostic = None;
        self.session
            .managed_object_size_prepared(object, &mut diagnostic)
    }
}
