// SPDX-License-Identifier: Apache-2.0
//! Explicit native state archive boundary; archive security remains the service's.
use super::restoration_keys::BoundKeys;

use super::{
    keys, reconstruction, record, AdvancedSession, CallerAssertedAuthenticatedRecord,
    OperationTicket, RecordLimits, SavedOperationState, StateProvenance, StateRestoreKeys,
};
use crate::symmetric::memory::{Buffer, Credit};
use crate::{Error, Result};
use std::sync::Arc;

#[doc = include_str!("../../docs/api/advanced/persistence/NativeStateRecord.md")]
pub struct NativeStateRecord {
    bytes: Buffer,
    _credit: Credit,
}
/// Local export refusal; the original state remains owned and is not retried.
/// No sensitive state formatting is provided.
pub struct StateExportFailure {
    /// Exact local failure.
    pub error: Error,
    /// Original state for an explicit caller decision; cipher source stays frozen.
    pub state: SavedOperationState,
}
impl NativeStateRecord {
    /// Explicit sensitive export. Consumer copies/storage are not erased here.
    pub fn as_bytes(&self) -> &[u8] {
        self.bytes.as_slice()
    }
}
pub(super) fn detached_context(bytes: &[u8], limits: record::Limits) -> Result<record::Context> {
    match record::decode(bytes, limits)?.0 {
        record::Kind::DetachedRestore => {
            let record = record::RestorationRecord::read(bytes, limits)?;
            Ok(record.saved.context)
        }
        record::Kind::Detached
        | record::Kind::DetachedCapture
        | record::Kind::DetachedValidation => {
            let record = record::DetachedRecord::read(bytes, limits)?;
            // The reader validates cross-section consistency. Exporting opaque
            // state does not publish retained plaintext as authenticated output.
            Ok(record.context)
        }
        _ => Err(Error::Rejected(crate::RejectionReason::Persistence(
            crate::PersistenceRejection::DetachedRecordKind,
        ))),
    }
}

pub(super) fn validate_import_with<'a>(
    bytes: &'a [u8],
    limits: record::Limits,
    observer: record::GraphObserver<'a>,
) -> Result<()> {
    match record::decode(bytes, limits)?.0 {
        record::Kind::GcmRecoveryManifest => {
            record::RecoveryManifest::read_with(bytes, limits, observer)?;
        }
        record::Kind::DualRecovery => {
            record::DualRecovery::read_with(bytes, limits, observer)?;
        }
        record::Kind::Detached
        | record::Kind::DetachedCapture
        | record::Kind::DetachedValidation => {
            record::DetachedRecord::read_with(bytes, limits, observer)?;
        }
        record::Kind::DetachedRestore => {
            record::RestorationRecord::read_with(bytes, limits, observer)?;
        }
        record::Kind::Saved => {
            record::SavedRecord::read_with(bytes, limits, observer)?;
        }
        // The recovery record's internal section is not an authenticated standalone manifest,
        // and cannot be imported as one. No fallback from an opaque record occurs.
        record::Kind::GcmRecovery => {
            return Err(Error::Rejected(crate::RejectionReason::Persistence(
                crate::PersistenceRejection::UnsupportedAuthenticatedRecordKind,
            )))
        }
    }
    Ok(())
}
impl SavedOperationState {
    /// Consume the local continuation and export its canonical sensitive record.
    /// A refusal returns the original state; an encryption source stays frozen.
    /// No implicit duplicate, native call, archive encryption or retry occurs.
    /// Pending authentication remains recorded in the continuation. Exporting
    /// these sensitive bytes does not change the conditions for publishing output.
    pub fn export_state(
        self,
        limits: RecordLimits,
    ) -> std::result::Result<NativeStateRecord, StateExportFailure> {
        let result = (|| -> Result<NativeStateRecord> {
            let owner = self.owner.upgrade().ok_or(Error::Rejected(
                crate::RejectionReason::Persistence(
                    crate::PersistenceRejection::CapturedModuleNoLongerOwned,
                ),
            ))?;
            let limits = limits.checked()?;
            let budget = &owner.symmetric_budget;
            let context = self.checkpoint_context()?;
            let native =
                self.bytes
                    .as_ref()
                    .ok_or(Error::Rejected(crate::RejectionReason::Persistence(
                        crate::PersistenceRejection::CapturedNativeStateAbsent,
                    )))?;
            let write = |writer: &mut record::Writer<'_>| {
                self.write_checkpoint_with_native(
                    budget,
                    limits,
                    &context,
                    native.as_slice(),
                    writer,
                )
            };
            let size = record::encoded_size(limits, &write)?;
            // The source is already resident. Admit the complete new export,
            // including its metadata, before materializing any second copy.
            let retained = self.retained_bytes(budget)?;
            let (mut bytes, credit) = Buffer::with_metadata_retained(
                budget,
                size,
                std::mem::size_of::<NativeStateRecord>(),
                Some(&retained),
                || Ok(()),
            )?;
            record::encode_into(record::Kind::Saved, limits, &mut bytes, write)?;
            let parsed = record::SavedRecord::read(bytes.as_slice(), limits)?;
            parsed.context.check(&context)?;
            Ok(NativeStateRecord {
                bytes,
                _credit: credit,
            })
        })();
        result.map_err(|error| StateExportFailure { error, state: self })
    }
}
impl AdvancedSession {
    /// Import a service-authenticated native checkpoint without native IO.
    /// References must already be admitted in this destination. Structural and
    /// native identity matches do not prove secret-key continuity. The caller
    /// chooses the restoration keys; the module decides their native usability.
    ///
    /// Always returns Imported provenance, including after later recapture.
    /// Native restoration is separate: start_state_restore and its poll perform
    /// session-state inspection and one explicit C_SetOperationState attempt.
    /// Their native refusal is retained; neither fresh decryption nor another key is retried.
    /// The input record is consumed even when this import is refused. Its external
    /// assertion covers provenance and exclusive continuation ownership.
    pub fn import_state(
        &self,
        record: CallerAssertedAuthenticatedRecord,
        keys: StateRestoreKeys<'_>,
    ) -> Result<SavedOperationState> {
        self.session.inner.module_binding.persistent_digest()?;
        let r = record::SavedRecord::read(record.bytes.as_slice(), record.limits)?;
        let progress = crate::session::AdmissionProgress::default()
            .retaining(record.retained_bytes(&self.session.inner.symmetric_budget)?)?;
        let authentication = {
            let access = self
                .session
                .advanced_access_progress(crate::session::CleanupAdmission::Ordinary, &progress)?;
            r.context
                .check_destination_binding(&self.session.inner, &self.session.snapshot)?;
            for key in [keys.encryption, keys.authentication].into_iter().flatten() {
                self.session
                    .native_object_handle(&access, key.reference.managed())?;
            }
            self.session.snapshot.authentication_stamp()
        };
        let session_state = r.context.required_session_state()?;
        let mut readers = keys::restoration::Prepared::imported(
            &self.session,
            r.descriptor,
            &r.messages,
            keys,
            &progress,
            authentication,
        )?;
        // The recipe owns its borrowed graph description; it does not borrow
        // the mutable destination that acquires roles after resource preparation.
        let initialization = readers.initialization_plan();
        let ((prepared, credit, bytes), _access, prepared_readers) =
            readers.prepare_with(&self.session, &progress, authentication, |key_plan| {
                let recipe = if let Some(initialization) = initialization {
                    let Some(crate::StateRestoreKey {
                        reference: crate::StateKeyReference::NativeMessages { parameters, .. },
                        ..
                    }) = keys.authentication
                    else {
                        return Err(Error::Rejected(crate::RejectionReason::Persistence(
                            crate::PersistenceRejection::NativeMessageDestinationRequired,
                        )));
                    };
                    reconstruction::Recipe::native_checkpoint(
                        &self.session,
                        r.descriptor,
                        &r.keys,
                        &r.messages,
                        r.validation.as_ref(),
                        record.limits,
                        self.session.inner.crypto_options.limits,
                        initialization,
                        parameters,
                    )?
                } else {
                    reconstruction::Recipe::checkpoint(
                        r.descriptor,
                        &r.keys,
                        &r.messages,
                        r.validation.as_ref(),
                        record.limits,
                        self.session.inner.crypto_options.limits,
                    )?
                };
                let resources = reconstruction::resources::Resources::prepare_with_key_storage(
                    &self.session,
                    &progress,
                    recipe,
                    Some(r.native.len()),
                    None,
                    std::mem::size_of::<SavedOperationState>(),
                    key_plan,
                    authentication,
                )?;
                let prepared = resources.continuation;
                let credit = resources.metadata;
                let mut bytes = resources.native.ok_or(Error::Rejected(
                    crate::RejectionReason::Persistence(
                        crate::PersistenceRejection::ImportNativeStorageAbsent,
                    ),
                ))?;
                bytes.as_mut().copy_from_slice(r.native);
                Ok(((prepared, credit, bytes), resources.key_storage))
            })?;
        let mut prepared = Some(prepared);
        let mut bound;
        let mut bound_candidate = None;
        let mut prepared_readers = prepared_readers;
        let _access = _access;
        self.session
            .snapshot
            .check_authentication_unchanged(authentication)?;
        r.context
            .check_destination_binding(&self.session.inner, &self.session.snapshot)?;
        bound = Some(prepared_readers.bind(keys, |permits| {
            BoundKeys::from_record_retained(
                &self.session,
                r.descriptor,
                &r.keys,
                &r.messages,
                keys,
                permits,
                &mut bound_candidate,
            )
        })?);
        let continuation =
            reconstruction::PreparedContinuation::bind_retained(&mut prepared, &mut bound)?;
        Ok(SavedOperationState {
            provenance: StateProvenance::Imported,
            owner: Arc::downgrade(&self.session.inner),
            snapshot: self.session.snapshot.clone(),
            authentication: self.session.snapshot.authentication_stamp(),
            session_state,
            bytes: Some(bytes),
            continuation,
            _credit: credit,
        })
    }
}
impl OperationTicket {
    /// Provenance of a restored/recovered state; None for a newly started plan.
    /// Retained after completion; not a certification or archive-authentication
    /// verdict. Imported provenance is never promoted by local recapture.
    pub fn state_provenance(&self) -> Option<StateProvenance> {
        self.state_provenance
    }
}
