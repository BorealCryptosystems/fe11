// SPDX-License-Identifier: Apache-2.0
//! Parsing and the consuming application's authentication assertion are distinct.
use super::record;
use crate::{
    mechanism_extension::graph::snapshot::{SnapshotIndex, SnapshotRecipe},
    symmetric::memory::{Buffer, Credit},
    Result,
};

/// Caller-selected bounds for canonical record parsing and export.
/// These bounds do not change the wire format's representational constraints.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct RecordLimits {
    /// Maximum complete envelope size in bytes.
    pub bytes: usize,
    /// Maximum number of messages.
    pub messages: usize,
    /// Maximum aggregate fragments, also bounding each individual message.
    pub fragments: usize,
}

impl RecordLimits {
    pub(super) fn checked(self) -> Result<record::Limits> {
        let limits = record::Limits {
            bytes: self.bytes,
            messages: self.messages,
            fragments: self.fragments,
        };
        limits.validate()?;
        Ok(limits)
    }
}

/// Structurally validated, owned sensitive bytes with no authentication claim.
/// This type cannot be passed to restoration or recovery operations.
pub struct ParsedRecord {
    bytes: Buffer,
    limits: record::Limits,
    _credit: Credit,
}

impl ParsedRecord {
    /// Copy and parse the current BPKIOP09 envelope under explicit bounds.
    /// Other envelope versions are rejected. No provider call or authentication
    /// occurs. Copies outside this owner are the caller's responsibility.
    /// Parsing validates the representation, not application authorization.
    pub fn parse(module: &crate::Module, bytes: &[u8], limits: RecordLimits) -> Result<Self> {
        let limits = limits.checked()?;
        record::decode(bytes, limits)?;
        // Traverse only declared graph sections. Arbitrary bytes containing an
        // FG01 prefix are never interpreted as a graph. This first pass checks
        // structure and computes the reusable scratch peak without allocating.
        let entries = std::cell::Cell::new(0usize);
        super::persistence::validate_import_with(
            bytes,
            limits,
            Some(&|graph| {
                let (blocks, pointers) = SnapshotRecipe::decode(graph)?.index_counts();
                let count = blocks.checked_add(pointers).ok_or(crate::Error::Rejected(
                    crate::RejectionReason::Restoration(
                        crate::RestorationRejection::RecordValidationAccounting,
                    ),
                ))?;
                entries.set(entries.get().max(count));
                Ok(())
            }),
        )?;
        let budget = &module.inner.symmetric_budget;
        // The credit follows the owned bytes through the consuming transition.
        let metadata = std::mem::size_of::<Self>()
            .max(std::mem::size_of::<CallerAssertedAuthenticatedRecord>());
        let mut scratch_bytes = SnapshotIndex::required_bytes(entries.get())?;
        loop {
            let combined = metadata
                .checked_add(scratch_bytes)
                .ok_or(crate::Error::Rejected(crate::RejectionReason::Restoration(
                    crate::RestorationRejection::RecordValidationAccounting,
                )))?;
            let (mut owned, mut credit) =
                Buffer::with_metadata(budget, bytes.len(), combined, || Ok(()))?;
            let scratch = SnapshotIndex::allocate(entries.get())?;
            let actual = scratch.allocated_bytes()?;
            if actual > scratch_bytes {
                drop(scratch);
                drop(owned);
                drop(credit);
                scratch_bytes = actual;
                continue;
            }
            credit.release(scratch_bytes - actual);
            owned.as_mut().copy_from_slice(bytes);
            let scratch = std::cell::RefCell::new(scratch);
            super::persistence::validate_import_with(
                owned.as_slice(),
                limits,
                Some(&|graph| scratch.borrow_mut().validate(graph)),
            )?;
            // Full semantic validation precedes publication and authentication.
            // Scratch offsets are public metadata and no longer needed; only
            // the immutable archive and its owner charge survive this boundary.
            drop(scratch);
            credit.release(actual);
            return Ok(Self {
                bytes: owned,
                limits,
                _credit: credit,
            });
        }
    }

    /// Borrow the exact immutable bytes that a later assertion will cover.
    pub fn as_bytes(&self) -> &[u8] {
        self.bytes.as_slice()
    }

    /// Ask the consuming application to assert the integrity and provenance of
    /// these exact bytes, including the recorded native results and completion flags.
    ///
    /// Resuming a continuation additionally requires exclusive ownership: its
    /// previous owner cannot still advance it, and an obsolete checkpoint cannot
    /// silently replay an effect already committed. An archive containing only a
    /// completed result does not imply that an old worker exists. A checksum,
    /// timeout, token serial or CKA_ID does not establish this provenance.
    ///
    /// Fe11 does not require a business command, authorized destination, temporal
    /// freshness policy or mathematical key certificate. The application chooses
    /// restoration keys; native refusals are preserved. The local output cursor
    /// is not a durable external acknowledgement or an exactly-once delivery promise.
    ///
    /// For a detached job, exclusion means exclusive ownership after successful
    /// GetID, not termination of the job to join. Never restart that job.
    ///
    /// This callback is an external trust assertion, not a cryptographic
    /// verifier supplied by Fe11. There is no default assertion. The owned bytes
    /// are immutably borrowed during the call and moved unchanged on success.
    /// Failure consumes and erases this owner's bytes without native effects.
    pub fn assert_authenticated(
        self,
        assertion: impl FnOnce(&[u8]) -> Result<()>,
    ) -> Result<CallerAssertedAuthenticatedRecord> {
        assertion(self.bytes.as_slice())?;
        Ok(CallerAssertedAuthenticatedRecord {
            bytes: self.bytes,
            limits: self.limits,
            _credit: self._credit,
        })
    }
}

#[doc = include_str!("../../docs/api/advanced/record_import/CallerAssertedAuthenticatedRecord.md")]
pub struct CallerAssertedAuthenticatedRecord {
    pub(super) bytes: Buffer,
    pub(super) limits: record::Limits,
    _credit: Credit,
}
impl CallerAssertedAuthenticatedRecord {
    pub(super) fn retained_bytes(
        &self,
        destination: &std::sync::Arc<crate::symmetric::memory::Budget>,
    ) -> Result<crate::symmetric::memory::RetainedBytes> {
        crate::symmetric::memory::RetainedBytes::measure(destination, |retained| {
            self.bytes.retain_credit(retained)?;
            retained.add_credit(&self._credit)
        })
    }
}
