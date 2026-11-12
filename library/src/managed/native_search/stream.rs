// SPDX-License-Identifier: Apache-2.0
//! One resident native search, with publication and catalogue ownership per batch.
use super::*;
use std::{cell::Cell, num::NonZeroUsize};

mod preparation;
mod publication;

/// Native-order object iteration with a caller-sized cache.
///
/// Creation copies the template and calls FindObjectsInit once. Each cache
/// refill calls FindObjects once; a short nonempty batch does not imply that
/// the search has ended. No attribute read or full-result collection is needed.
/// Returned references have independent lifetimes and remain subject to the
/// ordinary session, authentication and object invalidation rules.
///
/// Call [`Self::finish`] to observe cleanup errors. Drop makes one nonwaiting
/// admission attempt; an admitted native Final remains a synchronous call.
/// If completion is unproven, session recovery retains native
/// storage and the session cannot admit further ordinary work before close.
/// Dropping references or the iterator never destroys a native object.
pub struct NativeObjectIterator<'session> {
    session: &'session Session,
    cursor: Option<Cursor<'session>>,
    cache: Option<Cache>,
    // Kept outside Cursor: retiring native storage cannot release a returned
    // error's charge before the enclosing public invocation returns.
    diagnostics: Option<StreamDiagnostics>,
}

/// Terminal iteration failure and explicit finish are distinct stages. A failed
/// finish may be retried or followed by next, so it cannot consume the terminal
/// failure reserve. Each diagnostic retains its own credit after taking leaves.
struct StreamDiagnostics {
    failure: crate::error::PreparedCleanupDiagnostic,
    retirement: crate::error::PreparedCleanupDiagnostic,
    finishing: crate::error::PreparedCleanupDiagnostic,
}
impl StreamDiagnostics {
    fn allocation_bytes() -> usize {
        3 * crate::error::PreparedCleanupDiagnostic::allocation_bytes()
    }

    fn prepare(prepaid: &mut Credit) -> Result<Self> {
        Ok(Self {
            failure: crate::error::PreparedCleanupDiagnostic::prepare(prepaid)?,
            retirement: crate::error::PreparedCleanupDiagnostic::prepare(prepaid)?,
            finishing: crate::error::PreparedCleanupDiagnostic::prepare(prepaid)?,
        })
    }
}

struct Cache {
    objects: std::vec::IntoIter<NativeObjectRef>,
    // The vector allocation outlives every yielded element still in its cache.
    _credit: Credit,
}

struct Cursor<'session> {
    session: &'session Session,
    waiter: Waiting<'session>,
    epoch: u64,
    pending: Cell<bool>,
}

impl Drop for Cursor<'_> {
    fn drop(&mut self) {
        // Detach terminal storage before Waiting can run maintenance under
        // session possession. Pending storage stays resident until proven close.
        // This is metadata-only: Drop never gains native-call authority here.
        let _ = self.retire();
        let _withdrawal = search::SearchWithdrawal::new(self.session, &self.pending);
    }
}

impl Cursor<'_> {
    /// Called only outside session possession. The registry serializes this
    /// terminal metadata check with owner mutation; it reads no native handle.
    fn retire(&self) -> Result<bool> {
        self.pending.set(true);
        match self
            .session
            .entry
            .recovery
            .observations
            .retire_native_search(&self.waiter.coordination)?
        {
            crate::session::recovery::observations::SearchRetirement::Pending => Ok(false),
            crate::session::recovery::observations::SearchRetirement::Returned(retired) => {
                drop(retired);
                self.pending.set(false);
                Ok(true)
            }
            crate::session::recovery::observations::SearchRetirement::Absent => {
                self.pending.set(false);
                Ok(true)
            }
        }
    }
}

enum Batch {
    Idle,
    Reading(InventoryGuard),
    Publishing {
        inventory: InventoryGuard,
        matches: AllMatches,
    },
}

pub(crate) struct NativeSearchStreamOwner {
    search: SearchOwner,
    batch: Batch,
    _credit: Credit,
}

impl NativeSearchStreamOwner {
    pub(crate) fn pending(&self) -> bool {
        self.search.pending()
    }

    pub(crate) fn search_claimed(&self) -> bool {
        self.search.claimed()
    }
}

impl Session {
    /// Start one native search and retrieve references in bounded batches.
    ///
    /// The exact template preserves omission, empty values, order and repeated
    /// attributes. `batch_size` limits each native request, not the total number
    /// of objects. The caller's current resource/session admission applies to
    /// each method invocation, including publication of the complete next batch.
    /// Retaining earlier references can consume the caller's reference quota.
    /// No catalogue exclusion is held while caller code consumes a ready batch.
    pub fn iter_native_objects<'session, 'input>(
        &'session self,
        template: &'input [AttributeInput<'input>],
        limits: AttributeTemplateLimits,
        batch_size: NonZeroUsize,
    ) -> Result<NativeObjectIterator<'session>> {
        preparation::start(self, template, limits, batch_size)
    }
}

impl NativeObjectIterator<'_> {
    /// Finish this search and discard unconsumed cached references.
    ///
    /// A refusal before cleanup leaves the cursor available for another
    /// explicit attempt. An uncertain native Final is never repeated; its
    /// error leaves storage in session recovery until native close is proven.
    /// Calling finish on an already finished iterator performs no native call.
    pub fn finish(&mut self) -> Result<()> {
        let Some(cursor) = &self.cursor else {
            return Ok(());
        };
        let diagnostics = self
            .diagnostics
            .as_mut()
            .expect("active iterator diagnostics");
        // A previous finish invocation has already transferred its error to the
        // caller. Refill under the existing credit, before any possession or C;
        // allocation failure leaves this cursor available for an explicit retry.
        diagnostics.finishing.replenish()?;
        let result = finish_result(finish_cursor(cursor, false), &mut diagnostics.finishing);
        let _retired_diagnostics = if !cursor.pending.get() {
            self.cache = None;
            self.cursor = None;
            self.diagnostics.take()
        } else {
            None
        };
        result
    }

    fn fail(&mut self, error: Error, diagnostics: &mut StreamDiagnostics) -> Error {
        let diagnostic = diagnostics.failure.take(error);
        let cleanup = self
            .cursor
            .as_ref()
            .map(|cursor| finish_result(finish_cursor(cursor, true), &mut diagnostics.retirement));
        let error = diagnostic.finish_sequence(cleanup.and_then(Result::err));
        // Cleanup and terminal node extraction have released all possession.
        // A failed native cleanup still leaves its owner in session recovery.
        self.cache = None;
        self.cursor = None;
        error
    }
}

impl Iterator for NativeObjectIterator<'_> {
    type Item = Result<NativeObjectRef>;

    fn next(&mut self) -> Option<Self::Item> {
        let cursor = self.cursor.as_ref()?;
        if let Err(error) = cursor.waiter.check() {
            let mut diagnostics = self
                .diagnostics
                .take()
                .expect("active iterator diagnostics");
            return Some(Err(self.fail(error, &mut diagnostics)));
        }
        if let Some(cache) = &mut self.cache {
            if let Some(object) = cache.objects.next() {
                return Some(Ok(object));
            }
        }
        // Release the old vector and its credit before admitting a new batch.
        self.cache = None;
        match publication::fetch(self.session, cursor) {
            Ok(Some(matches)) => {
                let mut cache = Cache {
                    objects: matches.objects.into_iter(),
                    _credit: matches._credit,
                };
                let object = cache.objects.next();
                self.cache = Some(cache);
                object.map(Ok)
            }
            Ok(None) => {
                self.cursor = None;
                self.diagnostics = None;
                None
            }
            Err(error) => {
                let mut diagnostics = self
                    .diagnostics
                    .take()
                    .expect("active iterator diagnostics");
                Some(Err(self.fail(error, &mut diagnostics)))
            }
        }
    }
}

impl std::iter::FusedIterator for NativeObjectIterator<'_> {}

impl Drop for NativeObjectIterator<'_> {
    fn drop(&mut self) {
        if let Some(cursor) = &self.cursor {
            let _ = finish_cursor(cursor, true);
        }
    }
}

fn finish_cursor(cursor: &Cursor<'_>, nonwaiting: bool) -> (Result<()>, Result<()>) {
    let session = cursor.session;
    let result = (|| {
        let progress = crate::session::AdmissionProgress::default();
        let access = if nonwaiting {
            // No renewal of an expired deadline and no native authority from
            // the metadata-only retirement performed after this scope.
            session.try_advanced_access_progress(&progress)?
        } else {
            session.advanced_access()?
        };
        let slot = session
            .entry
            .recovery
            .observations
            .get(&cursor.waiter.coordination)?;
        let mut payload = slot.owner.lock().map_err(|_| Error::Poisoned)?;
        let owner = payload
            .as_mut()
            .ok_or(Error::Rejected(crate::RejectionReason::ObjectSearch(
                crate::ObjectSearchRejection::NativeSearchStreamOwnerAbsent,
            )))?
            .native_search_stream_mut()?;
        owner.search.finish(session, &access)
    })();
    // All guards, including those on an admission error, have left scope.
    // Detachment also handles a registered Init that never reached native code.
    // The complete node, template, identities and credits retire together here.
    let retirement = cursor.retire().and_then(|retired| {
        if retired {
            Ok(())
        } else {
            Err(Error::Rejected(crate::RejectionReason::ObjectSearch(
                crate::ObjectSearchRejection::SearchStreamStillPending,
            )))
        }
    });
    (result, retirement)
}

// Drop discards the two outcomes without allocating an error chain. Public
// finish and terminal failure compose them using their distinct prepaid slots.
fn finish_result(
    outcomes: (Result<()>, Result<()>),
    diagnostic: &mut crate::error::PreparedCleanupDiagnostic,
) -> Result<()> {
    match outcomes {
        (Err(error), Err(cleanup)) => Err(diagnostic.take(error).finish_sequence(Some(cleanup))),
        (Err(error), Ok(())) | (Ok(()), Err(error)) => Err(error),
        (Ok(()), Ok(())) => Ok(()),
    }
}
