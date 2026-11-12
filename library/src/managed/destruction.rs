// SPDX-License-Identifier: Apache-2.0
use super::*;
mod preparation;
mod prepared;
mod resident;
mod revocation_set;
pub(crate) use preparation::{prepare_destruction, DestructionDiagnostic};
pub(crate) use prepared::{
    PreparedRevocations, RevocationRetention, RevocationRetentions, RevocationShape,
    RevocationStorage,
};
pub(crate) use resident::DestructionOwner;
pub(crate) use revocation_set::RevocationSetPlan;

#[derive(Default)]
enum DestroyProgress {
    #[default]
    BeforeDispatch,
    InFlight,
    Returned,
    Uncertain,
}
impl DestroyProgress {
    fn pending(&self) -> bool {
        matches!(self, Self::InFlight | Self::Uncertain)
    }
}

// This guard borrows no native-addressable storage. It only withdraws further
// native access if Rust unwinds before a return can establish the outcome.
struct DispatchWithdrawal<'a> {
    session: &'a Session,
    state: &'a State,
    returned: bool,
}
impl Drop for DispatchWithdrawal<'_> {
    fn drop(&mut self) {
        if !self.returned {
            self.state.native.mark_uncertain();
            self.session.poison(self.state);
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum DestroyOutcome {
    Destroyed,
    Refused(CK_RV),
    Uncertain(CK_RV),
}

impl From<CK_RV> for DestroyOutcome {
    fn from(rv: CK_RV) -> Self {
        match rv {
            CKR_OK => Self::Destroyed,
            refusal
                if crate::native_return::MutationCall::Destroy.definite_object_refusal(refusal) =>
            {
                Self::Refused(refusal)
            }
            other => Self::Uncertain(other),
        }
    }
}

// Collected before dispatch while the destination and its activity are exclusive.
// No registry lock, allocation or context lookup is needed to revoke afterwards.
pub(crate) struct RevocationTargets {
    objects: Vec<Arc<crate::managed::NativeIdentity>>,
    managed: Vec<Arc<NativeIdentity>>,
    _storage_credit: Option<crate::symmetric::memory::Credit>,
}

impl RevocationTargets {
    fn revoke(&self) {
        for alias in &self.objects {
            alias.revoked.store(true, Ordering::Release);
        }
        for alias in &self.managed {
            alias.revoked.store(true, Ordering::Release);
        }
    }

    pub(crate) fn arm(self) -> PendingRevocation {
        PendingRevocation(self)
    }
}

pub(super) fn revoke_resource(state: &State, resource: ResourceIdentity) -> Result<()> {
    // Returned handles are unknown before C. Visit the current aliases without
    // allocating a private snapshot under possession or holding Entries during
    // an identity's last Drop. New publication follows this retirement.
    let result = (|| {
        let revoke = |alias: &NativeIdentity| {
            if alias.resource().native() == resource.native() {
                alias.revoked.store(true, Ordering::Release);
            }
        };
        state.objects.visit_native_identities(revoke)?;
        state.managed.visit_native_identities(revoke)
    })();
    if result.is_err() {
        withdraw_token(state, resource.slot);
    }
    result
}

/// A creation returning an existing input handle did not create an owned
/// output. Retire its current aliases without a stale pre-observation snapshot;
/// any registry failure remains a post-native uncertainty, never plain refusal.
/// The caller supplies a pre-admitted marker retained by its public invocation.
pub(crate) fn revoke_returned_source(
    state: &State,
    resource: ResourceIdentity,
    mark: impl FnOnce(Error) -> Error,
) -> Result<()> {
    revoke_resource(state, resource).map_err(mark)
}

// Arming transfers the prepared targets into an owner that also covers unwind.
// A refusal disarms by dropping ownership, never by resetting a revoked bit.
pub(crate) struct PendingRevocation(RevocationTargets);

impl PendingRevocation {
    // Caller established a completed, empty SetAttributeValue with unchanged
    // inputs. Discard pending targets; never reactivate an already revoked alias.
    pub(super) fn preserve_unmodified(mut self) {
        self.0.objects.clear();
        self.0.managed.clear();
    }
    pub(super) fn finish(mut self, call: crate::native_return::MutationCall, rv: CK_RV) {
        if call.definite_object_refusal(rv) {
            self.0.objects.clear();
            self.0.managed.clear();
        }
    }
}

impl Drop for PendingRevocation {
    fn drop(&mut self) {
        self.0.revoke();
    }
}

impl Session {
    /// Destroy an exact reference, letting the token enforce its permission.
    ///
    /// Native ACTION_PROHIBITED, SESSION_READ_ONLY and TOKEN_WRITE_PROTECTED
    /// preserve references and retain the native refusal.
    /// Success or an uncertain result revokes this native handle across application sessions.
    /// Application identifiers do not prove alias identity across sessions.
    /// A denied post-success report returns OperationCompleted with its cause;
    /// destruction is not undone and aliases remain revoked.
    pub fn destroy_managed(
        &self,
        object: &ManagedObjectRef,
        plan: crate::ObjectReferencePlan,
        content: crate::ContentObservation,
    ) -> Result<crate::ObjectReferenceReport> {
        let epoch = self.snapshot.authentication_stamp();
        let progress = crate::session::AdmissionProgress::default();
        {
            let access = self.access_progress_at_epoch(&progress, epoch)?;
            self.managed_handle(&access, object)?;
            access.native.table.C_DestroyObject.ok_or(Error::Rejected(
                crate::RejectionReason::ObjectObservation(
                    crate::ObjectObservationRejection::CDestroyObjectUnavailable,
                ),
            ))?;
        }
        resident::destroy(self, object, plan, content, &progress, epoch)
    }

    /// Destroy an exact native owner without reading its attributes first.
    /// The module decides permissions. A native refusal keeps the object; a
    /// successful or uncertain destruction revokes aliases across sessions.
    pub fn destroy_native_object(&self, object: &NativeObjectRef) -> Result<()> {
        if !Arc::ptr_eq(&self.inner, &object.inner) {
            return Err(Error::Rejected(crate::RejectionReason::ObjectReferences(
                crate::ObjectReferencesRejection::ForeignNativeObject,
            )));
        }
        let epoch = self.snapshot.authentication_stamp();
        let progress = crate::session::AdmissionProgress::default();
        // Destruction targets an existing native identity, not a destination
        // for a new object. Its writer and alias revocations exclude conflicting
        // use without reserving unrelated identifiers across the whole token.
        let (mut diagnostic, targets, reservation, access) =
            prepare_destruction(self, &[], object, &progress, epoch, |access| {
                self.native_identity_handle(access, &object.identity)
                    .map(|_| ())
            })?;
        self.native_identity_handle(&access, &object.identity)?;
        let completed = self.destroy_resource_reserved(
            &access,
            self.entry(&access)?.handle,
            object.identity.resource(),
            object.identity.activity()?,
            &reservation,
            targets,
            diagnostic.take()?,
        )?;
        completed.finish(object.identity.access().result(self, &access, Ok(())))
    }

    pub(crate) fn destroy_resource_reserved(
        &self,
        state: &State,
        session_handle: CK_SESSION_HANDLE,
        resource: ResourceIdentity,
        activity: &Arc<crate::registry::Activity>,
        reservation: &Reservation,
        targets: RevocationTargets,
        completed: crate::error::CompletionDiagnostic,
    ) -> Result<crate::error::CompletionDiagnostic> {
        self.destroy_resource_with(
            state,
            session_handle,
            resource,
            targets,
            completed,
            &mut DestroyProgress::BeforeDispatch,
            |resource| reservation.forget_object(self, resource, activity),
        )
    }

    fn destroy_resource_with(
        &self,
        state: &State,
        session_handle: CK_SESSION_HANDLE,
        resource: ResourceIdentity,
        targets: RevocationTargets,
        completed: crate::error::CompletionDiagnostic,
        progress: &mut DestroyProgress,
        forget: impl FnOnce(ResourceIdentity) -> Result<()>,
    ) -> Result<crate::error::CompletionDiagnostic> {
        let entry = self.entry(state)?;
        if resource.session != self.uid
            || resource.slot != entry.slot
            || resource.generation != self.snapshot.generation
            || session_handle != entry.handle
            || resource.handle == CK_INVALID_HANDLE
        {
            return Err(Error::Rejected(crate::RejectionReason::ObjectReferences(
                crate::ObjectReferencesRejection::ForeignDestructionResource,
            )));
        }
        let call = state.native.table.C_DestroyObject.ok_or(Error::Rejected(
            crate::RejectionReason::ObjectObservation(
                crate::ObjectObservationRejection::CDestroyObjectUnavailable,
            ),
        ))?;

        state.native.record("C_DestroyObject")?;
        let pending = targets.arm();
        // This ABI receives handles by value, no borrowed native-addressable
        // storage. A pending/GENERAL return still revokes aliases and withdraws
        // native access; Native/LoadedImage cannot unload an unfinalized image.
        // SAFETY: callers validate this session-bound resource while holding
        // the lifecycle, session, destination and object-activity guards.
        *progress = DestroyProgress::InFlight;
        let mut withdrawal = DispatchWithdrawal {
            session: self,
            state,
            returned: false,
        };
        let rv = unsafe { call(session_handle, resource.handle) };
        withdrawal.returned = true;
        if rv == CKR_PENDING {
            // Handles are passed by value, but native execution can still be
            // pending after Rust returns. Keep that proof beyond this frame.
            entry.recovery.mark_pending_call();
        }
        let outcome = DestroyOutcome::from(rv);
        *progress = if matches!(outcome, DestroyOutcome::Uncertain(_)) {
            DestroyProgress::Uncertain
        } else {
            DestroyProgress::Returned
        };
        pending.finish(crate::native_return::MutationCall::Destroy, rv);
        match outcome {
            DestroyOutcome::Destroyed => {
                if let Err(cause) = forget(resource) {
                    return completed.finish(Err(cause));
                }
                Ok(completed)
            }
            DestroyOutcome::Refused(rv) => {
                crate::error::check(rv, "C_DestroyObject", false).map(|_| unreachable!())
            }
            DestroyOutcome::Uncertain(rv) => self
                .mutation_result(state, crate::native_return::MutationCall::Destroy, rv)
                .map(|_| unreachable!()),
        }
    }
}

impl crate::AdvancedSession {
    /// Explicit synchronous destruction of an unobserved native owner.
    pub fn destroy_native_object(&self, object: &NativeObjectRef) -> Result<()> {
        self.session.destroy_native_object(object)
    }
}

impl crate::symmetric::memory::RetainedStorage for RevocationTargets {
    fn retain_credits(&self, retained: &mut crate::symmetric::memory::RetainedBytes) -> Result<()> {
        self._storage_credit.retain_credits(retained)?;
        Ok(())
    }
}
