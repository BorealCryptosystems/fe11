// SPDX-License-Identifier: Apache-2.0

use crate::{
    error::check,
    module::{discover_selected, discover_slot, Inner, State, TokenSnapshot},
    Capabilities, Error, Module, Result, SecretPin, Session,
};
use fe11_sys::*;
use std::sync::{atomic::Ordering, Arc};

mod discovery_admission;

/// Opaque observed administrative target, tied to one module and token generation.
/// Holding it does not prevent administration of another token.
pub struct TokenAdministrationTarget {
    inner: Arc<Inner>,
    snapshot: Arc<TokenSnapshot>,
}
impl TokenAdministrationTarget {
    /// Historical observation used to select the target explicitly.
    pub fn capabilities(&self) -> &Capabilities {
        &self.snapshot.capabilities
    }
}
// Captured generations only: a late failure must not withdraw a replacement.
fn discovery_failure(s: &State, observed: &[Arc<TokenSnapshot>], slot: CK_SLOT_ID, error: &Error) {
    if let Error::Native { code, .. } = error {
        let scope = crate::native_return::diagnostic_context_scope(*code);
        if let Some(token) = observed
            .iter()
            .find(|t| t.capabilities.identity.slot == slot as u64)
        {
            s.apply_failure_scope(token, scope);
        }
    }
}

fn pin_result(
    s: &State,
    entry: &crate::module::SessionEntry,
    call: crate::native_return::PinCall,
    rv: CK_RV,
) -> Result<()> {
    let scope = call.scope(rv);
    if scope == crate::native_return::FailureScope::Session {
        entry.poisoned.store(true, Ordering::Release);
    }
    s.apply_session_failure(entry, rv, scope);
    // This mutation may be refused for its required role. That does not prove
    // token-wide logout and must not revoke another session's authority.
    check(rv, call.function(), true)
}
// PIN retry/lock/change indicators are operational observations, not token identity.
// Keep all other flags, PIN bounds and mechanism properties in stable comparison.
pub(crate) fn same_capabilities(a: &Capabilities, b: &Capabilities) -> bool {
    let volatile = (CKF_USER_PIN_COUNT_LOW
        | CKF_USER_PIN_FINAL_TRY
        | CKF_USER_PIN_LOCKED
        | CKF_USER_PIN_TO_BE_CHANGED
        | CKF_SO_PIN_COUNT_LOW
        | CKF_SO_PIN_FINAL_TRY
        | CKF_SO_PIN_LOCKED
        | CKF_SO_PIN_TO_BE_CHANGED) as u64;
    a.identity == b.identity
        && a.label == b.label
        && (a.flags & !volatile) == (b.flags & !volatile)
        && a.maximum_sessions == b.maximum_sessions
        && a.maximum_read_write_sessions == b.maximum_read_write_sessions
        && a.mechanisms == b.mechanisms
        && a.minimum_pin_length == b.minimum_pin_length
        && a.maximum_pin_length == b.maximum_pin_length
}
impl Module {
    /// Return initial or explicitly refreshed administrative targets, including blank tokens.
    /// This method does not query native capabilities.
    pub fn administration_targets(&self) -> Result<Vec<TokenAdministrationTarget>> {
        let s = self.inner.read()?;
        let registry = s.token_registry()?;
        Ok(registry
            .tokens
            .iter()
            .filter(|t| t.admission_available())
            .map(|snapshot| TokenAdministrationTarget {
                inner: self.inner.clone(),
                snapshot: snapshot.clone(),
            })
            .collect())
    }
    /// Explicitly rediscover after administration or a slot change. No automatic fallback.
    /// Changed tokens with active sessions stay stale and must be closed first.
    /// Other tokens are published even if this returns the existing close-required error;
    /// use administration_targets/select to use them. No blocked token is reactivated.
    /// PIN retry/lock/change flags do not change generations. Capabilities on an existing
    /// context remain its initial immutable observation, not a current health report.
    pub fn refresh_tokens(&self) -> Result<Vec<Capabilities>> {
        let report = self.refresh_tokens_report(crate::DiscoverySelection::AllPresentSlots)?;
        if let Some(failure) = report.failures.into_iter().next() {
            return Err(failure.error);
        }
        Ok(report.tokens)
    }
    /// Refresh an explicit scope and retain each local observation/publication
    /// failure. Unselected slots are unchanged; failed observations do not
    /// establish absence. Successful independent replacements are published.
    /// A contradicted token context loses ordinary admission immediately. Its
    /// replacement still waits for unresolved owners; failures remain in the report.
    pub fn refresh_tokens_report(
        &self,
        selection: crate::DiscoverySelection,
    ) -> Result<crate::DiscoveryReport> {
        let s = self.inner.read()?;
        let selected = |slot: u64| match &selection {
            crate::DiscoverySelection::AllPresentSlots => true,
            crate::DiscoverySelection::Slots(slots) => slots.contains(&slot),
            crate::DiscoverySelection::Deferred => false,
        };
        let (mut revision, next_generation, observed, epochs) = {
            let r = s.token_registry()?;
            let mut epochs = Vec::new();
            epochs.try_reserve_exact(r.tokens.len()).map_err(|_| {
                Error::Rejected(crate::RejectionReason::TokenAdministration(
                    crate::TokenAdministrationRejection::TokenRegistryAllocation,
                ))
            })?;
            epochs.extend(
                r.tokens
                    .iter()
                    .map(|t| t.domain.foreign_epoch.load(Ordering::Acquire)),
            );
            (r.revision, r.next_generation, r.tokens.clone(), epochs)
        };
        // Shared observation excludes initialization/login while native discovery
        // runs, but allows ongoing crypto. The registry is never held across C.
        let observation = observed
            .iter()
            .filter(|token| selected(token.capabilities.identity.slot))
            .map(|t| t.observation_activity())
            .collect::<Result<Vec<_>>>()?;
        crate::module::Inner::validate(&s)?;
        if s.token_registry()?.revision != revision {
            return Err(Error::Busy(crate::BusyReason::TokenAdministration(
                crate::TokenAdministrationBusy::TokenRegistryChanged,
            )));
        }
        let mut report = discover_selected(
            &s.native,
            self.inner.limits,
            selection.clone(),
            &|slot, error| discovery_failure(&s, &observed, slot, error),
        )?;
        let current = &report.tokens;
        let failed = |slot: u64| report.failures.iter().any(|failure| failure.slot == slot);

        // Withdraw stale ordinary admission before waiting for owners or
        // allocating publication storage. Failure to publish a successor must
        // never make an already contradicted observation usable again.
        {
            let mut registry = s.token_registry()?;
            discovery_admission::withdraw(
                &mut registry,
                &mut revision,
                &observed,
                &epochs,
                |old| {
                    selected(old.capabilities.identity.slot)
                        && !failed(old.capabilities.identity.slot)
                        && !current
                            .iter()
                            .any(|c| same_capabilities(c, &old.capabilities))
                },
            )?;
        }
        drop(observation);
        // Native observations are complete and are never replayed. Publication
        // may wait for old owners, so release dispatch/module possession first.
        drop(s);
        let admission = crate::admission_wait::current();
        let (s, blocked, retired, _writers) = loop {
            admission.check_available()?;
            let s = self.inner.read()?;
            if s.token_registry()?.revision != revision {
                return Err(Error::Rejected(
                    crate::RejectionReason::TokenAdministration(
                        crate::TokenAdministrationRejection::TokenRegistryChangedAfterDiscovery,
                    ),
                ));
            }
            let mut wait_for = None;
            let mut blocked = std::collections::HashSet::new();
            let mut retired = Vec::new();
            let mut writers = Vec::new();
            for old in &observed {
                if !selected(old.capabilities.identity.slot)
                    || failed(old.capabilities.identity.slot)
                {
                    continue;
                }
                if !old.admission_available()
                    || !current
                        .iter()
                        .any(|c| same_capabilities(c, &old.capabilities))
                {
                    let slot = old.capabilities.identity.slot as CK_SLOT_ID;
                    match old.maintenance_activity_with_policy(
                        false,
                        &crate::ResourceAdmission::Immediate,
                    ) {
                        Ok(writer) => {
                            writers.push(writer);
                            if !s.session_ledger.refreshable_slot(slot)? {
                                blocked.insert(slot);
                            } else {
                                self.inner.foreign.slot_successor_ready(slot as u64)?;
                                old.invalidate();
                                s.operations.retire_slot_admission(slot as u64)?;
                                // Publication requires full retirement. A blocked
                                // refresh retains the withdrawn snapshot and its
                                // foreign completion authority, never admission.
                                retired.push(old.clone());
                            }
                        }
                        Err(Error::Busy(_)) => {
                            if matches!(admission, crate::ResourceAdmission::WaitUntil { .. })
                                && !crate::notify::in_callback()
                            {
                                wait_for = Some(old);
                                break;
                            }
                            blocked.insert(slot);
                        }
                        Err(e) => {
                            s.native.mark_uncertain();
                            return Err(e);
                        }
                    }
                }
            }
            if let Some(old) = wait_for {
                drop(writers);
                drop(s);
                let ready = old.maintenance_activity(false)?;
                drop(ready);
                continue;
            }
            break (s, blocked, retired, writers);
        };
        let mut next = next_generation;
        let capacity = current
            .len()
            .checked_add(observed.len())
            .ok_or(Error::Rejected(
                crate::RejectionReason::TokenAdministration(
                    crate::TokenAdministrationRejection::TokenRegistryCapacity,
                ),
            ))?;
        let mut snapshots = Vec::new();
        snapshots.try_reserve_exact(capacity).map_err(|_| {
            Error::Rejected(crate::RejectionReason::TokenAdministration(
                crate::TokenAdministrationRejection::TokenRegistryAllocation,
            ))
        })?;
        for cap in current {
            if blocked.contains(&(cap.identity.slot as CK_SLOT_ID)) {
                continue;
            }
            if let Some(old) = observed
                .iter()
                .find(|old| old.admission_available() && same_capabilities(&old.capabilities, cap))
            {
                snapshots.push(old.clone());
            } else {
                next = next.checked_add(1).ok_or(Error::Rejected(
                    crate::RejectionReason::TokenAdministration(
                        crate::TokenAdministrationRejection::TokenGenerationExhausted,
                    ),
                ))?;
                let replacement = match observed
                    .iter()
                    .find(|old| old.capabilities.identity.slot == cap.identity.slot)
                {
                    Some(old) => old.replacement(cap.clone(), next)?,
                    None => TokenSnapshot::with_domain(
                        cap.clone(),
                        next,
                        self.inner.foreign.domain(cap.identity.slot)?,
                    ),
                };
                snapshots.push(Arc::new(replacement));
            }
        }
        snapshots.extend(
            observed
                .iter()
                .filter(|old| {
                    let slot = old.capabilities.identity.slot;
                    !selected(slot) || failed(slot) || blocked.contains(&(slot as CK_SLOT_ID))
                })
                .cloned(),
        );
        // Reserve the failure report before publishing registry changes.
        report.failures.try_reserve(blocked.len()).map_err(|_| {
            Error::Rejected(crate::RejectionReason::TokenAdministration(
                crate::TokenAdministrationRejection::DiscoveryPublicationReportAllocation,
            ))
        })?;
        let admission_notification = s.session_ledger.notify_admission_on_drop();
        {
            let mut r = s.token_registry()?;
            if r.revision != revision {
                return Err(Error::Rejected(
                    crate::RejectionReason::TokenAdministration(
                        crate::TokenAdministrationRejection::TokenRegistryChangedAfterDiscovery,
                    ),
                ));
            }
            r.advance()?;
            for old in &retired {
                old.invalidate();
                old.forget_authentication()?;
            }
            r.tokens = snapshots;
            r.next_generation = next;
        }
        drop(admission_notification);
        // Generation-scoped revocation cannot revoke new aliases published by
        // a concurrently selected replacement after the registry was released.
        for old in retired {
            crate::managed::revoke_generation(
                &s,
                old.capabilities.identity.slot as _,
                old.generation,
            )?;
        }
        for slot in blocked {
            report.failures.push(crate::SlotDiscoveryFailure {
                slot: slot as u64,
                error: Error::Rejected(crate::RejectionReason::TokenAdministration(
                    crate::TokenAdministrationRejection::ChangedTokenSessionsRequireClose,
                )),
            });
        }
        Ok(report)
    }
    /// Initialize a specifically observed blank token. Never called by open/login.
    ///
    /// The application must arrange maintenance with no concurrent sessions on
    /// this token, including other processes. PKCS#11 C_InitToken has undefined
    /// consequences when an existing session is not detected by the module.
    /// Fe11 checks its known sessions; that registry cannot establish the
    /// interprocess condition. Ordinary token use needs no such maintenance.
    /// Shared clients must invoke this through RuntimeOwner::module.
    pub fn initialize_token(
        &self,
        target: &TokenAdministrationTarget,
        so_pin: impl Into<crate::PinRequest>,
        label: &str,
    ) -> Result<()> {
        let mut native_label = [b' '; 32];
        if label.len() > native_label.len() {
            return Err(Error::Rejected(
                crate::RejectionReason::TokenAdministration(
                    crate::TokenAdministrationRejection::TokenLabel,
                ),
            ));
        }
        native_label[..label.len()].copy_from_slice(label.as_bytes());
        let mut diagnostic = None;
        self.initialize_observed(target, so_pin.into(), native_label, false, &mut diagnostic)
    }
    /// Destructively reinitialize an explicitly observed initialized token.
    /// Any native return invalidates the target; reconcile through explicit refresh.
    /// The same cross-process maintenance precondition as initialize_token
    /// applies. Closing this caller's last session alone does not establish it.
    pub fn reinitialize_token(
        &self,
        target: &TokenAdministrationTarget,
        so_pin: impl Into<crate::PinRequest>,
        label: &str,
    ) -> Result<()> {
        let mut native_label = [b' '; 32];
        if label.len() > native_label.len() {
            return Err(Error::Rejected(
                crate::RejectionReason::TokenAdministration(
                    crate::TokenAdministrationRejection::TokenLabel,
                ),
            ));
        }
        native_label[..label.len()].copy_from_slice(label.as_bytes());
        let mut diagnostic = None;
        self.initialize_observed(target, so_pin.into(), native_label, true, &mut diagnostic)
    }
    /// Initialize an observed blank token with exactly the supplied 32 label bytes.
    /// No UTF-8 conversion, trimming or implicit padding is performed.
    /// The lifecycle authority and maintenance preconditions of initialize_token
    /// apply equally to this byte-preserving form.
    pub fn initialize_token_bytes(
        &self,
        target: &TokenAdministrationTarget,
        so_pin: impl Into<crate::PinRequest>,
        label: [u8; 32],
    ) -> Result<()> {
        let mut diagnostic = None;
        self.initialize_observed(target, so_pin.into(), label, false, &mut diagnostic)
    }
    /// Destructively reinitialize an observed token with an exact native label.
    /// The lifecycle authority and maintenance preconditions of initialize_token
    /// apply equally to this byte-preserving form.
    pub fn reinitialize_token_bytes(
        &self,
        target: &TokenAdministrationTarget,
        so_pin: impl Into<crate::PinRequest>,
        label: [u8; 32],
    ) -> Result<()> {
        let mut diagnostic = None;
        self.initialize_observed(target, so_pin.into(), label, true, &mut diagnostic)
    }
    fn initialize_observed(
        &self,
        target: &TokenAdministrationTarget,
        so_pin: crate::PinRequest,
        label: [u8; 32],
        destructive: bool,
        diagnostic_root: &mut Option<crate::error::PreparedCompletion>,
    ) -> Result<()> {
        self.require_lifecycle_owner()?;
        if !Arc::ptr_eq(&self.inner, &target.inner) {
            return Err(Error::Rejected(
                crate::RejectionReason::TokenAdministration(
                    crate::TokenAdministrationRejection::ForeignAdministrativeTarget,
                ),
            ));
        }
        self.inner.check_lifecycle_reentry()?;
        self.inner.foreign.wait_callbacks(
            &self.inner,
            Some(target.snapshot.capabilities.identity.slot),
        )?;
        let pin = crate::pin::PinFrame::new(so_pin);
        type Data = crate::pin::Credited<crate::pin::TokenInitializationFrame>;
        let fixed = std::mem::size_of::<Data>()
            + crate::module::TokenCallFrame::<'_, Data>::allocation_bytes();
        let (prepared, access, _foreign_callbacks) = loop {
            let (prepared, access) =
                crate::module::TokenAccess::prepare(&self.inner, &target.snapshot, false, || {
                    crate::pin::PreparedPins::prepare_with_completion(
                        fixed,
                        [Some(&pin), None],
                        None,
                        "C_InitToken",
                        |bytes| {
                            crate::module::TokenAccess::reserve_preparation(
                                &self.inner,
                                &target.snapshot,
                                false,
                                bytes,
                                0,
                            )
                        },
                    )
                })?;
            match self.inner.foreign.seal_callbacks(Some((
                target.snapshot.capabilities.identity.slot,
                target.snapshot.domain.clone(),
            ))) {
                Ok(seal) => break (prepared, access, seal),
                Err(Error::Busy(crate::BusyReason::ExternalExecution(
                    crate::ExternalExecutionBusy::ForeignCallbackActiveOrClosing,
                ))) => {
                    drop(access);
                    drop(prepared);
                    self.inner.foreign.wait_callbacks(
                        &self.inner,
                        Some(target.snapshot.capabilities.identity.slot),
                    )?;
                }
                Err(error) => return Err(error),
            }
        };
        let (prepared, diagnostic) = prepared;
        let diagnostic = diagnostic_root.insert(diagnostic);
        if !access
            .token_registry()?
            .tokens
            .iter()
            .any(|p| Arc::ptr_eq(p, &target.snapshot))
        {
            return Err(Error::Rejected(
                crate::RejectionReason::TokenAdministration(
                    crate::TokenAdministrationRejection::AdministrativeGenerationStale,
                ),
            ));
        }
        let cap = &target.snapshot.capabilities;
        let slot = cap.identity.slot as CK_SLOT_ID;
        let _callback_window = _foreign_callbacks.native_window();
        self.inner.foreign.maintenance_ready(slot as u64)?;
        if access.session_ledger.has_slot(slot)?
            || access.session_ledger.has_retention(&cap.identity)?
        {
            return Err(Error::Rejected(
                crate::RejectionReason::TokenAdministration(
                    crate::TokenAdministrationRejection::TargetTokenSessionsActive,
                ),
            ));
        }
        let init = access.native.table.C_InitToken.ok_or(Error::Rejected(
            crate::RejectionReason::TokenAdministration(
                crate::TokenAdministrationRejection::CInitTokenUnavailable,
            ),
        ))?;
        let query = access.native.table.C_GetTokenInfo.ok_or(Error::Rejected(
            crate::RejectionReason::TokenAdministration(
                crate::TokenAdministrationRejection::CGetTokenInfoUnavailable,
            ),
        ))?;
        let (input, witnesses) = prepared.bind(crate::pin::TokenInitializationFrame {
            pin,
            label,
            observation: crate::native::output::token_info(),
        });
        let mut frame = crate::native::frame::NativeFrame::token(access, input)?;
        let (returned, body) = frame.parts();
        let s = &body.access;
        crate::module::Inner::validate(s)?;
        s.native.record("C_GetTokenInfo")?;
        returned.arm();
        // SAFETY: aligned observation output, token writer and module guard
        // with their Arc referents belong to the same stable retained frame.
        let rv = returned.observe(
            unsafe { query(slot, &mut body.data.observation) },
            &s.native,
        );
        if crate::native_return::TokenCall::Info.completion_known(rv) {
            returned.terminated();
        }
        s.apply_failure_scope(
            &target.snapshot,
            crate::native_return::slot_scope("C_GetTokenInfo", rv),
        );
        crate::module::check_discovery(&s.native, rv, "C_GetTokenInfo")?;
        let info = &body.data.observation;
        if info.manufacturerID != cap.identity.manufacturer
            || info.model != cap.identity.model
            || info.serialNumber != cap.identity.serial
            || info.label != cap.label
            || (info.flags & CKF_TOKEN_INITIALIZED as CK_FLAGS != 0) != destructive
            || (cap.flags & CKF_TOKEN_INITIALIZED as u64 != 0) != destructive
        {
            return Err(Error::Rejected(
                crate::RejectionReason::TokenAdministration(
                    crate::TokenAdministrationRejection::AdministrativeTargetIdentityOrStateChanged,
                ),
            ));
        }

        crate::module::Inner::validate(s)?;
        let (pin_pointer, length) = body.data.pin.arguments()?;
        // Invalidate before the destructive dispatch; no failed/unwound request
        // can silently revive the old context or its object authorizations.
        // A local retirement refusal must not count an unissued C_InitToken.
        s.retire_slot(slot)?;
        crate::managed::revoke_token(s, slot)?;
        s.native.record("C_InitToken")?;
        returned.arm();
        // SAFETY: owned PIN/sentinel and exact 32-byte label remain stable even
        // on unexpected PENDING. The target gate excludes known Fe11 sessions.
        // Absence of sessions in other processes is the caller's documented
        // maintenance precondition, not a fact proved by our local registry.
        let rv = returned.observe(
            unsafe { init(slot, pin_pointer, length, body.data.label.as_mut_ptr()) },
            &s.native,
        );
        let certain = crate::native_return::TokenCall::Initialize.completion_known(rv);
        if certain {
            returned.terminated();
        }
        s.apply_failure_scope(
            &target.snapshot,
            crate::native_return::slot_scope("C_InitToken", rv),
        );
        let native_result = check(rv, "C_InitToken", true);
        if certain && (!witnesses.pins[0].unchanged(&body.data.pin) || body.data.label != label) {
            returned.quarantine(&s.native);
            return Err(diagnostic.take()?.boundary_failure(
                rv,
                Error::Rejected(crate::RejectionReason::TokenAdministration(
                    crate::TokenAdministrationRejection::NativeTokenInitializationInputChanged,
                )),
            ));
        }
        native_result
    }
}
impl Session {
    /// Request USER PIN initialization on this exact native session.
    /// The module checks its authentication state, session mode and PIN validity;
    /// a cached role observation does not preempt the native decision.
    /// Returns Busy without dispatch while this token has active operations.
    pub fn initialize_user_pin(&self, pin: impl Into<crate::PinRequest>) -> Result<()> {
        let mut diagnostic = None;
        self.initialize_pin_admitted(pin.into(), false, &mut diagnostic)
    }
    pub(crate) fn initialize_pin_admitted(
        &self,
        pin: crate::PinRequest,
        permit: bool,
        diagnostic_root: &mut Option<crate::error::PreparedCompletion>,
    ) -> Result<()> {
        let pin = crate::pin::PinFrame::new(pin);
        type Data = crate::pin::Credited<crate::pin::PinFrame>;
        let fixed = std::mem::size_of::<Data>()
            + crate::native::frame::SessionFrame::<
                '_,
                Data,
                crate::admission_wait::WriteGuard<'_, ()>,
            >::allocation_bytes();
        let ((prepared, diagnostic), s) = self.prepare_administrative_access(permit, || {
            crate::pin::PreparedPins::prepare_with_completion(
                fixed,
                [Some(&pin), None],
                None,
                "C_InitPIN",
                |bytes| {
                    crate::module::TokenAccess::reserve_preparation(
                        &self.inner,
                        &self.snapshot,
                        permit,
                        bytes,
                        crate::session::lifecycle_diagnostics::Store::allocation_bytes(),
                    )
                },
            )
        })?;
        let diagnostic = diagnostic_root.insert(diagnostic);
        let e = self.entry(&s)?;
        let h = e.handle;
        let call = s.native.table.C_InitPIN.ok_or(Error::Rejected(
            crate::RejectionReason::TokenAdministration(
                crate::TokenAdministrationRejection::CInitPINUnavailable,
            ),
        ))?;
        let (input, witnesses) = prepared.bind(pin);
        let mut frame = crate::native::frame::NativeFrame::session(s, input)?;
        let (returned, body) = frame.session_parts();
        let s = &body.access;
        let (pointer, n) = body.data.arguments()?;
        s.native.record("C_InitPIN")?;
        returned.arm();
        // SAFETY: complete frame owns PIN/sentinel, token writer, session owner
        // and their referents. Unknown completion retains all of these resources.
        let rv = returned.observe(unsafe { call(h, pointer, n) }, &s.native);
        let certain = crate::native_return::PinCall::Initialize.completion_known(rv);
        if certain {
            returned.terminated();
        }
        let native_result = pin_result(
            s,
            &self.entry,
            crate::native_return::PinCall::Initialize,
            rv,
        );
        if certain && !witnesses.pins[0].unchanged(&body.data) {
            returned.quarantine(&s.native);
            return Err(diagnostic.take()?.boundary_failure(
                rv,
                Error::Rejected(crate::RejectionReason::TokenAdministration(
                    crate::TokenAdministrationRejection::NativePinInputChanged,
                )),
            ));
        }
        native_result?;
        diagnostic.take()?.finish(self.public_result(s, Ok(())))
    }
    /// Change the PIN selected by the module's current session state.
    /// C_SetPIN has no role argument. No implicit login, role switch or retry is
    /// performed; the native refusal and any possible PIN-attempt effect remain
    /// observable independently of Fe11's cached authentication observations.
    /// Returns Busy without dispatch while this token has active operations.
    pub fn change_pin(&self, old: SecretPin, new: SecretPin) -> Result<()> {
        let mut diagnostic = None;
        self.change_pin_admitted(
            crate::PinChange::ProvidedPair { old, new },
            false,
            &mut diagnostic,
        )
    }
    /// Change the PIN through either two provided values or the protected path.
    /// The source is chosen as a pair; there is no mixed or automatic mode.
    pub fn change_pin_with(&self, change: crate::PinChange) -> Result<()> {
        let mut diagnostic = None;
        self.change_pin_admitted(change, false, &mut diagnostic)
    }
    pub(crate) fn change_pin_admitted(
        &self,
        change: crate::PinChange,
        permit: bool,
        diagnostic_root: &mut Option<crate::error::PreparedCompletion>,
    ) -> Result<()> {
        let change = crate::pin::PinChangeFrame::new(change);
        type Data = crate::pin::Credited<crate::pin::PinChangeFrame>;
        let fixed = std::mem::size_of::<Data>()
            + crate::native::frame::SessionFrame::<
                '_,
                Data,
                crate::admission_wait::WriteGuard<'_, ()>,
            >::allocation_bytes();
        let ((prepared, diagnostic), s) = self.prepare_administrative_access(permit, || {
            crate::pin::PreparedPins::prepare_with_completion(
                fixed,
                [Some(&change.old), Some(&change.new)],
                None,
                "C_SetPIN",
                |bytes| {
                    crate::module::TokenAccess::reserve_preparation(
                        &self.inner,
                        &self.snapshot,
                        permit,
                        bytes,
                        crate::session::lifecycle_diagnostics::Store::allocation_bytes(),
                    )
                },
            )
        })?;
        let diagnostic = diagnostic_root.insert(diagnostic);
        let e = self.entry(&s)?;
        let h = e.handle;
        let call = s.native.table.C_SetPIN.ok_or(Error::Rejected(
            crate::RejectionReason::TokenAdministration(
                crate::TokenAdministrationRejection::CSetPINUnavailable,
            ),
        ))?;
        let (input, witnesses) = prepared.bind(change);
        let mut frame = crate::native::frame::NativeFrame::session(s, input)?;
        let (returned, body) = frame.session_parts();
        let s = &body.access;
        let (old_pointer, old_n) = body.data.old.arguments()?;
        let (new_pointer, new_n) = body.data.new.arguments()?;
        s.native.record("C_SetPIN")?;
        returned.arm();
        // SAFETY: paired PIN choice owns separate stable buffers/sentinels;
        // the retained token writer excludes authentication and crypto calls.
        let rv = returned.observe(
            unsafe { call(h, old_pointer, old_n, new_pointer, new_n) },
            &s.native,
        );
        let certain = crate::native_return::PinCall::Change.completion_known(rv);
        if certain {
            returned.terminated();
        }
        let native_result = pin_result(s, &self.entry, crate::native_return::PinCall::Change, rv);
        if certain
            && (!witnesses.pins[0].unchanged(&body.data.old)
                || !witnesses.pins[1].unchanged(&body.data.new))
        {
            returned.quarantine(&s.native);
            return Err(diagnostic.take()?.boundary_failure(
                rv,
                Error::Rejected(crate::RejectionReason::TokenAdministration(
                    crate::TokenAdministrationRejection::NativePinInputChanged,
                )),
            ));
        }
        native_result?;
        diagnostic.take()?.finish(self.public_result(s, Ok(())))
    }
}

impl crate::TokenContext {
    /// Explicitly rediscover this quiescent slot, retaining any uncertain credits.
    /// Retires this context; select a replacement explicitly through Module.
    /// Different token identity is refused. Local writer admission follows the
    /// caller's resource policy; no native discovery call is retried.
    /// Live foreign sessions and sequences must first complete/close. A refusal
    /// at that check leaves their epoch usable; prior native loss is not undone.
    pub fn refresh(&self) -> Result<Capabilities> {
        let _drain = {
            let _state = self.inner.read()?;
            self.reserve_drain()?
        };
        let s = crate::module::TokenAccess::refresh(&self.inner, &self.snapshot)?;
        let slot = self.snapshot.capabilities.identity.slot as CK_SLOT_ID;
        if !s
            .token_registry()?
            .tokens
            .iter()
            .any(|t| Arc::ptr_eq(t, &self.snapshot))
        {
            return Err(Error::Rejected(
                crate::RejectionReason::TokenAdministration(
                    crate::TokenAdministrationRejection::TokenContextReplaced,
                ),
            ));
        }
        if !s.session_ledger.refreshable_slot(slot)? {
            return Err(Error::Rejected(
                crate::RejectionReason::TokenAdministration(
                    crate::TokenAdministrationRejection::ChangedTokenSessionsRequireClose,
                ),
            ));
        }
        // A refused voluntary refresh leaves foreign sessions/progression
        // usable. An already observed native retirement is never rolled back.
        self.inner.foreign.slot_successor_ready(slot as u64)?;
        let admission_notification = s.session_ledger.notify_admission_on_drop();
        let (revision, next) = {
            let mut r = s.token_registry()?;
            if !r.tokens.iter().any(|t| Arc::ptr_eq(t, &self.snapshot)) {
                return Err(Error::Rejected(
                    crate::RejectionReason::TokenAdministration(
                        crate::TokenAdministrationRejection::TokenContextReplaced,
                    ),
                ));
            }
            let next = r.next_generation.checked_add(1).ok_or(Error::Rejected(
                crate::RejectionReason::TokenAdministration(
                    crate::TokenAdministrationRejection::TokenGenerationExhausted,
                ),
            ))?;
            r.advance()?;
            self.snapshot.invalidate();
            self.snapshot.forget_authentication()?;
            (r.revision, next)
        };
        drop(admission_notification);
        crate::managed::revoke_generation(&s, slot, self.snapshot.generation)?;
        s.operations.retire_slot_admission(slot as u64)?;
        let cap = discover_slot(&s.native, self.inner.limits, slot, &|slot, error| {
            discovery_failure(&s, std::slice::from_ref(&self.snapshot), slot, error)
        })?;

        if cap.identity != self.snapshot.capabilities.identity {
            return Err(Error::Rejected(
                crate::RejectionReason::TokenAdministration(
                    crate::TokenAdministrationRejection::RefreshedTokenIdentityChanged,
                ),
            ));
        }
        let replacement = Arc::new(self.snapshot.replacement(cap.clone(), next)?);
        let mut r = s.token_registry()?;
        if r.revision != revision {
            return Err(Error::Busy(crate::BusyReason::TokenAdministration(
                crate::TokenAdministrationBusy::TokenRegistryChanged,
            )));
        }
        let index = r
            .tokens
            .iter()
            .position(|t| Arc::ptr_eq(t, &self.snapshot))
            .ok_or(Error::Rejected(
                crate::RejectionReason::TokenAdministration(
                    crate::TokenAdministrationRejection::TokenContextReplaced,
                ),
            ))?;
        r.advance()?;
        r.next_generation = next;
        r.tokens[index] = replacement;
        Ok(cap)
    }
}
