Cause contracts for `ModuleLifecycleRejection`.


The [Error](crate::Error) documentation defines the common effect and recovery
contract, including typed handling. The sites below locate the check within its
actual implementation owner; they are not a claim that the complete public request
is pre-dispatch. A cause shared by several sites has no single global phase.


## Causes and local owners


<a id="cause-CCloseAllSessionsUnavailable"></a>

### `CCloseAllSessionsUnavailable`


Local detection/handling phase and implementation owner:

- `TokenDrain::recover_sessions` — `src/module/drain.rs`.


<a id="cause-CGetInfoUnavailable"></a>

### `CGetInfoUnavailable`


Local detection/handling phase and implementation owner:

- `Module::library_info` — `src/module/observations.rs`.


<a id="cause-CGetMechanismInfoUnavailable"></a>

### `CGetMechanismInfoUnavailable`


Local detection/handling phase and implementation owner:

- `Module::mechanism_info` — `src/module/observations.rs`.


<a id="cause-CGetMechanismListUnavailable"></a>

### `CGetMechanismListUnavailable`


Local detection/handling phase and implementation owner:

- `Module::mechanism_ids` — `src/module/observations.rs`.


<a id="cause-CGetSlotInfoUnavailable"></a>

### `CGetSlotInfoUnavailable`


Local detection/handling phase and implementation owner:

- `Module::slot_info` — `src/module/observations.rs`.


<a id="cause-CGetSlotListUnavailable"></a>

### `CGetSlotListUnavailable`


Local detection/handling phase and implementation owner:

- `Module::slot_ids` — `src/module/observations.rs`.


<a id="cause-CLoginUnavailable"></a>

### `CLoginUnavailable`


Local detection/handling phase and implementation owner:

- `context_login_call` (module-level helper) — `src/session/context_authentication.rs`. Enclosing true branch: `state.native.table.C_Login.is_none()`.
- `PreparedContextLogin<'a>::perform` — `src/session/context_authentication.rs`. Enclosing false branch: `matches!(call, crate::native_return::SessionCall::ContextLoginUser)`.
- `TokenContext::login_on` — `src/module/sessions.rs`. Enclosing false branch: `matches!(call, crate::native_return::SessionCall::LoginUser)`.


<a id="cause-CLogoutUnavailable"></a>

### `CLogoutUnavailable`


Local detection/handling phase and implementation owner:

- `TokenContext::logout_on` — `src/module/sessions.rs`.


<a id="cause-AbsoluteModulePathRequired"></a>

### `AbsoluteModulePathRequired`


Local detection/handling phase and implementation owner:

- `Module::open_selected_symmetric` — `src/module/open.rs`. Enclosing true branch: `!config.path.is_absolute()`.
- `load_library` (module-level helper) — `src/native/platform.rs`. Enclosing true branch: `!path.is_absolute()`.
- `ModuleBuilder::observation_source` — `src/module/configuration/observation.rs`. Enclosing true branch: `!config.path.is_absolute()`.


<a id="cause-AsynchronousSessionCapability"></a>

### `AsynchronousSessionCapability`


Local detection/handling phase and implementation owner:

- `TokenContext::open_session_mode_with_notify` — `src/module/sessions.rs`. Enclosing true branch: `mode == crate::AdvancedSessionMode::Asynchronous && ((s.native.table.version.major, s.native.table.version.minor) != (3, 2) || s.native.asynchronous.is_none())`.


<a id="cause-CollectiveCloseDiagnosticAbsent"></a>

### `CollectiveCloseDiagnosticAbsent`


Local detection/handling phase and implementation owner:

- `TokenDrain::recover_sessions` — `src/module/drain.rs`.


<a id="cause-DiscoveryAllocation"></a>

### `DiscoveryAllocation`


Local detection/handling phase and implementation owner:

- `list` (module-level helper) — `src/module/discovery.rs`.


<a id="cause-DiscoveryAllocationRepresentation"></a>

### `DiscoveryAllocationRepresentation`


Local detection/handling phase and implementation owner:

- `list` (module-level helper) — `src/module/discovery.rs`.


<a id="cause-DiscoveryAttemptBudgetExhausted"></a>

### `DiscoveryAttemptBudgetExhausted`


Local detection/handling phase and implementation owner:

- `list` (module-level helper) — `src/module/discovery.rs`.


<a id="cause-DiscoveryFailureAllocation"></a>

### `DiscoveryFailureAllocation`


Local detection/handling phase and implementation owner:

- `discover_selected` (module-level helper) — `src/module/discovery.rs`.


<a id="cause-DiscoveryItemBudgetAfterSizing"></a>

### `DiscoveryItemBudgetAfterSizing`


Local detection/handling phase and implementation owner:

- `list` (module-level helper) — `src/module/discovery.rs`. Enclosing true branch: `n > limit`.


<a id="cause-DiscoveryLengthConversion"></a>

### `DiscoveryLengthConversion`


Local detection/handling phase and implementation owner:

- `list` (module-level helper) — `src/module/discovery.rs`.


<a id="cause-DiscoverySnapshotAllocation"></a>

### `DiscoverySnapshotAllocation`


Local detection/handling phase and implementation owner:

- `discover_selected` (module-level helper) — `src/module/discovery.rs`.


<a id="cause-DuplicateSlot"></a>

### `DuplicateSlot`


Local detection/handling phase and implementation owner:

- `discover_selected` (module-level helper) — `src/module/discovery.rs`. Enclosing true branch: `slots[..index].contains(slot)`.


<a id="cause-ExternalInitializationIdentityMismatch"></a>

### `ExternalInitializationIdentityMismatch`


Local detection/handling phase and implementation owner:

- `ExternalInitialization::check` — `src/module/external_initialization.rs`.


<a id="cause-ForeignDrainingSession"></a>

### `ForeignDrainingSession`


Local detection/handling phase and implementation owner:

- `ModuleDrain::poll_advanced` — `src/module/drain.rs`. Enclosing true branch: `!Arc::ptr_eq(&self.inner, &session.session.inner)`.
- `ModuleDrain::close_advanced_session` — `src/module/drain.rs`. Enclosing true branch: `!Arc::ptr_eq(&self.inner, &session.session.inner)`.
- `ModuleDrain::close_session` — `src/module/drain.rs`. Enclosing true branch: `!Arc::ptr_eq(&self.inner, &session.inner)`.
- `TokenDrain::poll_advanced` — `src/module/drain.rs`. Enclosing true branch: `!Arc::ptr_eq(&self.context.inner, &session.session.inner) || !Arc::ptr_eq(&self.context.snapshot, &session.session.snapshot)`.
- `TokenDrain::close_advanced_session` — `src/module/drain.rs`. Enclosing true branch: `!Arc::ptr_eq(&self.context.inner, &session.session.inner) || !Arc::ptr_eq(&self.context.snapshot, &session.session.snapshot)`.
- `TokenDrain::check_session` — `src/module/drain.rs`. Enclosing true branch: `!Arc::ptr_eq(&self.context.inner, &session.inner) || !Arc::ptr_eq(&self.context.snapshot, &session.snapshot)`.


<a id="cause-InitializationArgumentGraphChanged"></a>

### `InitializationArgumentGraphChanged`


Local detection/handling phase and implementation owner:

- `InitializationFrame::validate_return` — `src/module/initialization.rs`. Enclosing true branch: `self.args.flags != self.flags || self.args.pReserved != self.pointer || observed.addresses() != expected.addresses() || !self .reserved .as_ref() .map_or(true, InitializationReserved::unchanged)`.


<a id="cause-InvalidOrDuplicateProviderSession"></a>

### `InvalidOrDuplicateProviderSession`


Local detection/handling phase and implementation owner:

- `TokenContext::open_session_mode_with_notify` — `src/module/sessions.rs`. Enclosing true branch: `*handle == CK_INVALID_HANDLE as fe11_sys::CK_ULONG`.


<a id="cause-LoginRoleIdentifierConversion"></a>

### `LoginRoleIdentifierConversion`


Local detection/handling phase and implementation owner:

- `LoginRole::native` — `src/module/authentication.rs`. Enclosing match alternative: `Self::VendorExtension(value)`.


<a id="cause-LogoutDiagnosticAbsent"></a>

### `LogoutDiagnosticAbsent`


Local detection/handling phase and implementation owner:

- `TokenContext::logout_on` — `src/module/sessions.rs`.


<a id="cause-MechanismIdentifierConversion"></a>

### `MechanismIdentifierConversion`


Local detection/handling phase and implementation owner:

- `Module::mechanism_info` — `src/module/observations.rs`.


<a id="cause-ModuleClosed"></a>

### `ModuleClosed`


Local detection/handling phase and implementation owner:

- `Uncertainty::check_native_authority` — `src/native.rs`. Enclosing match alternative: `value if value == AdmissionLifecycle::Closed as u8`.
- `Native::finalize_admitted` — `src/native.rs`. Enclosing true branch: `matches!(self.finalization, Finalization::Published(CKR_OK))`.
- `Inner::validate_open` — `src/module/access.rs`. Enclosing true branch: `state.closed || state.native.finalization_succeeded()`.
- `finalize_owner` (module-level helper) — `src/module/finalization.rs`. Enclosing true branch: `state.closed`.


<a id="cause-ModuleIsNotRegularFile"></a>

### `ModuleIsNotRegularFile`


Local detection/handling phase and implementation owner:

- `Module::open_selected_symmetric` — `src/module/open.rs`. Enclosing true branch: `!source .file .metadata() .map_err(|_| { Error::Rejected(crate::RejectionReason::ModuleLifecycle( crate::ModuleLifecycleRejection::ModuleMetadata, )) })? .is_file()`.
- `ModuleBuilder::observation_source` — `src/module/configuration/observation.rs`. Enclosing true branch: `!source .file .metadata() .map_err(|_| { crate::Error::Rejected(crate::RejectionReason::ModuleLifecycle( crate::ModuleLifecycleRejection::ModuleMetadata, )) })? .is_file()`.


<a id="cause-ModuleMetadata"></a>

### `ModuleMetadata`


Local detection/handling phase and implementation owner:

- `Module::open_selected_symmetric` — `src/module/open.rs`. Enclosing match alternative: `provenance::Source::File(config)`.
- `prepare` (module-level helper) — `src/native/platform.rs`.
- `ModuleBuilder::observation_source` — `src/module/configuration/observation.rs`. Enclosing match alternative: `super::super::provenance::Source::File(config)`.


<a id="cause-NativeAuthenticationInputChanged"></a>

### `NativeAuthenticationInputChanged`


Local detection/handling phase and implementation owner:

- `PreparedContextLogin<'a>::perform` — `src/session/context_authentication.rs`. Enclosing true branch: `!input_unchanged`.
- `TokenContext::login_on` — `src/module/sessions.rs`. Enclosing true branch: `certain && (!witnesses.pins[0].unchanged(&input.pin) || !input.name_unchanged(&witnesses.name))`.


<a id="cause-NativeIdentifierAllocation"></a>

### `NativeIdentifierAllocation`


Local detection/handling phase and implementation owner:

- `identifiers_to_u64` (module-level helper) — `src/module/observations.rs`.


<a id="cause-NativeStateUncertain"></a>

### `NativeStateUncertain`


Local detection/handling phase and implementation owner:

- `Uncertainty::check_available` — `src/native.rs`. Enclosing true branch: `self.is_uncertain()`.
- `Native::finalize_admitted` — `src/native.rs`. Enclosing true branch: `self.is_uncertain() && !recovery`.
- `GetId::dispatch` — `src/advanced/asynchronous.rs`. Enclosing true branch: `s.native.is_uncertain()`.
- `JoinedCall::attach` — `src/advanced/asynchronous.rs`. Enclosing true branch: `s.native.is_uncertain()`.
- `JoinedCall::poll` — `src/advanced/asynchronous.rs`. Enclosing true branch: `s.native.is_uncertain()`.
- `drive_digest` (module-level helper) — `src/advanced/digest.rs`. Enclosing true branch: `s.native.is_uncertain()`.
- `Module::open_selected_symmetric` — `src/module/open.rs`. Enclosing true branch: `native.is_uncertain()`.
- `Module::open_selected_symmetric` — `src/module/open.rs`. Enclosing true branch: `native.is_uncertain()`.
- `Reservation<'a>::include` — `src/native/image_reservation.rs`. Enclosing true branch: `uncertainty.is_uncertain()`.
- `Reservation<'a>::include` — `src/native/image_reservation.rs`. Enclosing true branch: `uncertainty.is_uncertain()`.
- `Reservation<'a>::include` — `src/native/image_reservation.rs`. Enclosing true branch: `uncertainty.is_uncertain()`.
- `Reservation<'a>::check_borrowed` — `src/native/image_reservation.rs`. Enclosing true branch: `uncertainty.is_uncertain()`.
- `Session::entry_common` — `src/session/access.rs`. Enclosing true branch: `s.native.is_uncertain()`.
- `Admission::drive` — `src/advanced/admission/progression.rs`. Enclosing true branch: `s.native.is_uncertain()`.
- `DualOperation::drive` — `src/advanced/dual/operation.rs`. Enclosing true branch: `s.native.is_uncertain()`.
- `AeadMessageOperation::drive_inner` — `src/advanced/gcm/progression.rs`. Enclosing true branch: `s.native.is_uncertain()`.
- `MacOperation::drive_inner` — `src/advanced/messages/progression.rs`. Enclosing true branch: `s.native.is_uncertain()`.
- `NativeMessageOperation::drive_inner` — `src/advanced/native_messages/driver.rs`. Enclosing true branch: `state.native.is_uncertain()`.
- `StateIo::drive_selected` — `src/advanced/state_io/progression.rs`. Enclosing true branch: `s.native.is_uncertain()`.
- `TokenContext::open_session_mode_with_notify` — `src/module/sessions.rs`. Enclosing true branch: `s.native.is_uncertain()`.


<a id="cause-ProcessObservationOwnerAbsent"></a>

### `ProcessObservationOwnerAbsent`


Local detection/handling phase and implementation owner:

- `Module::open_selected_symmetric` — `src/module/open.rs`. Enclosing match alternative: `provenance::Source::Process(_)`.


<a id="cause-RecoveryOwnerMismatch"></a>

### `RecoveryOwnerMismatch`


Local detection/handling phase and implementation owner:

- `Identity::classify` — `src/advanced/lease.rs`. Enclosing true branch: `!self.matches(entry) || ticket == 0 || domain.advanced_count_invalid.load(Ordering::Acquire)`.
- `Identity::classify` — `src/advanced/lease.rs`. Enclosing false branch: `self.proof_ticket.load(Ordering::Acquire) == ticket`.
- `Identity::classify` — `src/advanced/lease.rs`. Enclosing match alternative: `_`.
- `Identity::classify` — `src/advanced/lease.rs`.
- `Identity::classify` — `src/advanced/lease.rs`. Enclosing true branch: `self .class .compare_exchange( LeaseClass::Unclassified as u8, LeaseClass::Stranded as u8, Ordering::AcqRel, Ordering::Acquire, ) .is_err()`.
- `Identity::prove_stranded` — `src/advanced/lease.rs`.
- `Identity::prove_stranded` — `src/advanced/lease.rs`. Enclosing true branch: `self.class.load(Ordering::Acquire) != LeaseClass::Stranded as u8`.
- `TokenLease::new_retained` — `src/advanced/lease.rs`. Enclosing true branch: `snapshot .domain .advanced_count_invalid .load(Ordering::Acquire)`.
- `TokenAccess<'a>::reserve_preparation` — `src/module/access.rs`. Enclosing true branch: `snapshot .domain .advanced_count_invalid .load(Ordering::Acquire)`.
- `TokenDrain::recover_sessions` — `src/module/drain.rs`. Enclosing true branch: `active < stranded`.
- `TokenDrain::recover_sessions` — `src/module/drain.rs`. Enclosing true branch: `owners.len() > stranded`.
- `TokenSnapshot::local_context` — `src/module/local_maintenance.rs`. Enclosing true branch: `self.domain.advanced_count_invalid.load(Ordering::Acquire)`.
- `SessionLedger::prove_stranded` — `src/session_budget/close.rs`.
- `SessionLedger::prove_stranded` — `src/session_budget/close.rs`.
- `SessionLedger::prove_stranded` — `src/session_budget/close.rs`. Enclosing true branch: `!retained || ticket == 0 || observed.as_ptr() != Arc::as_ptr(entry) || entry.advanced_operation.load(Ordering::Acquire) != ticket || !matches(entry)`.
- `SessionLedger::start_recovery` — `src/session_budget/recovery.rs`. Enclosing true branch: `!Arc::ptr_eq(&record.identity().proof, &item.proof)`.
- `Ledger::recovery_owners` — `src/advanced/ledger.rs`. Enclosing true branch: `owner.identity.uid() != uid`.
- `TokenSnapshot::maintenance_activity_with_policy` — `src/module/token_snapshot.rs`. Enclosing true branch: `self.domain.advanced_count_invalid.load(Ordering::Acquire)`.
- `TokenSnapshot::maintenance_activity_with_policy` — `src/module/token_snapshot.rs`. Enclosing true branch: `self.domain.advanced_count_invalid.load(Ordering::Acquire)`.
- `TokenSnapshot::maintenance_activity_with_policy` — `src/module/token_snapshot.rs`. Enclosing true branch: `self.domain.advanced_count_invalid.load(Ordering::Acquire)`.
- `TokenSnapshot::recovery_population` — `src/module/token_snapshot.rs`. Enclosing true branch: `self.domain.advanced_count_invalid.load(Ordering::Acquire)`.


<a id="cause-RecoverySnapshotAllocation"></a>

### `RecoverySnapshotAllocation`


Local detection/handling phase and implementation owner:

- `TokenDrain::recover_sessions` — `src/module/drain.rs`.
- `TokenDrain::recover_sessions` — `src/module/drain.rs`.
- `SessionLedger::prepare_recovery_selected` — `src/session_budget/recovery.rs`.
- `SessionLedger::prepare_recovery_selected` — `src/session_budget/recovery.rs`.
- `Ledger::recovery_owners` — `src/advanced/ledger.rs`.


<a id="cause-RecoveryTokenIdentityChanged"></a>

### `RecoveryTokenIdentityChanged`


Local detection/handling phase and implementation owner:

- `TokenDrain::recover_sessions` — `src/module/drain.rs`. Enclosing true branch: `observed != snapshot.capabilities.identity`.
- `SessionLedger::prepare_recovery_selected` — `src/session_budget/recovery.rs`. Enclosing true branch: `selected(r) && r.live_native() && r.identity().token.slot == identity.slot && r.identity().token != *identity`.


<a id="cause-ReplacementSlotMismatch"></a>

### `ReplacementSlotMismatch`


Local detection/handling phase and implementation owner:

- `TokenSnapshot::replacement` — `src/module/token_snapshot.rs`. Enclosing true branch: `capabilities.identity.slot != self.capabilities.identity.slot`.


<a id="cause-RuntimeClientIdentityExhausted"></a>

### `RuntimeClientIdentityExhausted`


Local detection/handling phase and implementation owner:

- `ClientId::allocate` — `src/module/runtime.rs`.


<a id="cause-RuntimeOwnerRequired"></a>

### `RuntimeOwnerRequired`


Local detection/handling phase and implementation owner:

- `LifecycleAccess::require_owner` — `src/module/runtime.rs`. Enclosing match alternative: `Self::Client(_)`.


<a id="cause-SelectedSlotAllocation"></a>

### `SelectedSlotAllocation`


Local detection/handling phase and implementation owner:

- `discover_selected` (module-level helper) — `src/module/discovery.rs`. Enclosing match alternative: `DiscoverySelection::Slots(selected)`.


<a id="cause-SelectedSlotBudget"></a>

### `SelectedSlotBudget`


Local detection/handling phase and implementation owner:

- `discover_selected` (module-level helper) — `src/module/discovery.rs`. Enclosing true branch: `selected.len() > limits.slots`.


<a id="cause-SessionCloseEpochExhausted"></a>

### `SessionCloseEpochExhausted`


Local detection/handling phase and implementation owner:

- `TokenSnapshot::advance_close_epoch` — `src/module/token_snapshot.rs`.


<a id="cause-SessionCloseResultAbsent"></a>

### `SessionCloseResultAbsent`


Local detection/handling phase and implementation owner:

- `validate_finalization_entry` (module-level helper) — `src/module/finalization.rs`. Enclosing match alternative: `None if entry.close_attempted.load(Ordering::Acquire) && collective.is_none()`.


<a id="cause-SessionOpeningStorageAccounting"></a>

### `SessionOpeningStorageAccounting`


Local detection/handling phase and implementation owner:

- `TokenContext::open_session_mode_with_notify` — `src/module/sessions.rs`.


<a id="cause-SlotCloseCount"></a>

### `SlotCloseCount`


Local detection/handling phase and implementation owner:

- `SlotClose::new` — `src/module/recovery.rs`.


<a id="cause-SlotIdentifierConversion"></a>

### `SlotIdentifierConversion`


Local detection/handling phase and implementation owner:

- `discover_selected` (module-level helper) — `src/module/discovery.rs`. Enclosing match alternative: `DiscoverySelection::Slots(selected)`.
- `slot_id` (module-level helper) — `src/module/observations.rs`.


<a id="cause-StandardLoginRoleRequiresDedicatedVariant"></a>

### `StandardLoginRoleRequiresDedicatedVariant`


Local detection/handling phase and implementation owner:

- `LoginRole::native` — `src/module/authentication.rs`. Enclosing true branch: `matches!(native, CKU_USER | CKU_SO | CKU_CONTEXT_SPECIFIC)`.


<a id="cause-TokenAdmissionOwnerMismatch"></a>

### `TokenAdmissionOwnerMismatch`


Local detection/handling phase and implementation owner:

- `TokenSnapshot::bind_admission` — `src/module/token_snapshot.rs`. Enclosing true branch: `!registered.ptr_eq(&Arc::downgrade(wake))`.


<a id="cause-TokenContextRetired"></a>

### `TokenContextRetired`


Local detection/handling phase and implementation owner:

- `Inner::validate_logout` — `src/module/access.rs`. Enclosing true branch: `!registry .tokens .iter() .any(|token| std::ptr::eq(token.as_ref(), snapshot))`.


<a id="cause-TokenContextStale"></a>

### `TokenContextStale`


Local detection/handling phase and implementation owner:

- `TokenSnapshot::check` — `src/module/token_snapshot.rs`. Enclosing true branch: `!self.admission_available()`.


<a id="cause-TokenRegistryRevisionExhausted"></a>

### `TokenRegistryRevisionExhausted`


Local detection/handling phase and implementation owner:

- `TokenRegistry::advance` — `src/module/state.rs`.


<a id="cause-TokenRetirementAllocation"></a>

### `TokenRetirementAllocation`


Local detection/handling phase and implementation owner:

- `State::retire_slot_into` — `src/module/state.rs`. Enclosing true branch: `let Some(generations) = generations.as_mut()`.


<a id="cause-TokenSelectorNotUnique"></a>

### `TokenSelectorNotUnique`


Local detection/handling phase and implementation owner:

- `Module::select` — `src/module/open.rs`. Enclosing true branch: `matches.len() != 1`.


<a id="cause-UnavailableDiscoveryCount"></a>

### `UnavailableDiscoveryCount`


Local detection/handling phase and implementation owner:

- `list` (module-level helper) — `src/module/discovery.rs`. Enclosing true branch: `frame.count == CK_UNAVAILABLE_INFORMATION`.

