Cause contracts for `ObjectMutationBusy`.


The [Error](crate::Error) documentation defines the common effect and recovery
contract, including typed handling. The sites below locate the check within its
actual implementation owner; they are not a claim that the complete public request
is pre-dispatch. A cause shared by several sites has no single global phase.


## Causes and local owners


<a id="cause-ContentCreationPlanChanged"></a>

### `ContentCreationPlanChanged`


Local detection/handling phase and implementation owner:

- `Session::create_content` — `src/managed/mutations/storage.rs`. Enclosing true branch: `!current()?`.
- `Session::create_content` — `src/managed/mutations/storage.rs`. Enclosing match alternative: `Err(Error::Busy(crate::BusyReason::ObjectMutation( crate::ObjectMutationBusy::ContentCreationPlanChanged, )))`.


<a id="cause-LabelMutationPlanChanged"></a>

### `LabelMutationPlanChanged`


Local detection/handling phase and implementation owner:

- `set` (module-level helper) — `src/managed/mutations/label/runner.rs`. Enclosing true branch: `!current()?`.
- `set` (module-level helper) — `src/managed/mutations/label/runner.rs`. Enclosing match alternative: `Err(Error::Busy(crate::BusyReason::ObjectMutation( crate::ObjectMutationBusy::LabelMutationPlanChanged, )))`.


<a id="cause-ObjectActivity"></a>

### `ObjectActivity`


Local detection/handling phase and implementation owner:

- `Activity::acquire_operation_writer` — `src/registry/activity.rs`. Enclosing true branch: `!state.operation_writer_available(borrowed_uid)?`.
- `Activity::wait_operation_writer_on` — `src/registry/activity.rs`. Enclosing true branch: `!state.operation_writer_available(borrowed_uid)?`.
- `Activity::acquire_write_owners` — `src/registry/activity.rs`. Enclosing true branch: `state.readers != allowed`.
- `Activity::acquire_write_owners` — `src/registry/activity.rs`. Enclosing true branch: `state .owned .iter() .any(|owner| owner.transferred_writers != 0 && !writer_allowed(owner.uid))`.
- `Activity::acquire_write_owners` — `src/registry/activity.rs`. Enclosing true branch: `!writer_allowed(owner)`.
- `Activity::acquire_write_owners` — `src/registry/activity.rs`. Enclosing match alternative: `_`.
- `Reservation::try_operation_permits_retained` — `src/managed/mutations/reservation.rs`. Enclosing match alternative: `Err(Error::Busy(crate::BusyReason::ObjectMutation( crate::ObjectMutationBusy::ObjectActivity, )))`.
- `Reservation::try_prepaid_access` — `src/managed/mutations/possession/prepaid.rs`. Enclosing true branch: `self .try_operation_permits_retained(session, &mut retention.writers)? .is_some()`.


<a id="cause-ObjectSelection"></a>

### `ObjectSelection`


Local detection/handling phase and implementation owner:

- `Catalog::check_admitted_owners` — `src/managed/mutations/inventory.rs`. Enclosing true branch: `*count != allowed`.


<a id="cause-TokenInventory"></a>

### `TokenInventory`


Local detection/handling phase and implementation owner:

- `Catalog::check_admitted_owners` — `src/managed/mutations/inventory.rs`. Enclosing true branch: `*count != owned`.


<a id="cause-TokenMutation"></a>

### `TokenMutation`


Local detection/handling phase and implementation owner:

- `Catalog::begin_scan` — `src/managed/mutations/inventory.rs`. Enclosing true branch: `self.occupied.iter().any(|k| (k.slot, k.generation) == key)`.
- `PreparedInventory::wait_available` — `src/managed/mutations/inventory.rs`. Enclosing true branch: `catalog .occupied .iter() .any(|item| (item.slot, item.generation) == key)`.
