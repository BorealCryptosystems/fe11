Cause contracts for `CallbacksRejection`.


The [Error](crate::Error) documentation defines the common effect and recovery
contract, including typed handling. The sites below locate the check within its
actual implementation owner; they are not a claim that the complete public request
is pre-dispatch. A cause shared by several sites has no single global phase.


## Causes and local owners


<a id="cause-NotificationPreparationConsumed"></a>

### `NotificationPreparationConsumed`


Local detection/handling phase and implementation owner:

- `NotifyRegistry::register_prepared` — `src/notify/preparation.rs`. Enclosing true branch: `handler.is_none() || prepared.context.is_none() || prepared.diagnostics.is_none()`.


<a id="cause-NotificationRegistryAllocation"></a>

### `NotificationRegistryAllocation`


Local detection/handling phase and implementation owner:

- `PreparedNotification::prepare_capacity` — `src/notify/preparation.rs`.


<a id="cause-NotificationRegistryCountOverflow"></a>

### `NotificationRegistryCountOverflow`


Local detection/handling phase and implementation owner:

- `NotifyRegistry::register_prepared` — `src/notify/preparation.rs`.


<a id="cause-NotificationRegistryStorageOverflow"></a>

### `NotificationRegistryStorageOverflow`


Local detection/handling phase and implementation owner:

- `PreparedNotification::allocation_bytes` — `src/notify/preparation.rs`.
- `PreparedNotification::prepare_capacity` — `src/notify/preparation.rs`.
- `PreparedNotification::prepare_capacity` — `src/notify/preparation.rs`.
- `NotifyRegistry::register_prepared` — `src/notify/preparation.rs`. Enclosing true branch: `contexts.entries.capacity() < count && prepared .candidate .as_ref() .map_or(true, |c| c.entries.capacity() < count)`.


<a id="cause-NotificationRegistryWithdrawn"></a>

### `NotificationRegistryWithdrawn`


Local detection/handling phase and implementation owner:

- `Progress::revision` — `src/notify/capacity.rs`. Enclosing match alternative: `u64::MAX`.


<a id="cause-NotificationRetainedStorageOverflow"></a>

### `NotificationRetainedStorageOverflow`


Local detection/handling phase and implementation owner:

- `PreparedNotification::prepare_capacity` — `src/notify/preparation.rs`.


<a id="cause-NotificationSessionBinding"></a>

### `NotificationSessionBinding`


Local detection/handling phase and implementation owner:

- `NotifyContext::bind` — `src/notify.rs`. Enclosing true branch: `!valid`.
- `NotifyContext::check` — `src/notify.rs`. Enclosing true branch: `self.diagnostics.mismatch.load(Ordering::Acquire)`.
