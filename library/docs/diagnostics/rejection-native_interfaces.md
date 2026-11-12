Cause contracts for `NativeInterfacesRejection`.


The [Error](crate::Error) documentation defines the common effect and recovery
contract, including typed handling. The sites below locate the check within its
actual implementation owner; they are not a claim that the complete public request
is pre-dispatch. A cause shared by several sites has no single global phase.


## Causes and local owners


<a id="cause-CounterExhausted"></a>

### `CounterExhausted`


Local detection/handling phase and implementation owner:

- `record_selection` (module-level helper) — `src/interfaces.rs`.
- `Native::record_counter` — `src/native.rs`.


<a id="cause-IncoherentSelectedInterface"></a>

### `IncoherentSelectedInterface`


Local detection/handling phase and implementation owner:

- `select` (module-level helper) — `src/interfaces.rs`. Enclosing true branch: `!unsafe { standard_name(selected.pInterfaceName)? } || unsafe { prefix(&selected)? } != version || (selected.flags as u64 & required_flags) != required_flags || !matches .iter() .any(|(table, flags)| *table == selected.pFunctionList && *flags == selected.flags)`.


<a id="cause-InterfaceAllocation"></a>

### `InterfaceAllocation`


Local detection/handling phase and implementation owner:

- `select` (module-level helper) — `src/interfaces.rs`.
- `collect` (module-level helper) — `src/interfaces/collection.rs`. Enclosing true branch: `frame.entries.try_reserve_exact(count).is_err()`.
- `copy_descriptors` (module-level helper) — `src/interfaces/inventory.rs`.
- `copy_descriptors` (module-level helper) — `src/interfaces/inventory.rs`.


<a id="cause-InterfaceDiscoveryAttemptsExhausted"></a>

### `InterfaceDiscoveryAttemptsExhausted`


Local detection/handling phase and implementation owner:

- `collect` (module-level helper) — `src/interfaces/collection.rs`. Enclosing true branch: `attempts == 0`.


<a id="cause-InterfaceListExport"></a>

### `InterfaceListExport`


Local detection/handling phase and implementation owner:

- `select` (module-level helper) — `src/interfaces.rs`.
- `observe` (module-level helper) — `src/native/interface_inventory.rs`.


<a id="cause-InterfaceSelectionExport"></a>

### `InterfaceSelectionExport`


Local detection/handling phase and implementation owner:

- `select` (module-level helper) — `src/interfaces.rs`.


<a id="cause-NullInterfaceName"></a>

### `NullInterfaceName`


Local detection/handling phase and implementation owner:

- `standard_name` (module-level helper) — `src/interfaces.rs`. Enclosing true branch: `p.is_null()`.
- `copy_descriptors` (module-level helper) — `src/interfaces/inventory.rs`. Enclosing true branch: `entry.pInterfaceName.is_null()`.


<a id="cause-NullInterfaceTable"></a>

### `NullInterfaceTable`


Local detection/handling phase and implementation owner:

- `prefix` (module-level helper) — `src/interfaces.rs`. Enclosing true branch: `interface.pFunctionList.is_null()`.
- `copy_descriptors` (module-level helper) — `src/interfaces/inventory.rs`. Enclosing true branch: `entry.pFunctionList.is_null()`.


<a id="cause-NullSelectedInterface"></a>

### `NullSelectedInterface`


Local detection/handling phase and implementation owner:

- `select` (module-level helper) — `src/interfaces.rs`. Enclosing true branch: `request.selected.is_null()`.


<a id="cause-RequestedInterfaceAbsent"></a>

### `RequestedInterfaceAbsent`


Local detection/handling phase and implementation owner:

- `select` (module-level helper) — `src/interfaces.rs`. Enclosing true branch: `matches.is_empty()`.


<a id="cause-UnsupportedInterfaceSelection"></a>

### `UnsupportedInterfaceSelection`


Local detection/handling phase and implementation owner:

- `InterfaceSelection::validate` — `src/interfaces.rs`. Enclosing true branch: `!matches!(version, (2, 40) | (3, 0) | (3, 1) | (3, 2)) || required_flags & !(CKF_INTERFACE_FORK_SAFE as u64) != 0`.


### `InterfaceNameLimit` and `InterfaceNamesTotalLimit`

Detected by `copy_descriptors` in `src/interfaces/inventory.rs` while copying a
completed interface-list observation. The index identifies the native entry;
the limit is the caller's per-name readable bound (including NUL), or aggregate
copied bytes (excluding NUL). No partial inventory is published. These causes
are enclosed in `NativeOutputAndLocalFailure`, preserving the native list count
in descriptor units. The caller can explicitly change the inventory limits;
the library does not retry or select a different interface after this refusal.


### Interface inventory producers

These are additional producers of the existing causes; their phases are distinct
from standard table selection:

| Cause | Owner and phase |
| --- | --- |
| `InterfaceListExport` | `observe` in `src/native/interface_inventory.rs`, export resolution before any list call. |
| `InterfaceDiscoveryAttemptsExhausted` | `collect` in `src/interfaces/collection.rs`, zero caller-selected attempts, before any list call. A last native `BUFFER_TOO_SMALL` instead returns its exact count and capacity. |
| `InterfaceAllocation` | `collect` in `src/interfaces/collection.rs` or `copy_descriptors` in `src/interfaces/inventory.rs`, fallible array/name allocation after a completed count or fill. Enclosed with the native count in `NativeOutputAndLocalFailure`. |
| `NullInterfaceName` | `copy_descriptors` in `src/interfaces/inventory.rs`, a completed fill supplied a null name; no name bytes are read. |
| `NullInterfaceTable` | `copy_descriptors` in `src/interfaces/inventory.rs`, a completed fill supplied a null table; no table contents are read. |

The last two causes also carry the native count through the preallocated
diagnostic. None of these local errors publishes a partial inventory or grants
initialization/cleanup authority. Returned metadata belongs to the retained
provider; a malformed descriptor does not become permission to interpret an
unknown table or retry through another export.
