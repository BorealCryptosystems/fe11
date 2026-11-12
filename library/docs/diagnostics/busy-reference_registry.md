Cause contracts for `ReferenceRegistryBusy`.


The [Error](crate::Error) documentation defines the common effect and recovery
contract, including typed handling. The sites below locate the check within its
actual implementation owner; they are not a claim that the complete public request
is pre-dispatch. A cause shared by several sites has no single global phase.


## Causes and local owners


<a id="cause-ObjectMutation"></a>

### `ObjectMutation`


Local detection/handling phase and implementation owner:

- `PreparedReader::acquire_ready` — `src/registry.rs`. Enclosing true branch: `state.writer`.
- `PreparedReader::wait_on` — `src/registry.rs`. Enclosing true branch: `state.writer`.
- `ReadPermit::duplicate` — `src/registry.rs`. Enclosing true branch: `state.writer`.
- `Admission::new` — `src/advanced/admission/preparation.rs`. Enclosing match alternative: `Err(Error::Busy(crate::BusyReason::ReferenceRegistry( crate::ReferenceRegistryBusy::ObjectMutation, )))`.
- `Catalog::begin_select` — `src/managed/mutations/inventory.rs`. Enclosing true branch: `keys .iter() .any(|k| self.occupied.iter().any(|o| k.overlaps(o)))`.


<a id="cause-ReferenceQuotaExceeded"></a>

### `ReferenceQuotaExceeded`


Local detection/handling phase and implementation owner:

- `Registry<T>::try_reserve` — `src/registry.rs`. Enclosing true branch: `state.maximum.is_some_and(|maximum| total > maximum)`.
