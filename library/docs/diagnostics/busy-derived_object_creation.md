Cause contracts for `DerivedObjectCreationBusy`.


The [Error](crate::Error) documentation defines the common effect and recovery
contract, including typed handling. The sites below locate the check within its
actual implementation owner; they are not a claim that the complete public request
is pre-dispatch. A cause shared by several sites has no single global phase.


## Causes and local owners


<a id="cause-KeaCreationPlanChanged"></a>

### `KeaCreationPlanChanged`


Local detection/handling phase and implementation owner:

- `Session::derive_kea_selected` — `src/managed/mutations/kea.rs`. Enclosing true branch: `!valid()?`.
- `Session::derive_kea_selected` — `src/managed/mutations/kea.rs`. Enclosing match alternative: `Err(Error::Busy(crate::BusyReason::DerivedObjectCreation( crate::DerivedObjectCreationBusy::KeaCreationPlanChanged, )))`.


<a id="cause-Sp800CreationPlanChanged"></a>

### `Sp800CreationPlanChanged`


Local detection/handling phase and implementation owner:

- `Session::derive_sp800_108_selected` — `src/managed/mutations/sp800.rs`. Enclosing true branch: `!current()?`.
- `Session::derive_sp800_108_selected` — `src/managed/mutations/sp800.rs`. Enclosing match alternative: `Err(Error::Busy(crate::BusyReason::DerivedObjectCreation( crate::DerivedObjectCreationBusy::Sp800CreationPlanChanged, )))`.


<a id="cause-DerivationCreationPlanChanged"></a>

### `DerivationCreationPlanChanged`


Local detection/handling phase and implementation owner:

- `Session::derive_native_input` — `src/managed/mutations/derivation.rs`. Enclosing true branch: `!current()?`.
- `Session::derive_native_input` — `src/managed/mutations/derivation.rs`. Enclosing match alternative: `Err(Error::Busy(crate::BusyReason::DerivedObjectCreation( crate::DerivedObjectCreationBusy::DerivationCreationPlanChanged, )))`.


<a id="cause-KeyTransportCreationPlanChanged"></a>

### `KeyTransportCreationPlanChanged`


Local detection/handling phase and implementation owner:

- `Session::create_key_transport` — `src/managed/mutations/native_transport.rs`. Enclosing true branch: `!current()?`.
- `Session::create_key_transport` — `src/managed/mutations/native_transport.rs`. Enclosing match alternative: `Err(Error::Busy(crate::BusyReason::DerivedObjectCreation( crate::DerivedObjectCreationBusy::KeyTransportCreationPlanChanged, )))`.

