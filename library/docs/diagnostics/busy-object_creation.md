Cause contracts for `ObjectCreationBusy`.


The [Error](crate::Error) documentation defines the common effect and recovery
contract, including typed handling. The sites below locate the check within its
actual implementation owner; they are not a claim that the complete public request
is pre-dispatch. A cause shared by several sites has no single global phase.


## Causes and local owners


<a id="cause-GenerationCreationPlanChanged"></a>

### `GenerationCreationPlanChanged`


Local detection/handling phase and implementation owner:

- `Session::generate_native_key_selected` — `src/managed/mutations/generation.rs`. Enclosing true branch: `!current()?`.
- `Session::generate_native_key_selected` — `src/managed/mutations/generation.rs`. Enclosing match alternative: `Err(Error::Busy(crate::BusyReason::ObjectCreation( crate::ObjectCreationBusy::GenerationCreationPlanChanged, )))`.
- `Session::generate_native_key_pair_owned` — `src/managed/mutations/generation.rs`. Enclosing true branch: `!current()?`.
- `Session::generate_native_key_pair_owned` — `src/managed/mutations/generation.rs`. Enclosing match alternative: `Err(Error::Busy(crate::BusyReason::ObjectCreation( crate::ObjectCreationBusy::GenerationCreationPlanChanged, )))`.


<a id="cause-KeyMaterialCreationPlanChanged"></a>

### `KeyMaterialCreationPlanChanged`


Local detection/handling phase and implementation owner:

- `Session::derive_tls_key_material_selected` — `src/managed/mutations/key_material.rs`. Enclosing true branch: `!current()?`.
- `Session::derive_tls_key_material_selected` — `src/managed/mutations/key_material.rs`. Enclosing match alternative: `Err(Error::Busy(crate::BusyReason::ObjectCreation( crate::ObjectCreationBusy::KeyMaterialCreationPlanChanged, )))`.


<a id="cause-NativeObjectCreationPlanChanged"></a>

### `NativeObjectCreationPlanChanged`


Local detection/handling phase and implementation owner:

- `execute` (module-level helper) — `src/managed/mutations/native_object.rs`. Enclosing true branch: `!current()?`.
- `execute` (module-level helper) — `src/managed/mutations/native_object.rs`. Enclosing match alternative: `Err(Error::Busy(crate::BusyReason::ObjectCreation( crate::ObjectCreationBusy::NativeObjectCreationPlanChanged, )))`.


<a id="cause-PrivateImportCreationPlanChanged"></a>

### `PrivateImportCreationPlanChanged`


Local detection/handling phase and implementation owner:

- `prepare_creation` (module-level helper) — `src/managed/mutations/create/resident/private.rs`. Enclosing true branch: `!current()?`.
- `prepare_creation` (module-level helper) — `src/managed/mutations/create/resident/private.rs`. Enclosing match alternative: `Err(Error::Busy(crate::BusyReason::ObjectCreation( crate::ObjectCreationBusy::PrivateImportCreationPlanChanged, )))`.


<a id="cause-PublicImportCreationPlanChanged"></a>

### `PublicImportCreationPlanChanged`


Local detection/handling phase and implementation owner:

- `create_public_prepared` (module-level helper) — `src/managed/mutations/create/resident/public.rs`. Enclosing true branch: `!current()?`.
- `create_public_prepared` (module-level helper) — `src/managed/mutations/create/resident/public.rs`. Enclosing match alternative: `Err(Error::Busy(crate::BusyReason::ObjectCreation( crate::ObjectCreationBusy::PublicImportCreationPlanChanged, )))`.


<a id="cause-TypedObjectCreationPlanChanged"></a>

### `TypedObjectCreationPlanChanged`


Local detection/handling phase and implementation owner:

- `create` (module-level helper) — `src/managed/mutations/create/resident/typed.rs`. Enclosing true branch: `!current()?`.
- `create` (module-level helper) — `src/managed/mutations/create/resident/typed.rs`. Enclosing match alternative: `Err(Error::Busy(crate::BusyReason::ObjectCreation( crate::ObjectCreationBusy::TypedObjectCreationPlanChanged, )))`.


<a id="cause-UnknownCreatorSessionClosing"></a>

### `UnknownCreatorSessionClosing`


Local detection/handling phase and implementation owner:

- `object_creator` (module-level helper) — `src/managed/mutations/origins/binding.rs`. Enclosing true branch: `catalog .unknown_closing .contains_key(&(resource.slot, resource.generation))`.
