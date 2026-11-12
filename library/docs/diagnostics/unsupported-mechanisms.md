Cause contracts for `MechanismsUnsupported`.


The [Error](crate::Error) documentation defines the common effect and recovery
contract, including typed handling. The sites below locate the check within its
actual implementation owner; they are not a claim that the complete public request
is pre-dispatch. A cause shared by several sites has no single global phase.


## Causes and local owners


<a id="cause-CGetMechanismInfoUnavailable"></a>

### `CGetMechanismInfoUnavailable`


Local detection/handling phase and implementation owner:

- `MechanismCatalog::require` — `src/mechanism_catalog.rs`. Enclosing match alternative: `Some(MechanismObservation::Unavailable)`.


<a id="cause-MechanismListNotObserved"></a>

### `MechanismListNotObserved`


Local detection/handling phase and implementation owner:

- `MechanismCatalog::require` — `src/mechanism_catalog.rs`. Enclosing match alternative: `MechanismDiscovery::NotRequested`.
