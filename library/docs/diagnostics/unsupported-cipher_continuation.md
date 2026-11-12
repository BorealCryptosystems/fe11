Cause contracts for `CipherContinuationUnsupported`.


The [Error](crate::Error) documentation defines the common effect and recovery
contract, including typed handling. The sites below locate the check within its
actual implementation owner; they are not a claim that the complete public request
is pre-dispatch. A cause shared by several sites has no single global phase.


## Causes and local owners


<a id="cause-CcmParameterLayoutUnavailableInSelectedEdition"></a>

### `CcmParameterLayoutUnavailableInSelectedEdition`


Local detection/handling phase and implementation owner:

- `start_retained` (module-level helper) — `src/advanced/cipher/api/preparation.rs`. Enclosing true branch: `!matches!(parameters, Selection::Extension(_)) && parameters.mechanism_number() == CKM_AES_CCM as u64 && !matches!( (table.version.major, table.version.minor), (2, 40..) | (3, _) )`.
