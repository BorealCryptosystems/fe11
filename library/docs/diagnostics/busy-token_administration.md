Cause contracts for `TokenAdministrationBusy`.


The [Error](crate::Error) documentation defines the common effect and recovery
contract, including typed handling. The sites below locate the check within its
actual implementation owner; they are not a claim that the complete public request
is pre-dispatch. A cause shared by several sites has no single global phase.


## Causes and local owners


<a id="cause-TokenRegistryChanged"></a>

### `TokenRegistryChanged`


Local detection/handling phase and implementation owner:

- `Module::refresh_tokens_report` — `src/administration.rs`. Enclosing true branch: `s.token_registry()?.revision != revision`.
- `crate::TokenContext::refresh` — `src/administration.rs`. Enclosing true branch: `r.revision != revision`.

