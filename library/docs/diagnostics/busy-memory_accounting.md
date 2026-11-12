Cause contracts for `MemoryAccountingBusy`.


The [Error](crate::Error) documentation defines the common effect and recovery
contract, including typed handling. The sites below locate the check within its
actual implementation owner; they are not a claim that the complete public request
is pre-dispatch. A cause shared by several sites has no single global phase.


## Causes and local owners


<a id="cause-SymmetricByteBudget"></a>

### `SymmetricByteBudget`


Local detection/handling phase and implementation owner:

- `Budget::try_reserve` — `src/symmetric/memory.rs`. Enclosing true branch: `next > self.maximum`.
