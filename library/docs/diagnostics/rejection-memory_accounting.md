Cause contracts for `MemoryAccountingRejection`.


The [Error](crate::Error) documentation defines the common effect and recovery
contract, including typed handling. The sites below locate the check within its
actual implementation owner; they are not a claim that the complete public request
is pre-dispatch. A cause shared by several sites has no single global phase.


## Causes and local owners


<a id="cause-CreditTransferExceedsOwnership"></a>

### `CreditTransferExceedsOwnership`


Local detection/handling phase and implementation owner:

- `Credit::split` — `src/symmetric/memory.rs`. Enclosing true branch: `bytes > self.bytes`.
- `Credit::split_group` — `src/symmetric/memory.rs`.
- `Credit::split_group` — `src/symmetric/memory.rs`. Enclosing true branch: `total > self.bytes`.


<a id="cause-ForeignByteCredit"></a>

### `ForeignByteCredit`


Local detection/handling phase and implementation owner:

- `Credit::merge_retained` — `src/symmetric/memory.rs`. Enclosing true branch: `!self.budget.same_account(&other.budget)`.


<a id="cause-ModuleStorageRequiresGlobalCredit"></a>

### `ModuleStorageRequiresGlobalCredit`


Local detection/handling phase and implementation owner:

- `Credit::into_module_resident` — `src/symmetric/memory.rs`. Enclosing true branch: `self.budget.parent.is_some()`.


<a id="cause-PrivateAccountRequiresCompleteSourceMeasurement"></a>

### `PrivateAccountRequiresCompleteSourceMeasurement`


Local detection/handling phase and implementation owner:

- `RetainedBytes::add_credit` — `src/symmetric/memory.rs`. Enclosing true branch: `let Some(storage) = &credit.budget._storage`.


<a id="cause-ResidentByteAccountingOverflow"></a>

### `ResidentByteAccountingOverflow`


Local detection/handling phase and implementation owner:

- `Credit::into_module_resident` — `src/symmetric/memory.rs`.


<a id="cause-RetainedSourceCreditOverflow"></a>

### `RetainedSourceCreditOverflow`


Local detection/handling phase and implementation owner:

- `RetainedBytes::add_credit` — `src/symmetric/memory.rs`. Enclosing true branch: `credit.budget.last_footprint.load(Ordering::Relaxed) != stamp`.
- `RetainedBytes::add_credit` — `src/symmetric/memory.rs`.
- `RetainedBytes::check_with_account` — `src/symmetric/memory.rs`.
- `RetainedBytes::check` — `src/symmetric/memory.rs`.
- `ContextLoginPlan<'_>::prepare_retained` — `src/session/context_authentication/preparation.rs`.


<a id="cause-RetainedSourceDestinationChanged"></a>

### `RetainedSourceDestinationChanged`


Local detection/handling phase and implementation owner:

- `RetainedBytes::check_with_account` — `src/symmetric/memory.rs`. Enclosing true branch: `!self.budget.same_account(destination)`.
- `RetainedBytes::check` — `src/symmetric/memory.rs`. Enclosing true branch: `!self.budget.same_account(destination)`.


<a id="cause-RetainedSourceObservationExhausted"></a>

### `RetainedSourceObservationExhausted`


Local detection/handling phase and implementation owner:

- `RetainedBytes::measure` — `src/symmetric/memory.rs`.


<a id="cause-SuccessorMustPreserveRetainedByteCreditDomain"></a>

### `SuccessorMustPreserveRetainedByteCreditDomain`


Local detection/handling phase and implementation owner:

- `Budget::check_successor_limit` — `src/symmetric/memory.rs`. Enclosing true branch: `self.parent.is_some() || self.maximum != limit.maximum_buffer_bytes`.


<a id="cause-SymmetricAllocation"></a>

### `SymmetricAllocation`


Local detection/handling phase and implementation owner:

- `UnboundBuffer::allocate` — `src/symmetric/memory.rs`.
- `Buffer::new_controlled_retaining` — `src/symmetric/memory.rs`.
- `Buffer::new_prepaid` — `src/symmetric/memory.rs`.


<a id="cause-SymmetricAllocationAccounting"></a>

### `SymmetricAllocationAccounting`


Local detection/handling phase and implementation owner:

- `Buffer::with_metadata_retained` — `src/symmetric/memory.rs`.
- `Buffer::with_metadata_retained` — `src/symmetric/memory.rs`.


<a id="cause-SymmetricAllocatorCapacity"></a>

### `SymmetricAllocatorCapacity`


Local detection/handling phase and implementation owner:

- `Buffer::new_prepaid` — `src/symmetric/memory.rs`.


<a id="cause-SymmetricBudgetCounterOverflow"></a>

### `SymmetricBudgetCounterOverflow`


Local detection/handling phase and implementation owner:

- `Budget::check_request` — `src/symmetric/memory.rs`.
- `Budget::check_intrinsic` — `src/symmetric/memory.rs`.
- `Budget::reserve_controlled_retaining` — `src/symmetric/memory.rs`.
- `Budget::try_reserve` — `src/symmetric/memory.rs`.


<a id="cause-SymmetricCreditOverflow"></a>

### `SymmetricCreditOverflow`


Local detection/handling phase and implementation owner:

- `Credit::check_additional_capacity` — `src/symmetric/memory.rs`.
- `Credit::merge_retained` — `src/symmetric/memory.rs`.
- `Credit::extend_admitted` — `src/symmetric/memory.rs`.


<a id="cause-SymmetricOutputLength"></a>

### `SymmetricOutputLength`

A local Buffer::set_length request exceeds the initialized owned capacity.
The stored logical length is unchanged. This helper neither calls C nor proves
that its caller has not already called C. Use the enclosing owner's failure and
completion protocol; do not treat the rejected length as a new capacity request,
expose bytes past capacity, or replay a native operation that preceded it.


Local detection/handling phase and implementation owner:

- `Buffer::set_length` — `src/symmetric/memory.rs`. Enclosing true branch: `n > self.capacity`.
