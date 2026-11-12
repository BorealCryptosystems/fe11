Cause contracts for `NativeDigestRejection`.


The [Error](crate::Error) documentation defines the common effect and recovery
contract, including typed handling. The sites below locate the check within its
actual implementation owner; they are not a claim that the complete public request
is pre-dispatch. A cause shared by several sites has no single global phase.


## Causes and local owners


<a id="cause-DigestBitCountAbiWidth"></a>

### `DigestBitCountAbiWidth`


Local detection/handling phase and implementation owner:

- `NativeDigestTruncation::new` — `src/native_digest.rs`.


<a id="cause-DigestOutputHostWidth"></a>

### `DigestOutputHostWidth`


Local detection/handling phase and implementation owner:

- `NativeDigestTruncation::new` — `src/native_digest.rs`.


<a id="cause-NativeDigestOutputLength"></a>

### `NativeDigestOutputLength`

Detected when moving an already produced digest buffer into its public typed
result: the length is not accepted by the selected native digest algorithm.
The move is refused before Buffer::take, so the current buffer owner retains
the bytes. This local conversion issues no C call and does not establish its
caller's native phase. Preserve the enclosing completion information; do not
normalize the bytes, relabel the algorithm or repeat the completed digest.


Local detection/handling phase and implementation owner:

- `NativeDigest::take` — `src/native_digest.rs`. Enclosing true branch: `!algorithm.accepts_length(bytes.as_slice().len())`.
