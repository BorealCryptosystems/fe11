# Borrowed protocol operands

Every negative fixture attempts to retain a public request after one of its byte
buffers expires. Its positive control retains the same buffer through the last
use. The compiler must report E0597 on the designated borrow; unrelated errors
do not satisfy the contract. Only metadata is emitted; no fixture is executed.

These fixtures test Rust ownership, not protocol support or cryptographic length
validation. Messaging requests contain slices whose native implicit lengths are
an explicit unsafe dispatch obligation; this suite does not invent fixed arrays
or promise that an arbitrary slice length is safe for a native module.
