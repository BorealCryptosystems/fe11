# Hash messages and obtain random bytes

These operations use the selected native module. SHA-256 requests need the
corresponding digest mechanism. `InputLimits` must cover the number of parts and
their aggregate bytes, within the module's configured `CryptoLimits`.

```rust,no_run
use fe11::*;

pub fn sha256(session: &Session, message: &[u8], limits: InputLimits) -> Result<PreparedDigest> {
    session.digest(HashAlgorithm::Sha256, message, limits)
}

pub fn sha256_parts(
    session: &Session, parts: &[&[u8]], limits: InputLimits,
) -> Result<PreparedDigest> {
    session.digest_multipart(HashAlgorithm::Sha256, parts, limits)
}

pub fn random_bytes(session: &Session, length: usize) -> Result<SecretBytes> {
    session.generate_random(length)
}
```

Borrow a digest through `PreparedDigest::as_bytes()` and random output through
`SecretBytes::as_slice()`. Copy only when the application needs independent
ownership. The library erases its secret buffers on drop; caller copies have
their own lifetime and erasure requirements. A zero-length request and a module
refusal retain their native semantics. Do not replace a failed random request
with predictable bytes.

Multipart hashing passes the ordered fragments through the digest sequence. A
native failure can leave cleanup work; preserve the error and session until the
operation's completion or recovery has been resolved.

[All How To guides](index.md)
