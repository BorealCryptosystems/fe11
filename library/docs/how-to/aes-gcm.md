# Protect application records with AES-GCM

Provide a `SymmetricKey` selected or generated for the module's AES-GCM mechanism.
The consuming protocol owns nonce allocation: use a unique 96-bit nonce for every
encryption under a given key, including across restarts and concurrent writers.
Persist any nonce-allocation state before encryption. Reusing a nonce under the
same key breaks GCM's security.

Authenticate stable record metadata as AAD, such as a protocol version and record
identifier in an unambiguous encoding. Keep the exact nonce, AAD and ciphertext
with the record. The helpers select the provided 12-byte nonce form and its
128-bit authentication tag.

```rust,no_run
use fe11::*;

pub fn encrypt_record(
    session: &Session, key: &SymmetricKey, nonce: [u8; 12],
    aad: &[u8], plaintext: &[u8], limits: InputLimits,
) -> Result<AeadCiphertext> {
    session.encrypt_aead(
        key, AeadParameters { nonce: AeadNonce::Provided(nonce), aad },
        plaintext, limits,
    )
}

pub fn decrypt_record(
    session: &Session, key: &SymmetricKey, nonce: [u8; 12],
    aad: &[u8], ciphertext_and_tag: &[u8], limits: InputLimits,
) -> Result<AeadPlaintext> {
    session.decrypt_aead(
        key, AeadParameters { nonce: AeadNonce::Provided(nonce), aad },
        ciphertext_and_tag, limits,
    )
}
```

`AeadCiphertext::as_bytes()` contains ciphertext followed by the tag. Pass that
complete byte sequence to decryption, with identical nonce and AAD. Process
`AeadPlaintext::as_bytes()` only after successful authentication. Keep the returned
owner alive while borrowing its bytes. Library-owned plaintext storage is erased
on drop; application copies need their own handling.

Size `InputLimits` and the module's owned-buffer budget for the message, AAD and
operation storage. A module may refuse a parameter combination. Retain the native
error and apply the [error-handling recipe](errors.md); do not silently switch
mechanisms or discard authentication.

[All How To guides](index.md)
