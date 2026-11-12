# Choose PQC message and prehash semantics

The API distinguishes three inputs. Choose the mode required by the protocol and
use the same mode, hash and context at signing and verification.

| Mode | Bytes supplied to Fe11 | Native mechanism |
| --- | --- | --- |
| `Pure` | Original message | Pure ML-DSA or SLH-DSA |
| `Prehashed(PqcHash::Sha512)` | Exact 64-byte SHA-512 digest | Generic hash ML-DSA or hash SLH-DSA |
| `HashMessage(PqcHash::Sha512)` | Original message | Combined native SHA-512/signature mechanism |

## Application-supplied SHA-512 digest

Hash the original message once using the application's selected SHA-512
implementation, or the native digest API. Supply the resulting 64 bytes:

```rust
use fe11::*;

pub fn sign_sha512_prehash(
    session: &Session, key: &PqcSigningKey, digest: &[u8; 64], context: &[u8],
    hedging: PqcHedging, limits: InputLimits,
) -> Result<PqcSignature> {
    let parameters = PqcSignatureParameters::new(
        PqcSignatureMode::Prehashed(PqcHash::Sha512), context, hedging,
    )?;
    session.sign_pqc(key, &parameters, digest, limits)
}
```

The array type makes this recipe's digest width explicit. Hash identity and input
mode remain explicit parameters: a 64-byte message is not automatically a prehash.
At verification construct the same `PqcSignatureParameters` and pass that digest
to `Session::verify_pqc` or `PqcPublicKey::verify`.

## Module-side hashing

```rust
use fe11::*;

pub fn sign_hashed_message(
    session: &Session, key: &PqcSigningKey, message: &[u8], context: &[u8],
    hedging: PqcHedging, limits: InputLimits,
) -> Result<PqcSignature> {
    let parameters = PqcSignatureParameters::new(
        PqcSignatureMode::HashMessage(PqcHash::Sha512), context, hedging,
    )?;
    session.sign_pqc(key, &parameters, message, limits)
}
```

Here the input is the complete original message. The selected module hashes it
through the combined mechanism. Check availability for the exact combination;
do not switch to a different mode after a native refusal. The signature mode and
context are protocol data and must agree between peers.

`PqcHash` also describes SHA-2, SHA-3 and combined SHAKE choices. In the PKCS#11
3.2 API, external SHAKE prehash identifiers have a specific representation limit:
the parameters API reports `Unsupported` where a standardized native identifier
is unavailable. Combined SHAKE mechanisms have their own explicit selectors.
See [PqcSignatureMode](https://borealcryptosystems.github.io/fe11/0.1.0/api/fe11/enum.PqcSignatureMode.html) and
[PqcHash](https://borealcryptosystems.github.io/fe11/0.1.0/api/fe11/enum.PqcHash.html) for the exact supported representations.

[All How To guides](index.md)
