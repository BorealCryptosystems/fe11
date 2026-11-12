# Select software public-key verification

Build `fe11-verify-engine` for the application's target with the documented
[OpenSSL prerequisites](https://borealcryptosystems.github.io/fe11/0.1.0/verify-engine/README.html). Deploy the resulting
DLL or shared object and establish its expected SHA-256 through your authenticated
deployment manifest. The engine performs explicit software hashing and public-key
signature verification; native signing remains at the PKCS#11 module.

```rust
use fe11::*;
use std::path::PathBuf;

pub fn with_verification_engine(
    config: ModuleConfig, options: ModuleOptions,
    engine_path: PathBuf, expected_engine_sha256: [u8; 32],
) -> Result<Module> {
    let engine = VerifyEngine::builder(
        engine_path,
        ModuleIntegrity::Sha256 {
            expected: expected_engine_sha256,
            on_mismatch: ModuleDigestMismatch::Refuse,
        },
    ).open()?;
    Module::builder(config, options).verify_engine(Some(engine)).open()
}
```

The handle can also be retained independently for operations taking `&VerifyEngine`.
`Module::verify_engine()` exposes an attached handle; `VerifyEngine::info()` reports
component and OpenSSL version information and available service entry points.

## Verify a PQC signature using its public representation

```rust
use fe11::*;

pub fn verify_in_software(
    engine: &VerifyEngine, public_key: &PqcPublicKey,
    message: &[u8], context: &[u8], hedging: PqcHedging,
    signature: &PqcSignature, limits: InputLimits,
) -> Result<Verification> {
    let parameters = PqcSignatureParameters::pure(context, hedging)?;
    public_key.verify(engine, message, signature, &parameters, limits)
}
```

Obtain `PqcPublicKey` from key generation or parse an authenticated SPKI with
`PqcPublicKey::from_spki`. Decode the signature using its explicit algorithm and
provide the same message, mode and context as the signer. This recipe chooses pure
mode. The prehash guide explains the parameter substitution for other modes.
Handle `Verification` separately from operational errors; an unavailable key or
parameter combination is not an invalid-signature verdict.

The software route is explicitly selected. A failed native verification does not
automatically select it. Retain the engine image for its documented lifetime and
respect the synchronous ABI's no-reentry precondition when using its C interface.
Independent calls may use different threads. See the engine's
[detailed services and ownership contract](https://borealcryptosystems.github.io/fe11/0.1.0/verify-engine/README.html) and
[ABI reference](https://borealcryptosystems.github.io/fe11/0.1.0/api/fe11_verify_engine_api/index.html).

[All How To guides](index.md)
