# Generate and use ML-DSA and SLH-DSA keys

Fe11 represents ML-DSA's three parameter sets and SLH-DSA's twelve parameter sets
explicitly. Use a module implementing the selected PKCS#11 PQC generation and
signature mechanisms. Request the PKCS#11 3.2 interface when that is your
deployment contract. A mechanism listing is a capability observation; generation
and signing still return the module's decision for the exact key and parameters.

## Select and generate

The examples below choose ML-DSA-65 and SLH-DSA-SHA2-128s as concrete alternatives.
Choose the parameter set for your protocol; it is not inferred from key size.

```rust
use fe11::*;

pub fn signature_algorithms() -> [PqcAlgorithm; 2] {
    [PqcAlgorithm::MlDsa(MlDsaParameterSet::MlDsa65),
     PqcAlgorithm::SlhDsa(SlhDsaParameterSet::Sha2_128s)]
}

pub fn generate_signature_pair(
    session: &Session, mut spec: PqcKeySpec, algorithm: PqcAlgorithm,
    public_policy: MechanismAttributes<'_>, private_policy: MechanismAttributes<'_>,
    protection: CurrentKeyProtection, public_visibility: ObjectVisibility,
) -> Result<CreatedObjects<PqcKeyPair>> {
    spec.algorithm = algorithm;
    spec.public_usages.verify = Some(true);
    spec.private_usages.sign = Some(true);
    session.generate_pqc_key_pair(
        spec, public_policy, private_policy, protection, public_visibility,
    )
}
```

Supply a [PqcKeySpec](https://borealcryptosystems.github.io/fe11/0.1.0/api/fe11/struct.PqcKeySpec.html) containing the ID, label,
persistence, private visibility, usages and both `ObjectAdmission` plans. The
helper preserves those choices while selecting the algorithm and enabling sign
and verify. Supply public/private `MechanismAttributes`, private
`CurrentKeyProtection` and public visibility separately. Requests for native
attributes and requested observations are independent. Size public metadata
storage for at least `algorithm.public_key_length()` and the native identity
scalars, plus any additional attributes your plans read.

Preserve the complete `CreatedObjects<PqcKeyPair>` result until its observation
and remainder have been handled. A successful observation gives `pair.private`,
`pair.public` and `pair.public_key`. The last is a public representation that can
be encoded with `to_spki()` for another verifier. Public-key distribution still
requires an authenticated application channel.

## Sign and verify in pure mode

```rust
use fe11::*;

pub fn sign_pure(
    session: &Session, key: &PqcSigningKey, message: &[u8], context: &[u8],
    hedging: PqcHedging, limits: InputLimits,
) -> Result<PqcSignature> {
    let parameters = PqcSignatureParameters::pure(context, hedging)?;
    session.sign_pqc(key, &parameters, message, limits)
}

pub fn verify_pure(
    session: &Session, key: &PqcVerificationKey, message: &[u8], context: &[u8],
    hedging: PqcHedging, signature: &PqcSignature, limits: InputLimits,
) -> Result<Verification> {
    let parameters = PqcSignatureParameters::pure(context, hedging)?;
    session.verify_pqc(key, &parameters, message, signature, limits)
}
```

Use the original message and the same binary context on both sides. The context
contains at most 255 bytes and separates application uses of the key. Select
`PqcHedging::Preferred`, `Required` or `DeterministicRequired` explicitly for the
protocol. The requested mode is forwarded to the module; its refusal is retained.
For a pure PKIX signature profile, `PqcSignatureParameters::pkix(hedging)` selects
the empty context. General application messages can use their own protocol context.

Read signature bytes with `PqcSignature::as_bytes()`. On receipt,
`PqcSignature::from_bytes(algorithm, bytes)` checks their representation before
verification. Handle the returned `Verification` verdict as well as operational
errors. A successful mathematical verification establishes the signature/message
relationship; bind the public key to identity and authorization in your protocol.

For `CKA_ALWAYS_AUTHENTICATE`, use `sign_pqc_with_context` with the key's
`ContextAuthentication`. That login context is distinct from the signature
context above. See [prehash modes](pqc-prehash.md) for hashing alternatives and
[software verification](verification-engine.md) for the optional engine.

Reference: [PqcAlgorithm](https://borealcryptosystems.github.io/fe11/0.1.0/api/fe11/enum.PqcAlgorithm.html),
[PqcSignatureParameters](https://borealcryptosystems.github.io/fe11/0.1.0/api/fe11/struct.PqcSignatureParameters.html).

[All How To guides](index.md)
