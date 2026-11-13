# Establish native shared keys with ML-KEM

ML-KEM creates a shared secret and a public encapsulation ciphertext. Fe11 keeps
the shared secret as a native key object. Select a PKCS#11 3.2 module exposing
`C_EncapsulateKey`, `C_DecapsulateKey`, ML-KEM and the chosen parameter set.

## Generate the recipient's key pair

```rust,no_run
use fe11::*;

pub fn generate_kem_pair(
    session: &Session, mut spec: KemKeySpec, parameter_set: MlKemParameterSet,
    public_policy: MechanismAttributes<'_>, private_policy: MechanismAttributes<'_>,
    protection: CurrentKeyProtection, public_visibility: ObjectVisibility,
) -> Result<CreatedObjects<KemKeyPair>> {
    spec.parameter_set = parameter_set;
    spec.public_usages.encapsulate = Some(true);
    spec.private_usages.decapsulate = Some(true);
    session.generate_kem_key_pair(
        spec, public_policy, private_policy, protection, public_visibility,
    )
}
```

For an ML-KEM-768 deployment, pass `MlKemParameterSet::MlKem768`. The other explicit
choices are ML-KEM-512 and ML-KEM-1024. Configure `KemKeySpec` with ID, label,
persistence, visibility and observation plans, and supply the independent native
mechanism/protection requests. Allow the public observation to read at least
`parameter_set.public_key_length()` bytes. Both public and private metadata budgets
must also cover three native `CK_ULONG` identity scalars, using the selected target's
ABI width. Additional requested attributes need their own read capacity. Handle
`CreatedObjects<KemKeyPair>` as described for [key creation](keys-and-signatures.md).

The recipient retains `pair.private`. Publish `pair.public.public_key().to_spki()`
through an authenticated channel. The sender can import that public key through
`Session::import_kem_public_key`, with its explicit identity, native
attributes and observation choices. Authenticate the recipient key before use.

## Encapsulate at the sender

```rust,no_run
use fe11::*;

pub fn encapsulate(
    session: &Session, recipient: &KemEncapsulationKey, output: KemSharedKeySpec,
) -> Result<CreatedObjects<KemEncapsulation>> {
    session.encapsulate_kem(recipient, output)
}
```

Select `KemSharedKeySpec` for the shared key's intended use: an explicit 32-byte
symmetric key, or an HKDF base key. This selection does not add an implicit KDF.
For a protocol that derives traffic keys, select the HKDF route and apply that
protocol's explicit salt, context information and key separation.

After handling the creation observation, retain `KemEncapsulation::shared_key`
locally and transmit `ciphertext.as_bytes()`. The ciphertext length is 768, 1088
or 1568 bytes for ML-KEM-512, -768 or -1024 respectively; use
`MlKemParameterSet::ciphertext_length()` when framing it. The native shared secret
is 32 bytes for all three sets. Do not log or export secret-key material.

## Decapsulate at the recipient

```rust,no_run
use fe11::*;

pub fn decapsulate(
    session: &Session, recipient: &KemDecapsulationKey,
    ciphertext: &[u8], output: KemSharedKeySpec,
) -> Result<CreatedObjects<KemSharedKey>> {
    let ciphertext = KemCiphertext::from_bytes(recipient.parameter_set(), ciphertext)?;
    session.decapsulate_kem(recipient, &ciphertext, output)
}
```

The typed decoder checks the ciphertext width for the private key's parameter
set. The receiver selects the corresponding shared-key use and preserves the
creation result. Use the resulting native key in the consuming protocol.

ML-KEM uses implicit rejection: successful decapsulation does not establish that
the ciphertext was authentic or that the sender possessed an expected identity.
The protocol must authenticate the exchange and perform its required key
confirmation. A public ciphertext is not itself a proof of peer identity.

## Creation and cleanup

Both operations create native objects. Preserve `objects`, failed observations
and any `remainder`; a reported required output size does not prove that nothing
was created or authorize an automatic retry. Session objects expire with successful
session closure; destroy persistent objects explicitly. Custom native destination
templates are available through `encapsulate_native` and `decapsulate_native` with
`NativeKemParameters::MlKem` and `GenerationTemplate`.

Reference: [KemSharedKeySpec](https://borealcryptosystems.github.io/fe11/0.1.0/api/fe11/enum.KemSharedKeySpec.html),
[KemKeySpec](https://borealcryptosystems.github.io/fe11/0.1.0/api/fe11/struct.KemKeySpec.html),
[NativeKemParameters](https://borealcryptosystems.github.io/fe11/0.1.0/api/fe11/enum.NativeKemParameters.html).

[All How To guides](index.md)
