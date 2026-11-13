# Find RSA keys, generate a pair and sign

## Search by application identity

Searches are templates, not uniqueness guarantees. This recipe selects private
RSA objects with an exact `CKA_ID`. Set `AttributeTemplateLimits` for three
attributes, their scalar storage and ID bytes; choose a nonzero batch size and
the application's result bound. `maximum_objects: None` chooses an unbounded
result count, subject to configured object resources.

```rust,no_run
use fe11::*;
use std::num::NonZeroUsize;

pub fn find_private_rsa(
    session: &Session, id: &[u8], batch_size: NonZeroUsize,
    maximum_objects: Option<usize>, template_limits: AttributeTemplateLimits,
) -> Result<NativeObjectMatches> {
    let template = [
        AttributeInput {
            attribute: AttributeType::Standard(StandardAttribute::CLASS),
            value: AttributeInputValue::Unsigned(fe11_sys::CKO_PRIVATE_KEY as u64),
        },
        AttributeInput {
            attribute: AttributeType::Standard(StandardAttribute::KEY_TYPE),
            value: AttributeInputValue::Unsigned(fe11_sys::CKK_RSA as u64),
        },
        AttributeInput {
            attribute: AttributeType::Standard(StandardAttribute::ID),
            value: AttributeInputValue::Bytes(id),
        },
    ];
    session.find_native_objects(
        &template,
        template_limits,
        SearchPlan { maximum_objects, batch_size },
    )
}
```

Inspect `matches.as_slice()`. If the application requires a unique key, accept
exactly one match and report zero or multiple matches as an application selection
error. Retain that `NativeObjectRef` for the operation. To verify, search for the
corresponding public RSA object by using `CKO_PUBLIC_KEY` in an otherwise explicit
template. Authenticate the public key's association through your application.

## Generate a pair with explicit attributes

```rust,no_run
use fe11::*;

pub fn generate_rsa(
    session: &Session, mut spec: KeySpec,
) -> Result<CreatedObjects<KeyPair>> {
    spec.public_usages.verify = Some(true);
    spec.private_usages.sign = Some(true);
    session.generate_rsa_signing_key_pair(spec)
}
```

Construct [KeySpec](https://borealcryptosystems.github.io/fe11/0.1.0/api/fe11/struct.KeySpec.html) with the desired `bits`, `exponent`,
`id`, `label`, persistence, visibility, private protection and separate public and
private observation plans. For example, an application's selected RSA-3072 key
uses `bits: 3072` and `exponent: 65537`. These are application choices, not library
defaults. Start usage requests from `KeyUsageRequest::omitted()` and set the
requested flags; this helper adds public verification and private signing.

`ObjectVisibility` controls `CKA_PRIVATE`, independently of public/private key
class. Set `CurrentKeyProtection` to the desired sensitive/extractable attributes.
`ObjectAdmission` selects searches and observations after creation; provision its
read capacities for the public representation and requested attributes. See
[ObjectAdmission](https://borealcryptosystems.github.io/fe11/0.1.0/api/fe11/struct.ObjectAdmission.html) for all observation fields.

Treat `CreatedObjects<KeyPair>` as a creation outcome: native objects can exist
even when a requested observation fails. Preserve `objects`, `observation` and
`remainder`. `into_observation()` returns a failure retaining the created objects;
do not regenerate a key merely because its metadata observation failed. The
generated pair's `ObjectRef::native_object()` gives the native-operation reference.

## Sign and verify the original message

```rust,no_run
use fe11::*;

pub fn sign_message(
    session: &Session, key: &NativeObjectRef, message: &[u8],
    limits: InputLimits, signature_capacity: usize,
) -> Result<NativeSignature> {
    session.sign_native(
        key,
        NativeSignatureParameters::Parameterless(NativeSignatureAlgorithm::SHA256_RSA_PKCS),
        MessageRoute::Single,
        &[message],
        limits,
        signature_capacity,
        None,
    )
}

pub fn verify_message(
    session: &Session, key: &NativeObjectRef, message: &[u8],
    signature: &[u8], limits: InputLimits,
) -> Result<()> {
    session.verify_native(
        key,
        NativeSignatureParameters::Parameterless(NativeSignatureAlgorithm::SHA256_RSA_PKCS),
        MessageRoute::Single,
        &[message],
        signature,
        limits,
        None,
    )
}
```

The combined `SHA256_RSA_PKCS` mechanism hashes the original message at the
module. Supply the message, not an external digest. Select `signature_capacity`
from the chosen key's modulus width (384 bytes for RSA-3072). Handle a reported
capacity requirement using its retained continuation, rather than starting an
unrelated second operation. These helpers select a single-part route and no
contextual authentication; use the explicit authentication argument when the key
requires it.

`NativeSignature::as_bytes()` borrows the result. `verify_native` returns `Ok(())`
for a successful native verification and an error for a native refusal. Preserve
that native code. Destroy persistent objects explicitly when retiring them;
dropping a Rust reference alone does not destroy a token object.

[All How To guides](index.md)
