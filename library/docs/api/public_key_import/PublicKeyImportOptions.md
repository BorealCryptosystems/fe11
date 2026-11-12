Explicit storage and usage requests for an imported public key.

These requests do not grant private-key usage or certificate trust. Native
refusals are preserved; readback follows the separate observation selection.
Permitting modification
does not make the key's cryptographic material modifiable under PKCS#11.

Persistence and destruction are explicit requests. Native copy permission
does not establish support for a particular copy or migration operation.
The returned creation result preserves native objects independently of the
optional descriptive observation. Its caller must retain the object references
for reconciliation and explicit cleanup, including when that observation fails.

```no_run
use fe11::{
    MechanismAttributes, MechanismRequest, MechanismObservationPlan,
    ObjectVisibility, PublicKeyImportOptions, Result, Session,
};
fn import(
    session: &Session,
    spki: &[u8],
    admission: fe11::ObjectAdmission,
) -> Result<fe11::CreatedObjects<fe11::PqcVerificationKey>> {
    let options = PublicKeyImportOptions {
        metadata: fe11::PublicImportMetadata::Exact { id: b"my-key".to_vec(), label: b"verification".to_vec() },
        usages: fe11::KeyUsageRequest {
            verify: Some(true),
            ..fe11::KeyUsageRequest::omitted()
        },
        persistent: false,
        destroyable: true,
        admission,
        visibility: ObjectVisibility::Private,
        modifiable: true,
        copyable: false,
    };
    session.import_pqc_verification_key(
        spki, MechanismAttributes {
            request: MechanismRequest::Omitted,
            admission: MechanismObservationPlan::NotRequested,
        }, options,
    )
}
```
