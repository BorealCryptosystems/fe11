# Generated RSA signatures and the verification component

The positive signature is byte-for-byte the deterministic result asserted by the
native SHA-256 RSA PKCS1 signing scenarios. The component verifies that exact
public key, message and signature. Separate changed-message and changed-signature
controls must be rejected. Native signing is not repeated by these cases.
The component and native module may share OpenSSL ancestry; the fixed signature
also has an independent integer/encoding reference. This tests the component ABI.
