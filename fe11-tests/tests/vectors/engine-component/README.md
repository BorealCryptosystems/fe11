# Verification component known answers

These published numerical vectors exercise the optional verification component's
public C ABI. They retain their original sources and attribution in the manifest.
RSA SubjectPublicKeyInfo and ECDSA signature encodings preserve the published
integers exactly. Original message bytes are passed to digest-based verification;
prehashed PKCS#11 inputs are deliberately separate from these message contracts.
No private key is included in the component verification fixtures.

Every verification requires successful preparation and completion, then the exact
published validity verdict. An engine error is not accepted as an invalid signature.
The concurrently open PKCS#11 module must receive no verification or digest calls.
