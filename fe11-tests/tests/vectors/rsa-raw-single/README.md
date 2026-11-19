# Raw RSA single-call fixtures

The public RSA-2048 SHA-256 reference signature is reused for CKM_RSA_PKCS
with the exact RFC 8017 DigestInfo supplied by the caller. Each owner signs
and verifies the reference bytes through Single only. No raw Multipart
capability is inferred. The fixture signature was independently checked by
RSA public exponentiation and PKCS#1 v1.5 encoding. Original key and vector
attributions are retained in the manifest.
