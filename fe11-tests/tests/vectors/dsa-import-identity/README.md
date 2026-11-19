# DSA import identities

The numerical key and SHA-1 signature over `sample` come from
[RFC 6979 Appendix A.2.1](https://www.rfc-editor.org/rfc/rfc6979#appendix-A.2.1).
Only public test data are used; the private scalar must never be used for
operational cryptography. The test imports and reads a domain object, uses its
returned parameters to import both keys, verifies the published signature and
signs with the private key. A separate OpenSSL process checks the generated
signature with a changed-signature negative control. Native DSA need not use
the deterministic nonce of the RFC and its signature need not equal the vector.
