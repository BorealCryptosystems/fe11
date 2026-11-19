# Public cryptographic vectors

Browse the [case manifests by worker mode](CASES.md) for the complete native index.

## Digest fixtures

The digest fixtures contain numerical test data from NIST's ACVP Server,
RFC 1321, and the Bouncy Castle GOST 34.11 test vectors. Each manifest entry
identifies the published source and its selected case, the Fe11 API route,
the input partition, and the expected native call sequence.

NIST data are selected from ACVP Server commit
`975de31eb83d87039ec88934fdc47d8c312b892d`. The selection and text encoding were
prepared on November 14, 2026. The numerical message and digest bytes are
unchanged. The National Institute of Standards and Technology is the source
of those vectors; its complete notice is in `NIST-NOTICE.txt`.

GOST vectors come from Bouncy Castle commit
`32f2b020cb672ac4e501bf7ad8a463dc0ab5e538`,
`core/src/test/java/org/bouncycastle/crypto/test/GOST3411DigestTest.java`.
The complete MIT notice is in `BOUNCY-CASTLE-LICENSE.html`.

MD5 vectors are the numerical examples in RFC 1321, appendix A.5. Their
manifest entries retain the RFC URL and the source-document SHA-256.

A digest fixture has five newline-terminated fields: the decimal PKCS#11
mechanism number, the API route, comma-separated fragment lengths, the input
in hexadecimal, and the expected digest in hexadecimal. Empty messages keep
their empty field. Filenames are the SHA-256 of the exact encoded fixture.
The manifest keeps distinct API and partition cases even when they share a
published vector.
