# Multipart Edwards signatures

A generated Ed25519 key pair first signs and verifies the original message
`abc` in a single call. The same key is then used with the three message parts
`a`, `b`, `c`. A successful multipart signature must equal the deterministic
single-part signature. Verification uses that successfully verified signature.

PKCS#11 defines multipart EdDSA. A module refusal is recorded as a failed
nominal operation, with its native call and code; it is never converted into a
positive signature result. Generation isolates multipart support from public
point import encoding. All created objects are retained for independent cleanup.
