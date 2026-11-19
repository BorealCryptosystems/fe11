# Edwards message and generated-key boundaries

The empty-message fixtures reproduce the published data from RFC8032 section7.1
(Ed25519, TEST1) and section7.4 (Ed448, Blank). Signature and verification are
separate cases on Session and AdvancedSession. An empty context is passed both
as a present empty slice and as None; the message is always the exact empty byte
string. Public-key imports retain raw RFC8032 bytes as specified by PKCS#11.

The generated-key cases use fresh pairs and `abc`. Each pair signs and verifies,
rejects a changed signature and verifies the original again. Both domain
attributes are read back exactly. The public encoding must contain32 or57 raw
bytes; a DER wrapper is reported as a mismatch and is never silently stripped.
All created objects are owned until cleanup, including after a failed assertion.

RFC8032 copyright (c)2017 IETF Trust and the persons identified as its authors.
The source is https://www.rfc-editor.org/rfc/rfc8032 and is subject to BCP78 and
the IETF Trust Legal Provisions at https://trustee.ietf.org/license-info.
Only published test-vector data is reproduced; no reference implementation code
is copied. Published test keys are public fixtures, never operational secrets.
