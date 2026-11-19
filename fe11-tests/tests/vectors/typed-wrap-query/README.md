# Typed wrapping size and capacity

This fixture uses the public key, key-encryption key and exact wrapped result
from RFC 3394 section 4.1. Each explicit request has capacity 0, 23, 24 or 25;
the typed API performs one size query and one output call. A refusal must retain
required length 24 and the actual capacity. Successful output must equal the
published 24 bytes and report the AES-KW profile without unrelated metadata.
The two imported objects remain owned through all requests and cleanup.

Reference: https://www.rfc-editor.org/rfc/rfc3394, copyright 2002 The Internet
Society. Test-vector data only; no RFC reference implementation is included.
