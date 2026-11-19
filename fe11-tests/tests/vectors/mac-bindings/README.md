# MAC binding fixtures

These fixtures use the public HMAC-SHA256 key, message and answer from
[RFC 4231 section 4.6](https://www.rfc-editor.org/rfc/rfc4231#section-4.6).
The runner checks the published answer, changes one message bit or one key bit
separately, then checks successful reuse of the same session. Both input routes
and both public session owners use the same bytes. Fixtures are public test
material, distributed with the suite under Apache-2.0.
