# Edwards context boundaries

Public RFC 8032 test keys and empty messages are reused with explicit binary
contexts of length 1 and 255. Expected signatures are computed with the
independent PyCryptodome 3.23.0 implementation after checking its result against
the published empty-message vector. Both Ed25519ctx/Ed25519ph and Ed448/Ed448ph
are represented. These new signatures are generated references, not published
RFC signatures. The worker passes the original message, prehash flag and exact
context to the native API and compares every signature byte. It performs no
local prehash and no fallback. Session and AdvancedSession are distinct cases.

RFC 8032 copyright 2017 IETF Trust and the persons identified as authors.
Source: https://www.rfc-editor.org/rfc/rfc8032, sections 7.1 and 7.4.
Only public vector data is reproduced; no implementation source is copied.
