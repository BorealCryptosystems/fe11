# ECDH peer boundaries

The published P-256 scalar and peer control come from the adjacent ECDH vector
collection, with the same source attribution. Each request changes only the peer:
empty, the uncompressed encoding of (0,0), a one-byte truncation, or a published
P-384 point. The private-key curve remains P-256. CKD_NULL, absent shared data and
the 32-byte output template remain fixed.

The pinned implementation rejects the empty descriptor at parameter validation;
its cryptographic backend rejects the three invalid points with GENERAL_ERROR.
That native error does not establish non-creation. The test preserves the error's
uncertainty and owns any object unexpectedly returned until explicit cleanup.
These observations are not interchangeable with a normatively preferred native
error or with a positive agreement result.
