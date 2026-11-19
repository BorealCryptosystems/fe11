# Typed ECDH KDF requests

Each case generates and admits a real P-256 agreement pair, then calls the public
`Session::derive_ecdh` API with a valid published peer. The three selectors are
`X963Sha256`, `ConcatSha256` and `Native(CKD_SHA256_KDF)`.

For this module recipe they must return native `CKR_MECHANISM_PARAM_INVALID`.
This is refusal coverage of an unavailable KDF, not a successful shared-secret
known answer. The independent published shared-secret controls are retained in
the ECDH fixtures. A SHA-256 operation checks that the session remains usable.
Both generated objects are retained before admission is inspected and destroyed
on every exit; an unexpectedly derived object is retained for cleanup as well.
