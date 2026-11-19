# Multipart and AEAD input guards

Each case uses a real generated native key. Refusals precede the specified
native cryptographic initialization. Exact counters, an independent observer,
an idle SHA-256 known-answer control and explicit cleanup remain separate checks.
The generated private signing key is non-extractable and never serialized.
