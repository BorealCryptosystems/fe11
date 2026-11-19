# Multipart post-quantum signatures

These cases preserve the exact keys, message, context and deterministic
signature from the attributed external NIST ACVP signing vectors. Only the
message partition changes: first half, empty part, second half. Both Session
and AdvancedSession submit the original message without a software prehash.
Signing must reproduce the published signature. Verification accepts that
signature and rejects a single-bit change in it through the native Final call.
