# RSA wrapping permission

The public RSA fixtures and attribution are shared with the unwrapping cases.
A successful native Wrap/Unwrap control must recover the exact original bytes
before the same public key with CKA_WRAP=false is exercised. Randomized wrapped
bytes are not compared to an unrelated deterministic envelope.
