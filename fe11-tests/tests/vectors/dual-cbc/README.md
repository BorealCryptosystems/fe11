# Classic dual-operation fixtures

Eight explicit public starters use AES-128-CBC and SHA-256 or HMAC-SHA256.
Keys, IVs and input blocks are public all-zero test values. An independent
completed SHA256(abc) is retained while the second session receives the expected
second-Init refusal. No dual Update, Final or successful dual output is inferred.
The HMAC input for decryption is the independently decoded CBC plaintext.
These generated public fixtures are distributed under Apache-2.0.
