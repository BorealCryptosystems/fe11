# RSA cipher boundaries

The public RSA-2048 test key is shared with the adjacent RSA known-answer
collection. PKCS#1 v1.5 inputs have lengths 0, 1 and 245 bytes; a 246-byte request
tests the encoding limit. Randomized ciphertext is independently decrypted in
Python and its complete encoding and message checked. Native decryption uses
separately calculated public ciphertext vectors with nonzero deterministic test
padding; these are test fixtures, not application encryption recommendations.

Raw RSA uses the representative n-1 with an independently computed result.
Representatives n and n+1 must be rejected, never reduced modulo n. The pinned
implementation reports GENERAL_ERROR for those native backend refusals. The
length-overflow case retains the DATA_LEN_RANGE oracle independently, even if
the implementation returns another error.

Each direction and boundary has its own process and receipt. Independent
decoding and native decryption are distinct assertions; they are not described
as a native round trip of the same randomized ciphertext.
