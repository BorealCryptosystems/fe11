# ML-KEM ciphertext length boundaries

Each case retains a published ACVP decapsulation key and mutates only ciphertext
length: empty, one byte short, or one appended zero. The unchanged tuple remains
a separate known-answer case. Both Session and Advanced routes and all three
parameter sets are explicit.

The PKCS#11 oracle is CKR_WRAPPED_KEY_LEN_RANGE. Other native codes remain
failures for attribution, including GENERAL_ERROR, which does not establish
that no object was created. Public vector keys are test data.
