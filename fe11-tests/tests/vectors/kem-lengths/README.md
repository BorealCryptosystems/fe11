# ML-KEM ciphertext length boundaries

Each case retains a published ACVP decapsulation key and mutates only ciphertext
length: empty, one byte short, or one appended zero. The unchanged tuple remains
a separate known-answer case. Both Session and Advanced routes and all three
parameter sets are explicit.

The negative oracle requires rejection by C_DecapsulateKey without publication
of a shared secret. It accepts CKR_WRAPPED_KEY_LEN_RANGE or CKR_GENERAL_ERROR,
both permitted native returns, and records the exact code. GENERAL_ERROR does
not establish non-creation: ObjectsMayRemain and may_have_effect are preserved.
Cleanup is required independently of the body verdict. Public vector keys are test data.
