# DSA verification with a different valid key

These cases preserve the published NIST ACVP DSA verification tuple except for
the public value y. The replacement is the generator g of the same subgroup;
its encoding has the same width. The independent public DSA equation validates
the original tuple and rejects the replacement before the fixture is retained.

Both session facades must reach C_Verify and receive CKR_SIGNATURE_INVALID.
A failed import, an invalid key or a signature-length refusal does not satisfy
this oracle. Existing unchanged positive controls remain linked by digest.
