# Standard nested input graphs

These positive cases use exact PKCS#11 ABI offsets and initialized padding.
OAEP label pointers are NULL with zero length, one-past-end with zero length,
or a nonempty span ending at an owned block boundary. AES CBC ENCRYPT DATA
uses the published NIST SP800-38A F.2.1 first block at an interior offset.
RSA-AES key unwrap follows two relocations: the aligned OAEP structure and
its empty label. Existing public RSA envelopes retain their provenance.

Only input regions alias or share storage. No malformed unsafe graph or
writable parameter output is submitted. Exact output bytes or created-object
values are checked independently; declaration and cleanup are observed separately.
