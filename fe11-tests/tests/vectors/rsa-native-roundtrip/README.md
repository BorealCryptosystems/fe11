# Native RSA ciphertext roundtrips

These fixtures reuse the published RSA2048 components and plaintexts of the
adjacent RSA cipher-boundary corpus. Its manifest retains their provenance and
license. Both public API facades feed the actual randomized encrypted output
into native decryption for lengths0,1 and245. This composition complements the
independent padding/modular reference checks; it does not replace them.

Both imported session objects are retained immediately and explicitly destroyed
on every completed path. No ciphertext, plaintext, private component or
credential is written to the report. A native refusal remains a failed case.
