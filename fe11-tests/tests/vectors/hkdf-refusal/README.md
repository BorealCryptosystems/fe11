# HKDF native refusal contracts

The base is a real, public session `CKK_GENERIC_SECRET` with `CKA_DERIVE=true`.
Its 32-byte length matches SHA-256 as required by PKCS#11 3.2 section 6.62.3.
Both extract and expand are enabled. The output length is 32 bytes, the salt is
absent, and the two public constructors use binary info or an absent info pointer.
Both `CKM_HKDF_DERIVE` and `CKM_HKDF_DATA` are submitted through each session facade.
The data output template excludes secret-key attributes.

These are native refusal tests for the configured recipe's absent mechanisms.
No missing `CKK_HKDF` key factory is inferred from a successful generic-key import.
No derived bytes or positive HKDF result are claimed. A returned creation remains
owned for cleanup and is a failure of this refusal expectation.
