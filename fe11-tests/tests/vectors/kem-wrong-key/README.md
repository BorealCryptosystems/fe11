# KEM key-class mismatch

The public RSA2048 test key is imported with the requested ENCAPSULATE or
DECAPSULATE usage. Import is a prerequisite, reported separately from KEM.
The decapsulation ciphertext is an unchanged ML-KEM-512 ACVP vector. Output
templates request a32-byte generic secret and preserve all required attributes.
EncapsulateKey must report KEY_TYPE_INCONSISTENT; DecapsulateKey must report
UNWRAPPING_KEY_TYPE_INCONSISTENT. A different native error remains a failure.
Unexpectedly returned objects are retained and destroyed during cleanup.
