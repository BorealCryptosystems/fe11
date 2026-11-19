# Native initialization refusals

Real AES, generic-secret and RSA public keys exercise each initialization route independently on PKCS#11 3.2. The observer includes later message and verification entry points to detect fallback or unexpected continuation. These cases assert the configured recipe's native FUNCTION_NOT_SUPPORTED result, not positive cryptographic coverage. Session objects are public and need no login.
