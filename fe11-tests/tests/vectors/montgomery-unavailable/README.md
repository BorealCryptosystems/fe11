# Unavailable Montgomery generator

The typed X25519 and X448 generation routes reach the native module. The selected
recipe lacks CKM_EC_MONTGOMERY_KEY_PAIR_GEN, so these cases require its exact
CKR_MECHANISM_INVALID refusal. They do not claim a key was generated, or replace
the separate nominal generation and agreement obligations. Cleanup retains
ownership and searches only each case's assigned namespace.
