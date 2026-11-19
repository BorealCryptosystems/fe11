# Explicit verification-engine identity

The runner verifies the selected existing engine file against its recorded
digest. The case changes one bit of the expected digest passed to Fe11 and
requires the exact identity-mismatch error. Existing positive loading controls
remain linked. No file is patched or replaced. A real PKCS#11 module remains
open during this check, and its counters must not change on refusal.
