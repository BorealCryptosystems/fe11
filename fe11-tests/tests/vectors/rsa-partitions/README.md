# RSA multipart fixtures

The fixed public RSA-2048 key and PKCS#1 v1.5 SHA-256 answer are reused
from the RSA reference vectors with their original attribution. The message
`abc` is supplied whole to Single and as empty / `a` / empty / `bc` / empty
to Multipart. Signing must return the same exact bytes; verification checks
both the correct signature and a changed signature. Each Init, Update and
Final call is observed independently. These keys are public test material.
