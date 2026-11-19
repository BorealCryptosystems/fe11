# Generated-key protection combinations

Each structurally distinct generator with an established native prerequisite is
exercised with all eight PRIVATE / SENSITIVE / EXTRACTABLE combinations on its
secret or private output. Other template fields come unchanged from a successful
generation control. Key-size, parameter-set and cryptographic-use partitions
belong to their separate generation cases; these protection cases vary the
three Booleans, not those independent axes.

The worker compares each requested attribute, LOCAL, KEY_GEN_MECHANISM,
ALWAYS_SENSITIVE and NEVER_EXTRACTABLE. It also reads the protected secret field
(RSA PRIVATE_EXPONENT, otherwise VALUE), requiring ATTRIBUTE_SENSITIVE whenever
SENSITIVE is true or EXTRACTABLE is false, and nonempty available bytes otherwise.
These generated values remain in owned buffers and are never printed.

Domain-parameter objects have no secret/private protection tuple. The optional
GOST prerequisite remains separately reported as unavailable, with no PASS.
