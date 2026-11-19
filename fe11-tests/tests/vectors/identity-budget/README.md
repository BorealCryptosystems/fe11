# Digest ticket identities and import budgets

The digest cases import a real public AES test key before producing a foreign
or consumed SHA-256 ticket. The original digest and receiver remain usable.
The import-budget case uses a public NIST ML-DSA key with an explicitly
undersized native mechanism array budget on the Linux 64-bit target.
