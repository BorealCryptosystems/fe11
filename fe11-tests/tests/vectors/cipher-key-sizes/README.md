# Explicit cipher key sizes

These cases complement the existing known answers with AES-CTR at 128 and
256 bits, AES-CBC-PAD at 192 and 256 bits, and two-key TDEA under the explicit
`CKK_DES2` object type. ECB, CBC and CBC-PAD retain their distinct parameters.
Expected output comes from PyCryptodome 3.23.0 using public test keys. The
nine-field and thirteen-field forms carry an explicit key-type suffix; older
fixture forms retain their original interpretation.
