# Object creation on SoftHSM

Each [case](manifest.json) starts with a valid template, changes one field, and records the native result and cleanup. Its attribute rules identify the class, attribute and PKCS #11 edition. The following observations apply to the tested OpenSSL configurations.

| Template change | Expected | Observed |
| --- | --- | --- |
| RSA private key, omit the public exponent | Incomplete template | The token creates the object. The case does not read the missing attribute back. |
| DH or DSA domain parameters, omit the key type | Incomplete template | The token returns `CKR_ATTRIBUTE_VALUE_INVALID`. |
| RSA private key, omit the CRT coefficient | An incomplete-template refusal, or a usable imported key | Import succeeds and the subsequent signature call returns `CKR_GENERAL_ERROR`. See the [usable-key case](../optional-rsa-crt-import/manifest.json). |

The exponent case follows the RSA private-key table in PKCS #11 Base 2.40 and 3.0, whose footnote 1 requires the attribute at creation. The corresponding Current Mechanisms tables omit that footnote. The Base text explicitly adds the public exponent to the required RSA private-key attributes. The consolidated 3.1 and 3.2 tables include footnote 1. The separate requirement to store the exponent does not establish whether the token computed it on import.

The coefficient has no footnote requiring it at creation. Under the object-creation template rules, a token that lacks sufficient material can return `CKR_TEMPLATE_INCOMPLETE`. Such a result records only the native refusal. A successful import is followed by a signature check. The import alone establishes no usable-key result.

See [Base 2.40](https://docs.oasis-open.org/pkcs11/pkcs11-base/v2.40/os/pkcs11-base-v2.40-os.html), [Current Mechanisms 2.40](https://docs.oasis-open.org/pkcs11/pkcs11-curr/v2.40/os/pkcs11-curr-v2.40-os.html), [Base 3.0](https://docs.oasis-open.org/pkcs11/pkcs11-base/v3.0/os/pkcs11-base-v3.0-os.html) and [Current Mechanisms 3.0](https://docs.oasis-open.org/pkcs11/pkcs11-curr/v3.0/os/pkcs11-curr-v3.0-os.html).
