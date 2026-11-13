# SoftHSM public integration suite

This workspace package exercises ten public API scenarios using a real SoftHSM
module: discovery, authentication, invalid PIN, single and multipart SHA-256,
RSA signing and verification, invalid signature, AES-GCM, invalid GCM tag, and
object search before and after destruction. Each scenario creates a fresh token
in a separate process. Keys are session objects and are explicitly destroyed.
Operation, cleanup and child-process exit outcomes are independent fields of
a bounded TSV record.

The SHA-256 `abc` vector is published in the NIST secure hash examples:
https://csrc.nist.gov/projects/cryptographic-standards-and-guidelines/example-values
Native operation/error contracts follow PKCS#11 Base 2.40, sections 5.4–5.11 and 5.13, and Current Mechanisms 2.40, AES-GCM:
https://docs.oasis-open.org/pkcs11/pkcs11-base/v2.40/os/pkcs11-base-v2.40-os.html
https://docs.oasis-open.org/pkcs11/pkcs11-curr/v2.40/os/pkcs11-curr-v2.40-os.html
For the pinned SoftHSM recipe, an altered GCM tag returns
`CKR_ENCRYPTED_DATA_INVALID` from `C_Decrypt`. The intact envelope must succeed
before and after that rejection. This expectation is grounded in the module's
SymDecrypt implementation, rather than accepting any error as an authentication
failure. The suite uses `decrypt_classic_aead`, which preserves the native code;
the convenience `decrypt_aead` API instead reports `InvalidCiphertext` for native
validity failures. No plaintext can be returned by the rejected `Result`.

The supported suite platform is Linux. Python 3.11+, Git, Rust's installation
prerequisites and the native build tools described by `ci/scripts/soft_hsm.py`
are required. The CI driver installs the exact selected Rust toolchain and
builds SoftHSM from its pinned upstream commit without patches.

The source identity is upstream commit
`31293555b3822fcd687057e0b64462a114359c17`, an untagged revision with the legacy
function-table version and GCM error classification used by this suite. The
utility reports `2.7.0`; the commit in the report identifies the actual sources.
Source: https://github.com/softhsm/SoftHSMv2/commit/31293555b3822fcd687057e0b64462a114359c17

```sh
python3 ci/scripts/job.py softhsm --rust 1.81.0 --root /absolute/new/job-directory
python3 ci/scripts/job.py softhsm --rust 1.100.0 --root /absolute/another/job-directory
```

The root must be new. Its token configuration path must contain no `#`, `=`,
carriage return or newline; the serialized `directories.tokendir` line must
fit SoftHSM's 1023-byte configuration line limit. Each complete run requires all ten named results and
fails on missing capabilities, crashes, malformed results or cleanup failures.
The driver writes only allowlisted evidence under `reports/`. Token directories,
PINs and key material are never report artifacts. PINs are random and ephemeral;
the administrative utility receives them through arguments visible to processes
of the same runner. Under GitHub Actions they are masked before use. Native
modules run within their test process; the disposable job is the isolation
boundary. A hard runner timeout may prevent final cleanup or artifact upload.

`cargo test --locked --release -p fe11-ci-softhsm --test integration` runs the
supervisor after the driver has configured the module, utility, digest and fresh
root. Its child selector is an internal supervisor protocol, not an acceptance
filter. The package uses only `std`, `fe11` and `fe11-sys`, and is not published
to the package registry. The library's default workspace member stays unchanged.
