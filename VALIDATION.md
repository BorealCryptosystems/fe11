# Interoperability reporting

Fe11 interfaces with PKCS#11 modules selected by the application. An interoperability
result describes a particular package, module, platform, mechanism, key and set of
parameters. Include those details when reporting a result or an unexpected behavior.

## Information to include

- Fe11 and fe11-sys versions, target triple, Rust version and enabled features.
- Native module name and version, selected PKCS#11 interface and initialization options.
- Mechanism, key type, relevant non-secret attributes and exact public parameters.
- Call sequence, returned native codes and Fe11's typed diagnostics.
- Expected behavior with the applicable PKCS#11 specification section.
- Cleanup outcomes and whether the result can be reproduced.

Remove credentials, PINs, private keys, identifying token data and other sensitive
material before sharing a report. Send suspected vulnerabilities through the
[private security reporting channel](SECURITY.md).

## Interpret results in context

Distinguish a native refusal, an unavailable module capability, an interface or
ownership error, and a cryptographic verification result. A mechanism advertised
by a module still has key and parameter requirements. Native errors may leave
operation state or uncertain object effects; preserve the associated diagnostics.

When comparing implementations, use the same native module, PKCS#11 interface,
initialization mode, session state, attributes, inputs and operation sequence.
PKCS#11 specifies the expected semantics; another wrapper is an independent
observation of the same native interface.

The supported ABI profiles are Linux x86_64 GNU and Windows x86_64 MSVC, with
Rust 1.81 minimum. [CONTRACTS.md](CONTRACTS.md) describes effects and lifetimes;
[BUILDING.txt](BUILDING.txt) gives build requirements and
[error recovery](library/docs/error-recovery.md) describes retained owners.

## Public validation for 0.1.1

The compiler matrix is Rust 1.81.0 and 1.100.0 on x86_64-unknown-linux-gnu and
x86_64-pc-windows-msvc. The library, raw bindings, verification ABI and optional
verification engine are compiled; public examples and documentation are checked.
The engine recipe uses static OpenSSL 3.5.9 with native symbol inspection.

The Linux integration suite exercises discovery, login/logout, invalid PIN,
single and multipart SHA-256, RSA sign/verify, invalid signature, AES-GCM,
invalid GCM tag and object search/destruction. Ten scenarios passed with each
compiler in local acceptance, including cleanup. The module source is the
unmodified official SoftHSM commit
`31293555b3822fcd687057e0b64462a114359c17`; its utility reports 2.7.0. The source
commit identifies this build precisely. See [the public suite](ci/softhsm/README.md)
for parameters and oracles.

The [workflow results](https://github.com/BorealCryptosystems/fe11/actions/workflows/ci.yml)
record hosted executions separately from local acceptance. Each job records its
checkout, compiler, native tools and result status. A result applies to those
inputs and scenarios; other mechanisms and deployment configurations need their
own interoperability evidence. PKCS#11 remains the source of expected semantics.
