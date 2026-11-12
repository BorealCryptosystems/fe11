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
