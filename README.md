# Fe11 0.1.1

[![Public validation](https://github.com/BorealCryptosystems/fe11/actions/workflows/ci.yml/badge.svg?branch=main)](https://github.com/BorealCryptosystems/fe11/actions/workflows/ci.yml)

Fe11 is a Rust interface to PKCS#11 modules, maintained by **Boreal Cryptosystems**
and licensed under Apache-2.0. It loads the native module selected by the application
and represents sessions, objects, operations and their retained memory with Rust owners.

The application selects mechanisms, keys and parameters. The native module decides
cryptographic compatibility and policy. Fe11 checks interface representation,
buffer capacities and ownership. The application establishes trust in the native
module and its loader configuration.

## Packages

| Package | Purpose |
| --- | --- |
| `fe11` | Rust PKCS#11 API with owned sessions, objects and operations |
| `fe11-verify-engine-api` | C ABI shared with the optional verification component |
| `fe11-verify-engine` | Software public-key signature verification and hashing |

The raw bindings, `fe11-sys`, have their own repository and package. Supported
targets are Linux x86_64 GNU and Windows x86_64 MSVC; minimum Rust is **1.81**.
The module's ABI must match the selected profile. See [BUILDING.txt](BUILDING.txt).

Add `fe11 = "0.1.1"` to your application's dependencies. The default workspace build selects only the library. The optional
engine uses its own static OpenSSL build for explicitly selected software verification.

## Documentation

The [documentation website](https://borealcryptosystems.github.io/fe11/) and
[searchable API reference](https://borealcryptosystems.github.io/fe11/0.1.1/api/index.html)
cover the 0.1.1 release.


- [How To: detailed usage recipes](library/docs/how-to/index.md), including
  [ML-DSA and SLH-DSA](library/docs/how-to/pqc-signatures.md),
  [PQC prehash modes](library/docs/how-to/pqc-prehash.md) and
  [ML-KEM](library/docs/how-to/ml-kem.md).

- [Getting started](library/docs/getting-started.md) and [API guide](GUIDE.md) and [API reference](API-REFERENCE.md).
- [Operation and error contracts](CONTRACTS.md), [recovery](library/docs/error-recovery.md)
  and [coexistence](COEXISTENCE.txt).
- [Architecture and safety](ARCHITECTURE.md) and [ownership guarantees](library/docs/ownership.md).
- [Verification engine](verify-engine/README.md) and [its ABI](verify-engine-api/README.md).
- [Interoperability reporting](VALIDATION.md), [changes](CHANGELOG.md), [security](SECURITY.md)
  and [contributions](CONTRIBUTING.md).
- [License](LICENSE), [copyright](COPYRIGHT), [contributors](CONTRIBUTORS.md),
  [third-party notices](THIRD-PARTY-NOTICES.md) and [dependency inventory](SBOM.json).

## Compiler and integration checks

Fe11 supports Rust 1.81 and is also checked with Rust 1.100 on Linux x86_64 GNU
and Windows x86_64 MSVC. The public CI runs ten API scenarios against an
unmodified upstream SoftHSM build on both compiler versions. See the
[validation scope](VALIDATION.md) and [local test instructions](ci/softhsm/README.md).

The verification packages and `fe11-sys` remain at version 0.1.0. Fe11 0.1.1
preserves the 0.1.0 API and adds compiler/dependency compatibility checks and
public CI tooling. [Documentation for 0.1.0](https://borealcryptosystems.github.io/fe11/0.1.0/index.html)
remains available.
