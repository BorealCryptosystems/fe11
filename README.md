# Fe11 0.1.1

[![Public validation](https://github.com/BorealCryptosystems/fe11/actions/workflows/ci.yml/badge.svg?branch=main)](https://github.com/BorealCryptosystems/fe11/actions/workflows/ci.yml)

Fe11 is a Rust interface to PKCS#11 modules, maintained by **Boreal Cryptosystems**
and licensed under Apache-2.0. It loads the native module selected by the application
and represents sessions, objects, operations and their retained memory with Rust owners.

The application selects mechanisms, keys and parameters. The native module decides
cryptographic compatibility and policy. Fe11 checks interface representation,
buffer capacities and ownership. The application establishes trust in the native
module and its loader configuration.

## Packages and installation

| Package | Version | Purpose |
| --- | --- | --- |
| `fe11` | 0.1.1 | Rust PKCS#11 API with owned sessions, objects and operations |
| `fe11-tests` | 0.1.1 | Public API contracts, native scenarios and attributed reference vectors |
| `fe11-verify-engine-api` | 0.1.0 | C ABI shared with the optional verification component |
| `fe11-verify-engine` | 0.1.0 | Software public-key signature verification and hashing |
| `fe11-sys` | 0.1.0 | Raw bindings, maintained in the [Fe11-sys repository](https://github.com/BorealCryptosystems/fe11-sys) |

Add the library to your application's `Cargo.toml`:

```toml
[dependencies]
fe11 = "0.1.1"
```

Supported targets are Linux x86_64 GNU and Windows x86_64 MSVC; minimum Rust is
**1.81**. The module's ABI must match the selected profile. See
[BUILDING.txt](BUILDING.txt) and [getting started](library/docs/getting-started.md).
The default workspace build selects the library.

The optional verification engine supplies public-key signature verification and
hashing through an explicitly loaded component. Its private static OpenSSL build
provides the software algorithms; PKCS#11 operations continue to use the application's
selected native module. See [engine services, supported algorithms and deployment](verify-engine/README.md).

## Changes in 0.1.1

This release corrects session coordination for searches, authentication and
simultaneous classic cryptographic operations. Each accepted operation retains
its own ticket and progress; grouped native state capture and restoration preserve
the participating operations. It also corrects token administration, empty date
attributes, GOST derivation templates and bookkeeping after uncertain object
creation or key generation. The [changelog](CHANGELOG.md) describes each change
and the added public methods.

The release adds a separately packaged public test suite and GitHub validation
with Rust 1.81 and 1.100. The verification packages and raw bindings remain at
0.1.0. [Documentation for 0.1.0](https://borealcryptosystems.github.io/fe11/0.1.0/index.html)
remains available.

## Documentation

Browse the [documentation website](https://borealcryptosystems.github.io/fe11/) and
the [0.1.1 API reference](https://borealcryptosystems.github.io/fe11/0.1.1/api/index.html).
The source documentation is also directly accessible here:

- [How To: detailed usage recipes](library/docs/how-to/index.md), including
  [ML-DSA and SLH-DSA](library/docs/how-to/pqc-signatures.md),
  [PQC prehash modes](library/docs/how-to/pqc-prehash.md) and [ML-KEM](library/docs/how-to/ml-kem.md).
- [Getting started](library/docs/getting-started.md), [API guide](GUIDE.md) and [API reference guide](API-REFERENCE.md).
- [Operation and error contracts](CONTRACTS.md), [recovery](library/docs/error-recovery.md)
  and [coexistence](COEXISTENCE.txt).
- [Architecture and safety](ARCHITECTURE.md) and [ownership guarantees](library/docs/ownership.md).
- [Verification engine](verify-engine/README.md) and [its ABI](verify-engine-api/README.md).
- [Interoperability reporting](VALIDATION.md), [security](SECURITY.md) and [contributions](CONTRIBUTING.md).
- [License](LICENSE), [copyright](COPYRIGHT), [contributors](CONTRIBUTORS.md),
  [third-party notices](THIRD-PARTY-NOTICES.md) and [dependency inventory](SBOM.json).

## Public validation

The compiler matrix covers Rust 1.81 and 1.100 on Linux x86_64 GNU and Windows
x86_64 MSVC. The [fe11-tests package](fe11-tests/README.md) provides local API
contracts and native scenarios. Linux CI runs the native suite on disposable
SoftHSM tokens with file and database storage and both selected interface profiles.

Results retain the original scenario verdict, native diagnostics, prerequisite
status and separate CI classification. The [validation guide](VALIDATION.md)
explains the exact acceptance rules, documented module divergences and areas
that remain unqualified in this configuration.
