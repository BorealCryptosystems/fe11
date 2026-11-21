# fe11 0.1.1

Rust PKCS#11 interface with owned sessions, objects and operation buffers.
Maintained by Boreal Cryptosystems; Apache-2.0; Rust 1.81 minimum.
Supported targets: x86_64-unknown-linux-gnu and x86_64-pc-windows-msvc.

```toml
[dependencies]
fe11 = "0.1.1"
```

The application selects a trusted native module whose ABI matches the bindings.
It controls mechanisms and policy. Native operations execute through that module.
The optional verification engine supplies explicitly selected software public-key
verification and hashing through a separate component.

## Operations and ownership

Fe11 provides module and interface discovery, session authentication, object
creation and search, typed mechanism parameters, cryptographic operations and
continuations. Native errors retain their producer and effect diagnostics.
Advanced operations use tickets to retain their buffers and track progress.

Version 0.1.1 corrects search and authentication between native calls, independent
classic-operation tickets, grouped state capture and restoration, token and PIN
administration, empty date values, GOST derivation output classes, and bookkeeping
after uncertain object creation or key generation. See the
[release changelog](https://github.com/BorealCryptosystems/fe11/blob/v0.1.1/CHANGELOG.md).

## Documentation

Start with [getting started](docs/getting-started.md), [the overview](docs/overview.md),
[ownership guarantees](docs/ownership.md) and [error recovery](docs/error-recovery.md).
The [How To guides](docs/how-to/index.md) cover setup, authentication, hashing,
AES-GCM, keys and signatures, public verification, ML-DSA, SLH-DSA and ML-KEM.
The [API reference](https://borealcryptosystems.github.io/fe11/0.1.1/api/fe11/index.html)
specifies method contracts and unsafe obligations.

## Compiler compatibility and tests

Fe11 0.1.1 is checked with Rust 1.81 and 1.100. The exact `base64ct = 1.6.0` and
`zeroize_derive = 1.4.3` constraints preserve the minimum compiler for fresh
resolutions. They can conflict with application dependencies requiring newer
compatible versions of those packages; review the combined graph when updating
dependencies. Fresh-resolution checks apply to the registry state at validation
time and do not guarantee every future resolution.

The separate `fe11-tests = 0.1.1` source package contains public API contracts,
native scenarios and reference vectors. Its README describes how to run it.
Security contact: security@borealcryptosystems.com.
