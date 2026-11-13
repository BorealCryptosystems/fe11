# fe11 0.1.1

Rust PKCS#11 interface with owned sessions, objects and operation buffers.
Maintained by Boreal Cryptosystems; Apache-2.0; Rust 1.81 minimum.
Supported targets: x86_64-unknown-linux-gnu and x86_64-pc-windows-msvc.

The application selects a trusted native module whose ABI matches the bindings.
It controls mechanisms and policy. Native operations execute through that module.
The optional verification engine supplies explicitly selected software public-key
verification and hashing through a separate component.

Read [getting started](docs/getting-started.md), [the overview](docs/overview.md),
[ownership guarantees](docs/ownership.md) and [error recovery](docs/error-recovery.md).
Method-level Rust documentation specifies the detailed contracts and unsafe obligations.
Security contact: security@borealcryptosystems.com.

Fe11 0.1.1 is checked with Rust 1.81 and 1.100. Its manifest constrains the
shared Base64 and zeroization-derive dependencies to versions compatible with
Rust 1.81, including when an application resolves its own dependencies.
