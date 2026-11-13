# Getting started

Fe11 requires Rust 1.81 or later and a compatible native PKCS#11 module installed
by the application. Linux x86_64 GNU uses natural LP64 layout; Windows x86_64 MSVC
uses one-byte-packed LLP64 layout. Establish ABI compatibility before loading.

Add `fe11 = "0.1.1"` to Cargo.toml. Build the core with
`cargo build --release -p fe11`; OpenSSL is not required for this package.
Generate method-level documentation with `cargo doc -p fe11 --no-deps`.

Use `ModuleBuilder` to select the image and initialization options, then open the
module, select the token and open a session. `ModuleBuilder::open_shared` and
`attach_initialized` have separate lifecycle and safety contracts for shared use.
Follow the documentation on those methods rather than assuming a second open
acquires an existing initialization.

Select the operation, mechanism, parameters and attributes explicitly. Check the
result and its native-effect information before retrying. A local publication
error can follow a successful native operation. Do not turn it into a duplicate
mutation. Explicitly close sessions and the module when results of cleanup matter;
`Drop` is not a universal completion guarantee.

Read [the overview](overview.md), [ownership](ownership.md) and
[error recovery](error-recovery.md) before handling retained or detached operations.
Native asynchronous PKCS#11 3.2 execution is not enabled. A declared mechanism
does not imply that the selected module supports it.

## How To

Follow the [detailed recipes](how-to/index.md) for complete configuration, authentication, signatures, AES-GCM, PQC and the optional verification engine.
