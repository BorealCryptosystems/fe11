# fe11-verify-engine 0.1.0

Fe11's optional software component performs **public-key signature verification and hashing** using a private, statically linked OpenSSL installation. It is distributed as a separately built dynamic library (`cdylib`) and selected explicitly by the application. It is licensed under Apache-2.0, maintained by Boreal Cryptosystems and requires Rust 1.81.

## What the engine provides

| Service | Inputs and result |
| --- | --- |
| Algorithm availability | Key, signature and optional digest/MGF algorithm names; reports whether their implementations can be fetched |
| Verification preparation | Exact public key, signature scheme and parameters; imports the key and prepares that combination |
| Signature verification | Prepared request description, message and signature; returns a verification verdict |
| Fixed-length hash | Algorithm name, whole message and exact digest size; returns owned digest bytes |
| Extendable-output hash | Algorithm name, whole message and caller-selected output length; returns owned output bytes |
| Component information | ABI version, implementation version and private OpenSSL version |

Availability, preparation and verification are separate observations. An availability check establishes the presence of named implementations. A preparation probe checks the actual key and parameter combination. Only verification evaluates a supplied signature against its message.

### Signature schemes and key representations

| Scheme | Parameter handling |
| --- | --- |
| RSA PKCS#1 v1.5 | Explicit message digest; RSA public key |
| RSA-PSS | Explicit message digest, MGF1 digest and exact nonnegative salt length |
| ECDSA | EC public key and explicit message digest |
| Ed25519 and Ed448 | Pure-message verification |
| Ed25519ctx, Ed25519ph and Ed448ph | Explicit RFC 8032 instance and context; original message supplied to the engine |
| ML-DSA and SLH-DSA | Algorithm family, context and explicit message-framing selection |

Public keys use SubjectPublicKeyInfo DER or the raw-public-key representation accepted for the selected algorithm. The DER importer consumes the complete input and checks its key family. Fe11's typed adapters provide the corresponding public-key representation and signature encoding.

RSA-PSS salt length is an exact value, checked for conversion to the engine's integer representation. EdDSA and PQC context strings have a 255-byte bound. Pure Ed25519 uses an empty context. With the supplied OpenSSL implementation, Ed25519ctx with an empty context returns `UNAVAILABLE` during preparation; the native PKCS#11 route retains its own parameter handling.

PQC message encoding has two explicit modes: engine framing of the supplied message and context, or verification of already framed input with an empty additional context. This preserves the requested domain separation. Supported parameter combinations are established by the preparation call against the built component.

For fixed-size hashing, the requested length must equal the selected digest size. For XOF hashing, the caller selects the length and the selected method must provide XOF semantics.

## Selecting the component in Fe11

1. Build the engine for the application's target.
2. Deploy its dynamic library and establish trust in that native image.
3. Create `VerifyEngine::builder(absolute_path, integrity_selection)`.
4. Apply any required Windows loader and file-observation options, then call `open()`.
5. Attach the resulting handle with `ModuleBuilder::verify_engine(Some(engine))`.
6. Use the Fe11 operations that explicitly request software verification.

`Module::verify_engine()` exposes the selected handle. `VerifyEngine::info()` reports source path, source SHA-256, requested integrity observations, ABI/version information and available service entry points. Fe11's typed verification adapters construct requests and manage their outputs; the public engine handle supplies selection and information.

Native PKCS#11 operations execute through the selected PKCS#11 module. Software verification executes through this separately selected engine. A native error remains the result of that native operation.

## Execution and memory ownership

Requests are synchronous and borrow input storage until return. Each request owns its public key, operation context and algorithm resources. Different threads can issue independent requests. The calling thread must not reenter the engine during a request; enforcing this precondition is the caller's responsibility. Output slots must be aligned, exclusively writable and disjoint from inputs. The host pins the image before invoking any service other than interface discovery.

A private OpenSSL library context loads the built-in default provider with `provider=default`. Per-request resources are released in dependency order. Configuration loading and automatic process-exit cleanup are disabled by the component's initialization choices.

Digest results cross the C ABI as `OwnedBytes`: an opaque allocation owner and a borrowed byte view. The host copies the result, then calls the originating component's `release` function exactly once. Allocator ownership stays with that component. Fe11 retains the component image for the process lifetime; updating a selected image requires a process restart.

The application trusts the native image and establishes ABI compatibility. Source hashes and loader observations describe that selection; their precise guarantees are documented by `VerifyEngineInfo` and the builder methods.

## Results and diagnostics

| ABI status | Meaning |
| --- | --- |
| `OK` (0) | Request completed; verification verdict is supplied separately |
| `INVALID_REQUEST` (1) | Invalid request representation or parameter combination |
| `UNAVAILABLE` (2) | Required implementation, public-key import or exact preparation unavailable |
| `ENGINE_FAILURE` (3) | Failure while executing the engine operation |
| `ALLOCATION_FAILURE` (4) | Required allocation failed |

For verification, `OK` with verdict 1 means a valid signature; `OK` with verdict 0 means a signature mismatch. A non-OK status reports an operation failure. Fe11 maps these statuses to typed `VerificationEngineRejection` diagnostics.

## Build

Supported targets are Linux x86_64 GNU and Windows x86_64 MSVC. Supply a private static OpenSSL 3.5+ installation within major version 3, configured with `no-shared`, `no-engine`, `no-autoload-config` and PIC on Linux. Headers, libcrypto and libssl archives must come from that installation.

Set:

```text
OPENSSL_STATIC=1
OPENSSL_NO_VENDOR=1
OPENSSL_DIR=<absolute installation prefix>
OPENSSL_LIB_DIR=<absolute archive directory under that prefix>
```

The headers selected by openssl-sys must resolve to `<OPENSSL_DIR>/include`. Build from the workspace with:

```text
cargo build --release -p fe11-verify-engine
```

From the unpacked crate, use `cargo build --release`. The build script checks the configuration. Inspect the resulting ELF/PE to confirm local symbol binding and static OpenSSL linkage. Standard output names are `libfe11_verify_engine.so` on Linux and `fe11_verify_engine.dll` on Windows.

## API reference

The public C contract is declared by `fe11-verify-engine-api`. Its ABI version is **2**, independently of package version 0.1.0. Discovery uses `Fe11_VerifyEngine_GetInterface`, which fills the caller's exact-size table for the requested version.

Generate this component's Rustdoc with `cargo doc -p fe11-verify-engine --no-deps` after configuring its build prerequisites. The companion ABI crate documents request structures, table fields, callbacks, status constants and pointer-lifetime requirements.
