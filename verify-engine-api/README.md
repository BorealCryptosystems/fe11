# fe11-verify-engine-api 0.1.0

This `no_std` crate defines the versioned C interface shared by Fe11 and its software verification and hashing component. It contains request structures, service function types, status constants and the interface discovery contract. Apache-2.0; maintained by Boreal Cryptosystems; Rust 1.81 minimum.

## Interface and services

Package version 0.1.0 uses **ABI version 2**. The exported entry point `Fe11_VerifyEngine_GetInterface` accepts a requested ABI version and fills an exact-size `Interface` supplied by the caller.

| Declaration | Role |
| --- | --- |
| `Information` | ABI, structure size, implementation version and private OpenSSL version |
| `VerificationAlgorithms` | Named implementations to query before an exact-key request |
| `VerificationRequest` | Public key, format, scheme, digests, salt, context and message encoding |
| `DigestRequest` | Algorithm, fixed/XOF selection, output length and whole message |
| `Bytes` | Borrowed pointer and byte length |
| `OwnedBytes` | Component-owned allocation token and readable result view |
| `Interface` | Information, availability, preparation, verification, digest and release entry points |

Availability checks, exact-key preparation probes and actual signature verification produce distinct results. Successful verification returns a separate valid/mismatch verdict. Status constants identify request, capability, execution and allocation failures.

## Ownership and calls

The caller must keep inputs initialized, readable and immutable through synchronous calls. Output slots must be aligned, exclusively writable and disjoint from inputs. The calling thread must not reenter the engine during a request; the caller enforces this precondition. Pointer lengths and storage must satisfy the function's Safety contract. The host must pin the component image before using its service table and keep it available for every callback and release.

Returned `OwnedBytes` allocations are released exactly once through the originating component. Their byte views remain readable until release. The component's allocator owns those allocations, including a non-null owner with zero-length data.

Generate the complete public reference with:

```text
cargo doc -p fe11-verify-engine-api --no-deps
```

Rustdoc documents each field, service signature, version/size requirement and unsafe caller obligation.
