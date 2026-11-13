# Changelog

## 0.1.1

- Validate Rust 1.100 on Linux x86_64 GNU and Windows x86_64 MSVC while retaining
  Rust 1.81 as the minimum supported compiler.
- Keep fresh application dependency resolution compatible with Rust 1.81 by
  constraining the already-used `base64ct` and `zeroize_derive` packages.
- Add public SoftHSM integration scenarios and a six-job compiler/integration CI.
- Publish versioned API documentation and guides alongside the retained 0.1.0 site.

The PKCS#11 API, verification ABI and native-operation behavior are unchanged.
`fe11-sys`, `fe11-verify-engine-api` and `fe11-verify-engine` remain at 0.1.0.


The exact `base64ct = 1.6.0` and `zeroize_derive = 1.4.3` constraints preserve
the minimum compiler for fresh resolutions. They can conflict with application
dependencies requiring newer compatible versions of those packages; review the
combined graph when updating dependencies. Fresh-resolution checks apply to the
registry state at validation time and do not guarantee every future resolution.

## 0.1.0

Initial release of the Rust PKCS#11 library, with owned sessions and objects,
typed mechanism parameters, operation continuations and recovery, and native
error diagnostics. The workspace includes the optional software verification
engine and its C ABI. Usage guides and the API reference document the interfaces.
