# Changelog

## 0.1.1

### Sessions and operations

- Search for objects while a synchronous session has a quiescent classic
  cryptographic operation. The module decides whether the search can start.
  After a successful logout, Fe11 forwards continuation and finalization of
  an existing generic native object search. The module determines the outcome.
- Start a second classic operation of a different kind on the same session.
  When the module accepts both, each ticket tracks its own progress. Use
  `ClassicOperation` and `take_classic_ticket` to select a ticket. Grouped
  state capture and restoration retain the participating operations on modules
  that support native operation state.
- Call `C_Login` or `C_LoginUser` between native calls of an active operation.
  `authenticate_session_context` also lets the module select the key for a
  context-specific login. Ticket-scoped authentication remains available.
- Preserve a live operation when a direct `C_SessionCancel` returns
  `CKR_FUNCTION_NOT_SUPPORTED`. Fe11 reports the native code and marks that
  cancellation attempt as having no effect.

### Tokens, attributes and key derivation

- Keep an otherwise valid session usable after a synchronous key or key-pair
  generation error with uncertain effects. Preserve the native error and the
  uncertain creation record while allowing cleanup of existing objects.
- Submit `C_InitToken` when the token has idle sessions. A native
  `CKR_SESSION_EXISTS` preserves those sessions. During a token drain,
  `initialize_user_pin` and `change_pin` can reach `C_InitPIN` and `C_SetPIN`.
- Accept a zero-length byte value for a date attribute. An explicitly supplied
  eight-byte `CK_DATE` keeps all eight bytes, including an all-zero date.
- Honor an explicit object class in the output template of `CKM_GOSTR3410_DERIVE`
  when reserving and observing the destination. The native module decides
  whether to accept the derivation.

### Build and public tests

- Distribute the public suite in the separate `fe11-tests` package, pinned to Fe11 0.1.1. The versioned HTML documentation is available as an offline archive.

- Support Rust 1.100 on Linux x86_64 GNU and Windows x86_64 MSVC while retaining
  Rust 1.81 as the minimum supported compiler. Fe11 pins `base64ct = 1.6.0` and
  `zeroize_derive = 1.4.3` for fresh resolutions with Rust 1.81. Applications
  requiring newer versions of either package should check their combined graph.
- Add public local API tests, SoftHSM integration scenarios, a [case catalogue](fe11-tests/tests/vectors/CASES.md)
  and a [guide to observed module results](fe11-tests/tests/README.md#known-softhsm-results).
  The GitHub workflow schedules the native suite with both Rust versions,
  the file and database object stores, and the legacy and standard module
  interfaces. Its coverage report retains raw results and identifies exact
  reproductions of documented module behavior.
- Record the length and encoding shape of each public point used in the
  `sect239k1`, `secp160k1`, `prime192v2` and `c2tnb239v2` ECDH scenarios
  so that a native refusal can be investigated.
- Provide versioned API documentation and usage guides. The companion crates
  `fe11-sys`, `fe11-verify-engine-api` and `fe11-verify-engine` remain at 0.1.0.
- Distinguish retained Montgomery refusals from created objects, with exact
  native return observations and independent namespace checks. Report states
  requiring a created pair as unavailable in the pinned SoftHSM CI profile.
- Accept permitted generic native refusals for invalid PSS salt and ML-KEM
  ciphertext lengths while preserving exact codes and possible effects. Keep
  the second oversized-salt PSS route explicitly open for attribution.
- Compare randomized PSS controls through independent verification and exact
  lengths; retain raw hashes and structured failure receipts. Report unavailable
  native or host prerequisites and refused-generation transitions separately.

## 0.1.0

Initial release of the Rust PKCS#11 library, with owned sessions and objects,
typed mechanism parameters, operation continuations and recovery, and native
error diagnostics. The workspace includes the optional software verification
engine and its C ABI. Usage guides and the API reference document the interfaces.
