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

## Public validation for 0.1.1

The compiler matrix is Rust 1.81.0 and 1.100.0 on x86_64-unknown-linux-gnu and
x86_64-pc-windows-msvc. The library, raw bindings, verification ABI and optional
verification engine are compiled; public examples and documentation are checked.
The engine recipe uses static OpenSSL 3.5.9 with native symbol inspection.

The `fe11-tests` package selects the matching Fe11 version. Its local tests
exercise Rust API contracts. On Linux, its native worker exercises PKCS#11
against disposable tokens. The public manifests identify the mechanism, inputs,
expected result and applicable execution contexts. The SoftHSM recipe uses
official commit `7380895665c3094a6f57640085bee97dcfeb1496`. The GOST configuration
of that revision fails to build because the declaration and definition of
`OSSLGOST::signInit` differ. Results from the OpenSSL full configuration apply
to the selected module, interface and storage backend. See the
[suite guide](fe11-tests/tests/README.md) for the oracles and known module results.

### How a native job treats a documented divergence

Each native result records the original scenario `status` and a separate
`ci_verdict`. A job can accept a raw `FAIL` as `DOCUMENTED_DIVERGENCE` when the
case and execution context have a matching entry in the
[observation catalogue](ci/scripts/native-divergences.json). The comparison
covers the fixture, pinned input archives and build recipe, verified runtime
dependencies, native call sequence, worker assertions, and failure phase.
The shard plan reports the observed image hashes and lists differences from
the reference build. A rebuilt image can match the same observation only after
the recipe, provider configuration and loaded images have been verified.
Provisioning, trace collection and
cleanup must complete. The scenario continues to count as a failure in
conformance totals.

A different native error, an additional assertion failure, a missing receipt,
or a previously failing case that now passes requires investigation. Each
causes the job to fail until the evidence and attribution have been reviewed.
For oversized RSA-PSS salts, a permitted generic refusal on the raw route now
allows the combined-hash route to run. That route can return
`CKR_MECHANISM_INVALID` at `C_SignInit`, which remains outside the oracle.
The nine cases (72 compiler/storage/interface coordinates) have complete
two-route observations: `C_Sign/CKR_GENERAL_ERROR` followed by
`C_SignInit/CKR_MECHANISM_INVALID`. CI recognizes only their documented full
observation as a divergence of the pinned module's parameter-error diagnostic.
The strict oracle and raw FAIL remain unchanged. A different code, effect flag,
phase, assertion or call sequence still requires investigation.

For raw SHA-256 RSA-PSS, the pinned module returns `CKR_GENERAL_ERROR` on
signing and `CKR_SIGNATURE_INVALID` on verification for digests of 31 or 33
bytes. The cases expect `CKR_DATA_LEN_RANGE` and then exercise a valid input
on the same key and owner. For the combined SHA-256 mechanism with SHA-384
in the PSS parameters, initialization returns `CKR_ARGUMENTS_BAD` where the
case expects `CKR_MECHANISM_PARAM_INVALID`.

Two derivation cases request `CKA_VALUE_LEN = 0`. For ECDH, the resulting
key reports length zero and returns 32 bytes in `CKA_VALUE`. The concatenation
case also fails the empty-value assertion. For ML-KEM encapsulation with a
zero-byte buffer or a buffer one byte too short, the required size returned
with `CKR_BUFFER_TOO_SMALL` equals the supplied capacity. The test expects
the full ciphertext length for the selected parameter set.

The report distinguishes a failed assertion from a documented unavailable
prerequisite. For example, on the pinned module an RSA object with the
requested KEM usage is rejected at `C_CreateObject`. The wrong-key KEM
scenarios retain their raw failure, record `body_started = false`, and
contribute zero KEM operations to coverage. The same verified refusal and
successful cleanup are required to recognize that prerequisite.

For AES-GCM on the pinned module, each of the 112 non-byte-aligned tag lengths
between 1 and 127 bits has a recorded refusal at `C_EncryptInit` with
`CKR_ARGUMENTS_BAD`. The comparison checks the individual tag fixture,
interface, backend and Rust version. The expected encryption result remains
unobserved for these cases.

For the byte-output PRF and key-material derivation cases, the module checks
the output handle pointer before checking mechanism availability. The trace
records `C_DeriveKey` returning `CKR_ARGUMENTS_BAD` when the expected result
for an unavailable mechanism is `CKR_MECHANISM_INVALID`. The PKCS#11
mechanisms in those cases return their output through mechanism parameters.

Other catalogue entries cover individual observations in RSA-OAEP, AES key
wrap, Triple DES transport and parity, Edwards public-key import, binary
curve key generation and ECDH, and object access after logout. Look up the
specific case and execution context in the catalogue. A matching mechanism
name or native return code alone cannot identify the same failure.

Three object-creation cases exercise inconsistent templates. SoftHSM created
an object when the template supplied two different values for `CKA_VALUE`.
The case retained and destroyed the returned object. For a public key with a
secret-key type and a secret key with an RSA type, `C_CreateObject` returned
`CKR_ATTRIBUTE_VALUE_INVALID`. Each case expects `CKR_TEMPLATE_INCONSISTENT`.

For an empty ML-KEM ciphertext, the pinned module returned
`CKR_ATTRIBUTE_VALUE_INVALID` from `C_DecapsulateKey`. The case expects
`CKR_WRAPPED_KEY_LEN_RANGE` or the permitted generic `CKR_GENERAL_ERROR`,
while retaining any possible creation effect. `CKR_ATTRIBUTE_VALUE_INVALID`
remains a raw failure. For the 246-byte RSA PKCS#1 v1.5 encryption
input and 2,048-bit key, the module returned `CKR_GENERAL_ERROR` from
`C_Encrypt` where the case expects `CKR_DATA_LEN_RANGE`. Both comparisons
preserve the original failure and the reported uncertainty about side effects.

On `sect239k1`, two valid uncompressed SEC1 points can have the same 61-byte
length and receive different results. With one point, Fe11 and a direct C client
derived the same secret. With a point whose first two bytes also form a DER
OCTET STRING header for that length, both clients received `CKR_GENERAL_ERROR`
from the pinned module. Both routes used the same private scalar, peer point
and derivation attributes for each comparison. A return code alone cannot
establish the encoding of a point from an earlier run.
For this curve and the `secp160k1`, `prime192v2` and `c2tnb239v2` scenarios,
the shard report retains the uncompressed point length and a
boolean indicating whether the header also matches a DER OCTET STRING, in
the order of the derivation attempts. The same agreement and secret-length
checks apply to both point shapes.

For Montgomery key-pair generation, the observer records the scalar return
from each `C_GenerateKeyPair` call. The case reports the ticket action
separately. A successful generation requires both key objects. A second session
searches by the case's ID and label, validates and destroys the objects it
finds, then repeats the search to verify cleanup. If generation is refused,
an existing ticket can still be dropped. A capture in CREATED_UNCLAIMED or CONSUMED requires a created pair and
is unexecuted when that prerequisite fails. Capture on a retained refused
ticket is a separate ownership check.

The CI profile explicitly excludes Montgomery CREATED_UNCLAIMED and CONSUMED
states because the pinned recipe does not implement Montgomery pair generation. These
16 case definitions account for 112 coordinates. They remain in the generic
package but contribute no bodies to this CI profile. The privileged umask
isolation scenario contributes another eight unavailable coordinates.
The definition-bound list and reasons are in
[native-prerequisites.json](ci/scripts/native-prerequisites.json).

Twenty additional Montgomery action definitions now match a retained native
refusal with its exact independent return and two empty inventory reads.
They include capture, polling, cancellation, dropping an observer, logout and
closure. Capture checks the ownership guard reached by the completed refusal;
polling preserves the same native code. No object destruction is required when
both the return observation and inventory establish an empty namespace. The
nominal successful-generation trace still requires destruction of both objects.
The acceptance report counts successful refused-ticket transitions separately;
they are not successful generation. These source corrections require targeted
execution before they can be credited as new validated results.

The Legacy240 Edwards cancellation scenario first checks the local cancellation
refusal, then completes verification using its retained ticket. An imported
raw public key encounters the documented SoftHSM encoding divergence during
that verification. The CI compares the complete retained observation for each
context and preserves the raw failure.

Two scenarios follow a generated AES session key across calls. In
`aes.generated.gcm-authentication`, the session encrypts and decrypts with
the same key, flips one bit in the tag, checks the native rejection and then
decrypts the original envelope again. In `aes.generated.private-session-search`,
the session looks up its private key by `CKA_ID` alone, destroys the originally
generated key and repeats the same search. The expected counts are one and zero.

The Linux workflow builds the native dependency recipe from its pinned source
archives and runs the worker compiled from the matching `fe11-tests` package.
Each compiler, object store and interface has 32 partitions. The acceptance
report checks their case IDs against the public manifests and lists the
unavailable GOST contexts separately. Each shard publishes its plan, raw
scenario statuses and CI decisions in the workflow reports.

The [workflow results](https://github.com/BorealCryptosystems/fe11/actions/workflows/ci.yml)
record hosted executions separately from local acceptance. Each job records its
checkout, compiler, native tools and result status. A result applies to those
inputs and scenarios; other mechanisms and deployment configurations need their
own interoperability evidence. PKCS#11 remains the source of expected semantics.

### Portable observations and retained receipts

The four PSS invalid-input cases with same-owner positive controls compare
independent RFC 8017 verification and exact lengths instead of byte equality
of randomized signatures. Each raw output hash is retained in its structured
receipt. All native codes, assertions and phases remain part of comparison.

Native result artifacts retain structured non-PASS observations for 90 days.
They contain public scalar results, identities and hashes, not raw process
streams, PINs, token files or generated keys. `receipt_bytes` measures their
actual uncompressed volume. Recipe and image checks still precede comparison;
changed or missing observations remain unaccepted. Forty-five generated-key ECDH
scenarios remain explicitly `NOT_QUALIFIED` on SoftHSM, even when an individual
execution succeeds. They still execute and retain their raw verdicts; the
acceptance report lists them separately and reports partial qualification.
The [domain inventory](ci/ECDH-SCOPE.md) documents the affected point encodings.
The [CI profile](ci/README.md#ecdh-scenarios-outside-qualification) defines the
bounded failure path and the errors that still fail CI, together with evidence
retention and the distinction between module diagnosis and each observation.

See the [CI profile](ci/README.md) for selection, retention and open attribution.
