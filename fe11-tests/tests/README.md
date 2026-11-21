# Public test suite

The suite exercises Fe11 through its public Rust API. Local contracts run without
a PKCS#11 module; native cases use real SoftHSM modules and disposable tokens.
Rust 1.81 is the minimum compiler and Rust 1.100 is the second validation target.

Native cases run in separate processes, one parameter tuple per process. Token
provisioning completes in a separate process before a case starts. The runner
generates fresh PINs and supplies them as bounded binary frames on standard input.
Result records distinguish prerequisites, assertions, native cleanup, process exit
and timeout. Native return codes and typed public errors are compared explicitly.

Test keys and vectors are public, attributed fixtures. Use them only for testing.
The tests create and destroy only their own objects and disposable token storage.
The native module executes in the test process with the permissions of that process.

Sources are divided into local contracts, native operation families, runner
support and public fixtures. Shared helpers provide input framing and ownership;
each operation family states its own setup and assertions.

## Running and reviewing a case

From the workspace root, run the [local API tests](local.rs) with
`cargo test --locked -p fe11-tests --test local`. They check Rust values, errors and
ownership contracts without loading a token. When using an extracted source crate, run
`python tests/driver/fixture_archive.py unpack` from the crate directory first.
The command restores native input files from the bundled archive and checks each
file against its public manifest. The Git checkout contains the expanded inputs.
For a native case, build the
[worker](native/main.rs) with
`cargo test --locked --release -p fe11-tests --test native --no-run`.
The [case driver](driver/case.py) runs that executable against a prepared Linux
SoftHSM installation. Its `--help` lists the required recipe, worker, fixture
manifest, prerequisite report (`--gate`), hashes and configuration. Give each
case a fresh working directory. The runner creates a disposable token there.

For a native case, start with its manifest entry. Its `id` selects the scenario, its `file` and
`sha256` identify the exact inputs, and its `contexts` list the configurations
in which the case applies. Multiple contexts express the same contract on
different builds or storage backends. The `worker_mode` selects the Rust path
that performs the operation. Read its assertion alongside the expected value
or native call sequence in the manifest. The observer filters native calls;
the sequence therefore describes the selected functions.

| Contract | Start here | What to inspect |
| --- | --- | --- |
| Digest and cipher outputs | [Digest vectors](vectors/digest/manifest.json), [cipher vectors](vectors/cipher/manifest.json) | Compare the returned bytes with the cited vector. |
| Object templates | [Creation cases](vectors/creation-class-attribute-changes/manifest.json), [worker](native/attribute_creation_change.rs) | One field changes in a valid template. For an omitted mandatory field the oracle expects `CKR_TEMPLATE_INCOMPLETE`. For a forbidden supplied field it accepts `CKR_ATTRIBUTE_READ_ONLY` or `CKR_TEMPLATE_INCONSISTENT`. |
| RSA generation | [Exponent cases](vectors/rsa-generation-exponent/manifest.json), [worker](native/selection_rsa.rs) | The last line of each fixture gives the requested public exponent in hex. Compare the decoded SPKI and the separately read token attribute with that value. |
| RSA private-key import | [Optional CRT coefficient](vectors/optional-rsa-crt-import/manifest.json) | A refusal with `CKR_TEMPLATE_INCOMPLETE` exercises the refusal branch. An accepted template must produce the expected signature. Only the latter branch demonstrates use of the key. |
| MAC and post-quantum operations | [MAC bindings](vectors/mac-bindings/manifest.json), [PQC fixtures](vectors/pqc/manifest.json) | Inspect the key type, parameters, expected answer and any prerequisite for the selected mechanism. |

The driver writes `result.json` in the case directory. Read the status together
with the setup, body and cleanup records. A negative case can pass when the
specified native refusal occurs and the remaining assertions hold. A `FAIL`
records an unmet expectation; attribution requires examining the observed call,
the contract and the worker. An `INCOMPLETE` result identifies a problem with
the execution or its evidence. Report the case ID, configuration, failed phase,
expected value and observed value when discussing a result.

### Following one result back to the contract

In [the exponent manifest](vectors/rsa-generation-exponent/manifest.json),
`generation.explicit_exponent.rsa-wrap` selects the encryption-key generator.
Its input requests exponent 17 for a 2048-bit key. [Typed selection](native/typed_selection.rs) calls the [RSA preparation helper](native/selection_rsa.rs). During setup, that helper parses the
returned public key independently and reads `CKA_PUBLIC_EXPONENT` from the
public object. If either value differs from 17, the case fails even if key generation
itself succeeded. The failure is recorded in the setup phase. A passing record carries the setup verdict; the numeric exponent is not emitted in the trace. The body separately verifies selection identity and absence of a new object. The companion case applies the same oracle to the signing-key
generator. The two cases distinguish which public API forwarded the request.

Browse [all case manifests by worker mode](vectors/CASES.md) and [known SoftHSM results](#known-softhsm-results). For MAC transitions, the case ID is a stable selector. The `scenario`, `state` and `action` fields give the actual precondition and operation.

When contributing a case, name the public operation and the observable
difference it checks. Put the expected return, value, length or state next to
the case and preserve the independent source for a known-answer vector.
Reuse a fixture when the inputs and assertion are identical. Keep separate
cases when a different public entry point, native operation or failure branch
can change the outcome. Distinguish a PKCS#11 edition's requirement from the
interface actually loaded by the test.

## Known SoftHSM results

The pinned module can return a different code from the case's expected result.
The runner keeps the original verdict. Use the case ID, operation and observed
code to distinguish a known result from a new failure.

| Cases | Observed result |
| --- | --- |
| [RSA-PSS parameter combinations](vectors/rsa-domain/manifest.json), distinct message and MGF hashes | SoftHSM rejects `C_SignInit` with `CKR_ARGUMENTS_BAD`. The suite contains 288 such fixtures. For example, SHA-256 with MGF1-SHA384 and a 32-byte salt reaches initialization on the raw PSS route. |
| [RSA-PSS salt length](vectors/rsa-domain/manifest.json), salt too long for a 2048-bit key and the chosen hash | The test checks raw PSS first and accepts its permitted generic refusal `CKR_GENERAL_ERROR`. It then checks the combined-hash route. A SHA-1/235-byte measurement returned `CKR_MECHANISM_INVALID` at the second `C_SignInit`; that code remains outside this oracle. The nine oversized-salt cases remain `REVIEW_REQUIRED` in CI until the complete two-route observations are attributed. |
| [RSA private keys and DH/DSA domain objects](vectors/creation-class-attribute-changes/README.md) | The creation notes identify the omitted field, the expected code and the result. A successful RSA import and a subsequent usable signature are separate observations. |

## RSA-AES key wrapping

For `CKM_RSA_AES_KEY_WRAP`, PKCS#11 specifies the wrapping of asymmetric
keys. The generic-secret fixtures record interoperability with the
tested module. They cover wrapping permissions, unwrapping templates and the
nested OAEP parameter layout on both session interfaces. Their results are
reported separately from the asymmetric-key requirement.

The [RSA-AES case index](vectors/rsa-aes-coverage.json) lists the fixtures for each group.


## Interpreting unavailable prerequisites and generic refusals

A generation ticket can contain either a created pair or a retained native
refusal. Montgomery ownership scenarios compare CKR_MECHANISM_INVALID with an
independent native return observation and require an empty object namespace
before and after cleanup. Such a pass covers the refused-ticket transition;
it does not cover successful Montgomery generation. Scenarios requiring a
created or consumed pair need a module that actually provides that generation.

The oversized RSA-PSS salt and malformed ML-KEM ciphertext scenarios distinguish
rejection from the precision of the native diagnostic. CKR_GENERAL_ERROR is an
allowed generic refusal in these calls. The tests retain its exact producer and
effect flag, require no signature or shared secret to be published, and require
cleanup. A generic refusal does not prove that no object was created or that the
module diagnosed the precise invalid parameter.

The repository CI profile lists prerequisites unavailable in its pinned recipe
separately from executed results. Those coordinates are NOT_EXECUTED, with zero
bodies exercised. The generic package retains their fixtures for environments
that meet the prerequisites. Known module divergences keep their raw FAIL and
are accepted by CI only when the complete documented observation matches.

The output-credit waiting scenario observes the Linux worker's admission wait
through `/proc` before querying the same session concurrently. The query uses
the same caller-selected deadline to tolerate transient session preparation.
The test retains the output until the query completes, then checks progress
and the exact output length after releasing it. Observation failure, deadline
expiry and cancellation remain failures; all paths release and join the worker.

If a regression retains session possession throughout the credit wait, the
concurrent query can wait until the 60-minute supervision deadline. Such a
timeout is a failure, not an accepted contention result or a performance target.
