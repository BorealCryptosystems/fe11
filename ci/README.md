# SoftHSM CI profile

The CI uses the public `fe11-tests` package with Rust 1.81 and 1.100, file and
SQLite storage, and the legacy and 3.2 interface selectors. The native recipe
is pinned to SoftHSM commit `7380895665c3094a6f57640085bee97dcfeb1496`.
The metadata gate checks the recipe mechanism inventory before execution.

## Coverage and prerequisites

`native-prerequisites.json` binds every excluded coordinate to its case
definition and the pinned recipe. The report records NOT_EXECUTED and the
missing prerequisite, never PASS. The normal hosted profile excludes the
privileged umask isolation scenario and Montgomery states that require a
successfully created pair. Refused-ticket and unsupported-mechanism scenarios
remain selected. The fixtures remain in the public package.

A changed case definition or recipe requires reassessing this selection.
The acceptance report reconciles every selected coordinate and separately
counts unavailable coordinates. The unsupported GOST recipe remains a separate
reported configuration gap.

## Results and evidence

Every executed scenario retains its raw result. `native-divergences.json`
contains expectations for the verified recipe, not a permission to ignore a
native error. Classification compares the exact case definition, native calls,
ordered assertions, setup/body/cleanup phases, observer coverage and loaded
runtime. A new, changed or disappeared divergence fails the job. Differences
between native image hashes are reported separately after recipe verification.

The PSS positive controls contain randomized signatures. For the four
`rsa.negative.pss-{digest-length,hash-mismatch}.{session,advanced}.sign` cases,
comparison requires independent RFC 8017 verification and the exact output
length instead of equality of randomized bytes. The original output hash is
retained in the raw structured receipt. Other comparison fields are unchanged.

Failed, unaccepted and `NOT_QUALIFIED` observations are uploaded under
`observations/`, including raw successes outside qualification.
They contain typed worker assertions, public scalar diagnostics, identities,
process results, cleanup status and the portable comparison object when it can
be established. They exclude raw child streams, token files and generated keys.
A missing complete receipt is insufficient evidence, not a documented divergence.

The reference observations include [the complete campaign](https://github.com/BorealCryptosystems/fe11/actions/runs/44668526812),
[its targeted diagnostics](https://github.com/BorealCryptosystems/fe11/actions/runs/44733138605),
and [generation cleanup validation](https://github.com/BorealCryptosystems/fe11/actions/runs/44739865446).
Expectations reused across equivalent compiler/storage contexts still have to
match the complete observation in each new run. They do not create a historical
execution record for a context that was not measured.

## Remaining native differences

The exact profiles retain raw failures for imported Edwards points, truncated
SHA-512 OAEP parameters, deprecated AES wrap padding, explicit AES wrap IVs,
DES parity, logout and invalid handles, fixed-width ECDH, and DSA 512-bit pair
generation. They do not change Fe11 or the PKCS#11 oracle to emulate SoftHSM.

### ECDH scenarios outside qualification

Forty-five generated-key scenarios are `NOT_QUALIFIED` on the pinned SoftHSM
recipe. The [domain inventory](ECDH-SCOPE.md) derives this scope from the raw
point length and the curve field bounds, rather than from a list of observed
failures. SoftHSM's confusion between raw SEC1 points and DER is a confirmed
input-dependent defect, reported in [SoftHSM #931](https://github.com/softhsm/SoftHSMv2/issues/931).
Direct C and Fe11 diagnostics reproduced it on five curves. This does not
prove the same failure on every exposed curve or reconstruct lost inputs
from historical observations.

These scenarios still run in all eight hosted contexts (360 coordinates).
Both raw PASS and raw FAIL remain visible; an isolated success earns no
qualification credit. `native-unqualified.json` binds the definitions and
contexts; `native-ecdh-domains.json` binds the audited field bounds.
The CI accepts a raw failure within this exclusion only when the complete
observation follows the documented `C_DeriveKey/CKR_GENERAL_ERROR` path:
validated recipe and trace, exact ordered assertions and native call sequence,
uncertain effects retained, and successful setup and cleanup. Six exposed
curves also have an existing fixed-width divergence profile: its exact
observation comparison remains applicable, with a separate
`qualification: NOT_QUALIFIED` flag. A disappearance of that documented
divergence is still reported as `DIVERGENCE_DISAPPEARED` and requires review.
Other refusals, local errors, changed definitions, incomplete observations
and failed cleanup still fail CI. Matching the bounded refusal path does not
prove the cause of an individual new refusal.

The aggregate report lists every unqualified coordinate and raw verdict,
reports their raw totals in `not_qualified_raw` and `qualification: PARTIAL`,
and excludes these bodies from
`qualifying_bodies_exercised`. A successful CI execution therefore does not
claim qualification of those scenarios. Public point-shape observations,
where already available, remain in the receipts without point coordinates or
derived secrets. The generic tests and their PKCS#11 oracles are unchanged.

## Open attribution and retention

The nine oversized-salt RSA-PSS cases have complete observations in all eight
contexts. Raw PSS returns C_Sign/CKR_GENERAL_ERROR, followed by
C_SignInit/CKR_MECHANISM_INVALID on the combined-hash route. The latter is a
parameter-error diagnostic divergence: the strict oracle continues to fail.
The catalogue recognizes only the exact full observations, including effect
flags, assertions, call order and completed cleanup, under the verified recipe.
Their raw FAIL results remain visible; changed or missing evidence fails CI.

The acceptance summary counts `refused_generation_transitions` separately
from total exercised bodies. Those successful negative transitions are not
successful generation. `receipt_bytes` records the actual uncompressed receipt
volume per shard and in the reconciled report. Native result artifacts are
retained for 90 days, matching the repository's existing diagnostic retention;
GitHub compresses the uploaded files. Raw streams and token storage remain
excluded. Durable release evidence must be archived before artifact expiry.
