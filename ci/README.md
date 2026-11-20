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

Failed or otherwise unaccepted observations are uploaded under `observations/`.
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
Intermittent ECDH errors on generated keys remain unclassified. Their cases
continue to fail CI if reproduced; public point-shape observations assist
attribution without exposing coordinates or derived secrets.

## Open attribution and retention

The nine oversized-salt RSA-PSS cases remain REVIEW_REQUIRED in all eight
contexts. After the permitted refusal on raw PSS, their combined-hash route
may return CKR_MECHANISM_INVALID at C_SignInit. The oracle does not accept
that code; complete two-route observations are still required for attribution.
The CI cannot report acceptance while these observations remain unresolved.

The acceptance summary counts `refused_generation_transitions` separately
from total exercised bodies. Those successful negative transitions are not
successful generation. `receipt_bytes` records the actual uncompressed receipt
volume per shard and in the reconciled report. Native result artifacts are
retained for 90 days, matching the repository's existing diagnostic retention;
GitHub compresses the uploaded files. Raw streams and token storage remain
excluded. Durable release evidence must be archived before artifact expiry.
