# SPDX-License-Identifier: Apache-2.0
"""Check the complete native matrix before scheduling the candidate's test jobs."""
from collections import Counter
import json
from pathlib import Path
import tomllib

from candidate_inputs import ROOT
from native_matrix import COMMIT, SHARDS, catalogue_for, context, group, partitions
from common import digest
from native_qualification import exposed_domain, policy as qualification_policy
from native_verdict import fingerprint


def main():
    suite = ROOT / "fe11-tests"
    cases = catalogue_for(suite)
    rows = partitions()
    counts = Counter(axis for _, axes in cases.values() for axis in axes)
    axes = {context(r) for r in rows}
    total = sum(counts[axis] for axis in axes)
    if (len(rows) != 256 or len({group(r) for r in rows}) != len(rows)
            or len(axes) != 8 or total != 99775):
        raise ValueError("Unexpected native test matrix for Fe11 0.1.1")
    for axis in axes:
        numbers = sorted(r["shard"] for r in rows if context(r) == axis)
        if numbers != list(range(SHARDS)) or not counts[axis]:
            raise ValueError(f"Incomplete partition plan: {axis}")
    for package in (ROOT / "library", suite):
        if tomllib.loads((package / "Cargo.toml").read_text())["package"]["version"] != "0.1.1":
            raise ValueError("Wrong package version")
    qualification = qualification_policy()
    domains = json.loads(Path(__file__).with_name("native-ecdh-domains.json").read_text())["domains"]
    curves = json.loads((suite / "tests/vectors/curve-operations/manifest.json").read_text())
    named = {d["id"]: d for d in curves if d["curve"]["field"] != "unknown"}
    if set(domains) != set(named):
        raise ValueError("Curve domain inventory changed; reassess ECDH qualification")
    for identity, domain in domains.items():
        definition = named[identity]
        bits = domain["field_bits"]
        if (type(bits) is not int or not 112 <= bits <= 571
                or (bits + 7) // 8 != definition["field_width"]
                or type(domain["first_x_byte_max"]) is not int
                or not 0 <= domain["first_x_byte_max"] < (1 << ((bits - 1) % 8 + 1))):
            raise ValueError("Invalid audited curve domain")
    if set(qualification) != {key for key, domain in domains.items() if exposed_domain(domain)}:
        raise ValueError("Unqualified scenarios do not cover the audited decoder domain")
    for identity, rule in qualification.items():
        manifest, declared = cases[identity]
        definition, = [d for d in json.loads(manifest.read_text()) if d["id"] == identity]
        if (fingerprint(definition) != rule["definition"]
                or rule["vector_sha256"] != definition["sha256"]
                or rule["nominal_sequence"] != definition["expected_native_calls"]
                or set(rule["contexts"]) != axes or not axes.issubset(declared)):
            raise ValueError("Unqualified ECDH policy differs from the candidate definitions")
    reference = json.loads(Path(__file__).with_name("native-runtime-reference.json").read_text())
    if (reference["upstream_commit"] != COMMIT or reference["recipe"] != "openssl-full"
            or reference["recipe_driver"] != digest(suite / "tests/driver/recipes.py")
            or reference["recipe_support"] != digest(suite / "tests/driver/recipe_support.py")):
        raise ValueError("SoftHSM recipe identity mismatch")
    print(json.dumps(dict(coordinates=total, partitions=len(rows), contexts={a: counts[a] for a in sorted(axes)},
                          softhsm_commit=COMMIT), indent=2))


if __name__ == "__main__":
    main()
