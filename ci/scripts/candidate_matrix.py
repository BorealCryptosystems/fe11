# SPDX-License-Identifier: Apache-2.0
"""Check the complete native matrix before scheduling the candidate's test jobs."""
from collections import Counter
import json
from pathlib import Path
import tomllib

from candidate_inputs import ROOT
from native_matrix import COMMIT, SHARDS, catalogue_for, context, group, partitions
from common import digest


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
    reference = json.loads(Path(__file__).with_name("native-runtime-reference.json").read_text())
    if (reference["upstream_commit"] != COMMIT or reference["recipe"] != "openssl-full"
            or reference["recipe_driver"] != digest(suite / "tests/driver/recipes.py")
            or reference["recipe_support"] != digest(suite / "tests/driver/recipe_support.py")):
        raise ValueError("SoftHSM recipe identity mismatch")
    print(json.dumps(dict(coordinates=total, partitions=len(rows), contexts={a: counts[a] for a in sorted(axes)},
                          softhsm_commit=COMMIT), indent=2))


if __name__ == "__main__":
    main()
