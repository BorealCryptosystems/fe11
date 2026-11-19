# SPDX-License-Identifier: Apache-2.0
"""Enumerate native coordinates and validate their fixtures before scheduling."""
from collections import Counter
import hashlib
import json
from pathlib import Path

HERE = Path(__file__).resolve().parent
VECTORS = HERE.parent / "vectors"


def sha(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def catalogue():
    contexts = {f"linux.{rust}.openssl-{recipe}.{store}.{interface}"
                for rust in ("1.81.0", "1.100.0") for recipe in ("full", "gost")
                for store in ("file", "db") for interface in ("Standard32", "Legacy240")}
    cases = {}
    known = {sha(path): path.name for path in HERE.glob("*.py")}
    for path in sorted(VECTORS.glob("*/manifest.json")):
        rows = json.loads(path.read_text(encoding="utf-8"))
        if not isinstance(rows, list) or not any(isinstance(row, dict) and "contexts" in row for row in rows):
            continue
        for row in rows:
            identity = row["id"]
            axes = row["contexts"]
            if (identity in cases or not axes or len(set(axes)) != len(axes)
                    or not set(axes).issubset(contexts)):
                raise ValueError(f"invalid native coordinates for {identity}")
            fixture = (path.parent / row["file"]).resolve(strict=True)
            if fixture.parent != path.parent or sha(fixture) != row["sha256"]:
                raise ValueError(f"invalid fixture for {identity}")
            for field in ("reference_sha256", "known_reference_sha256", "generated_reference_sha256",
                          "domain_reference_sha256", "negative_reference_sha256", "encoding_sha256",
                          "context_reference_sha256"):
                if field in row and row[field] not in known:
                    raise ValueError(f"stale {field} for {identity}")
            for name, expected in row.get("reference_sources", {}).items():
                if known.get(expected) != name:
                    raise ValueError(f"stale reference source for {identity}")
            cases[identity] = (path, tuple(axes))
    if not cases:
        raise ValueError("empty native catalogue")
    return cases


if __name__ == "__main__":
    observed = catalogue()
    print(json.dumps(dict(cases=len(observed), contexts=Counter(
        context for _, axes in observed.values() for context in axes)), indent=2))

