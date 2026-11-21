# SPDX-License-Identifier: Apache-2.0
"""Require one complete, explicitly non-qualified observation per selected context."""
import argparse
import json
from pathlib import Path

from native_matrix import context


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--row", type=json.loads, required=True)
    parser.add_argument("--root", type=Path, required=True)
    args = parser.parse_args()
    selection = json.loads(Path(__file__).with_name("soft-hsm-correction-selection.json").read_text())
    selected = [item for item in selection if item["context"] == context(args.row)]
    if len(selected) != 1:
        raise ValueError("Expected exactly one selected coordinate")
    output = args.root / "diagnostics"
    summary = json.loads((output / "summary.json").read_text())
    rows = [json.loads(line) for line in (output / "observations.jsonl").read_text().splitlines()]
    if len(rows) != 1 or summary.get("selected") != 1 or summary.get("attempts_per_case") != 1:
        raise ValueError("Missing, repeated or additional execution")
    row = rows[0]
    result = row["result"]
    raw = result.get("status")
    if (row.get("case") != selected[0]["case"] or row.get("context") != selected[0]["context"]
            or row.get("definition_sha256") != selected[0]["definition_sha256"]
            or row.get("driver_failure") or row.get("classification_error")
            or row.get("qualification") != "NOT_QUALIFIED" or row.get("ci_verdict") != "NOT_QUALIFIED"
            or raw not in ("PASS", "FAIL") or summary.get("results") != {raw: 1}
            or result.get("body_started") is not True or result.get("native_sequence_matches") is not True
            or row.get("token_cleanup") != {"status": "REMOVED"}):
        raise ValueError("Unexpected or incomplete targeted observation")
    terminal = result["worker_records"][-1]
    if any(terminal.get(key) != value for key, value in
           (("setup", "PASS"), ("body", raw), ("cleanup", "PASS"), ("status", raw))):
        raise ValueError("Setup, execution or cleanup did not complete")
    print(json.dumps(dict(case=row["case"], context=row["context"], raw=raw,
                          ci_verdict=row["ci_verdict"], qualification=row["qualification"])))


if __name__ == "__main__":
    main()
