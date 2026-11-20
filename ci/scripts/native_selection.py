# SPDX-License-Identifier: Apache-2.0
"""Account explicitly for prerequisites unavailable in the pinned CI recipe."""
import json
from pathlib import Path
from native_verdict import fingerprint


def selection(cases, context):
    policy = json.loads(Path(__file__).with_name("native-prerequisites.json").read_text())
    if policy["upstream_commit"] != "7380895665c3094a6f57640085bee97dcfeb1496":
        raise ValueError("prerequisite policy belongs to a different native recipe")
    applicable = sorted(key for key, (_, axes) in cases.items() if context in axes)
    definitions = {}
    excluded = {}
    for identity, rule in policy["cases"].items():
        if identity not in cases:
            raise ValueError("unknown prerequisite case")
        if context not in rule["contexts"]:
            continue
        if identity not in applicable:
            raise ValueError("prerequisite outside declared case contexts")
        manifest = cases[identity][0]
        if manifest not in definitions:
            definitions[manifest] = {d["id"]: d for d in json.loads(manifest.read_text(encoding="utf-8"))}
        if fingerprint(definitions[manifest][identity]) != rule["definition"]:
            raise ValueError("excluded case definition changed; reassess its prerequisite")
        excluded[identity] = {"status": "NOT_EXECUTED", "body_started": False,
                              "prerequisite": rule["prerequisite"], "reason": rule["reason"],
                              "definition": rule["definition"]}
    return [key for key in applicable if key not in excluded], excluded
