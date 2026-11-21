# SPDX-License-Identifier: Apache-2.0
"""Keep unstable ECDH scenarios visible without crediting qualification."""
import json
from functools import lru_cache
from pathlib import Path

from native_verdict import classify as classify_documented, fingerprint, observation_details


@lru_cache(maxsize=1)
def policy():
    rules = json.loads(Path(__file__).with_name("native-unqualified.json").read_text())
    if (rules["upstream_commit"] != "7380895665c3094a6f57640085bee97dcfeb1496"
            or rules["recipe"] != "openssl-full" or rules["qualification"] != "NOT_QUALIFIED"):
        raise ValueError("unqualified scenarios belong to a different native recipe")
    return {identity: dict(rule, contexts=rules["contexts"], nominal_sequence=rules["nominal_sequence"])
            for identity, rule in rules["cases"].items()}


def exposed_domain(domain):
    """Bound the raw/DER ambiguity by point length and the field's top byte."""
    length = 1 + 2 * ((domain["field_bits"] + 7) // 8)
    if length in (32, 56, 65, 97, 133):
        return False
    first = domain["first_x_byte_max"]
    return (length - 2 < 128 and length - 2 <= first) or (length > 3 and first >= 0x81)


def rule_for(identity, context, definition):
    rule = policy().get(identity)
    if rule is None or context not in rule["contexts"]:
        return None
    if definition != rule["definition"]:
        raise ValueError("unqualified scenario definition changed")
    return rule


def known_refusal(rule, result):
    """Match the complete refused-agreement path, not GENERAL_ERROR alone.

    This is a bounded quarantine, not an attribution of each new failure.
    The independent observer and cleanup receipt are checked by classify().
    Local refusals, changed assertions and failures outside this path block CI.
    """
    if (result.get("native_sequence_matches") is not True
            or result.get("vector_sha256") != rule["vector_sha256"]
            or result.get("curve_created_pairs") != 2):
        return False
    owned = result.get("curve_owned_objects")
    if type(owned) is not int or owned not in (6, 7):
        return False
    attempts = owned - 5
    nominal = rule["nominal_sequence"]
    cut = [n for n, name in enumerate(nominal) if name == "C_DeriveKey"][attempts - 1]
    expected_calls = nominal[:cut + 1] + ["C_DestroyObject"] * owned + ["C_CloseSession", "C_Finalize"]
    if result.get("native_sequence") != expected_calls:
        return False
    records = result["worker_records"]
    events = [(r.get("phase"), r.get("assertion"), r.get("producer"), r.get("value"))
              for r in records[:-1]]
    expected = [("setup", "module_opened", "fe11_local", True)]
    if rule["shape_observed"]:
        for n in range(attempts):
            offset = 1 + n * 2
            if len(events) <= offset + 1 or type(events[offset + 1][3]) is not bool:
                return False
            expected.extend([
                ("body", "ecdh_sec1_point_bytes", "test_oracle", rule["point_bytes"]),
                ("body", "ecdh_sec1_matches_der_header", "test_oracle", events[offset + 1][3])])
    expected.extend([
        ("body", "native_error", "native", {"function": "C_DeriveKey", "code": 5, "may_have_effect": True}),
        ("body", "curve_created_pairs", "native", 2),
        ("body", "curve_owned_objects", "native", owned),
        ("body", "curve_generation_import_signature_agreement", "test_oracle", False)])
    # JSON fingerprints also distinguish booleans from integer values.
    return (fingerprint(events) == fingerprint(expected)
            and all(r.get("kind") == "assertion" and r.get("sequence") == n
                    for n, r in enumerate(records[:-1], 1)))


def classify(rule, catalogue, identity, context, result, work, runtime):
    """Keep raw PASS/FAIL separate from qualification and require complete evidence."""
    if (runtime is None or runtime["reference_module"] != catalogue["module_sha256"]
            or result.get("module_sha256") != runtime["module"]
            or result.get("case") != identity or result.get("context") != context
            or result.get("body_started") is not True
            or result.get("vector_sha256") != rule["vector_sha256"]):
        return "INSUFFICIENT_EVIDENCE"
    if ((work / "tokens").exists()
            or json.loads((work / "token-cleanup.json").read_text()) != {"status": "REMOVED"}):
        return "INSUFFICIENT_EVIDENCE"
    dependencies = {name: value[0] for name, value in runtime["dependencies"].items()}
    if any(result.get(name) != dependencies for name in ("provision_dependencies", "case_dependencies")):
        return "INSUFFICIENT_EVIDENCE"
    if result["status"] == "PASS":
        if context in catalogue["cases"].get(identity, {}).get("contexts", {}):
            # A previously documented failure becoming successful is a change
            # requiring review, even though this scenario earns no qualification.
            return classify_documented(catalogue, identity, context, rule["definition"], result, work, runtime)
        terminal = result["worker_records"][-1]
        if (result.get("native_sequence_matches") is True
                and all(terminal.get(name) == "PASS" for name in ("setup", "body", "cleanup", "status"))):
            return "NOT_QUALIFIED"
        return "INSUFFICIENT_EVIDENCE"
    if result["status"] == "FAIL":
        observation_details(result, work, runtime)
        if known_refusal(rule, result):
            return "NOT_QUALIFIED"
        # Some exposed curves already have an independently documented width
        # divergence. Preserve its exact comparison instead of accepting other
        # errors broadly, or turning an established observation into a regression.
        return classify_documented(catalogue, identity, context, rule["definition"], result, work, runtime)
    return "UNEXPECTED_RESULT"
