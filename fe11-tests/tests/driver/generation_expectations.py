# SPDX-License-Identifier: Apache-2.0
"""Select a generation trace using the observed return and independent inventory."""
import json


def refused_pair(case, result):
    contract = case["generation_refusal"]
    if type(contract["code"]) is not int or contract["code"] != 0x70 or type(contract["prerequisite"]) is not bool:
        raise ValueError("invalid generation refusal contract")
    rows = result["worker_records"]
    terminal = rows[-1]
    expected = [
        ("setup", "module_opened", "fe11_local", True),
        ("setup", "keypair_native_return", "native", contract["code"]),
        ("cleanup", "keypair_namespace_objects", "test_oracle", 0),
        ("cleanup", "keypair_namespace_remaining", "test_oracle", 0),
    ]
    if contract["prerequisite"]:
        expected.append(("setup", "native_error", "native",
                         {"function": "C_GenerateKeyPair", "code": 0x70, "may_have_effect": True}))
        phases = ("FAIL", "NOT_EXECUTED", "PASS", "FAIL")
    else:
        expected.append(("body", "generation_transition_and_native_ownership", "test_oracle", True))
        phases = ("PASS", "PASS", "PASS", "PASS")
    if "assertions" in contract:
        # A manifest may describe a different action on the same refused ticket.
        # Keep its complete ordered assertions, including native cancellation or
        # polling outcomes. It must still independently prove an empty namespace.
        expected = contract["assertions"]
        if (contract["prerequisite"] or
                [r for r in expected if r[1] == "keypair_native_return"] not in (
                    [["setup", "keypair_native_return", "native", 0x70]],
                    [["body", "keypair_native_return", "native", 0x70]]) or
                any(["cleanup", name, "test_oracle", 0] not in expected
                    for name in ("keypair_namespace_objects", "keypair_namespace_remaining"))):
            raise ValueError("incomplete refused-ticket observation contract")
    observed = [(r.get("phase"), r.get("assertion"), r.get("producer"), r.get("value")) for r in rows[:-1]]
    # Exact records reject unexpected errors. The observer return is also
    # copied by the worker; namespace reads independently establish cleanup.
    # JSON comparison preserves boolean/integer distinctions in assertion values.
    return (json.dumps(result.get("generation_returns")) == json.dumps([contract["code"]])
            and json.dumps(observed, sort_keys=True) == json.dumps(expected, sort_keys=True)
            and terminal.get("kind") == "terminal"
            and tuple(terminal.get(k) for k in ("setup", "body", "cleanup", "status")) == phases)
