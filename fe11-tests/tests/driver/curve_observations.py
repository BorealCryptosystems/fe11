# SPDX-License-Identifier: Apache-2.0
"""Observe stopped curve scenarios without turning failures into passes.

An unsuccessful body may stop at a prefix of its fixed call sequence, then
destroy exactly the objects it reports owning. Successful bodies still require
the entire nominal sequence. This retains failure evidence without accepting
missing calls as successful coverage.
"""


def sequences(case, records, actual):
    """Return only traces consistent with the terminal and owned objects."""
    counts = {}
    for name, maximum in (("curve_created_pairs", 2), ("curve_owned_objects", 8)):
        values = [r for r in records[:-1] if r.get("assertion") == name]
        if (len(values) != 1 or values[0].get("producer") != "native"
                or type(values[0].get("value")) is not int
                or not 0 <= values[0]["value"] <= maximum):
            raise ValueError("missing or invalid curve ownership observation")
        counts[name] = values[0]["value"]
    pairs, owned = counts["curve_created_pairs"], counts["curve_owned_objects"]
    terminal = records[-1]
    if terminal.get("setup") != "PASS" or terminal.get("cleanup") != "PASS":
        raise ValueError("curve setup or cleanup incomplete")
    prefix = ["C_Initialize", "C_OpenSession"]
    close = ["C_CloseSession", "C_Finalize"]
    refused = prefix + ["C_GenerateKeyPair"] + close
    nominal = case["expected_native_calls"]
    if case["expected_refused_native_calls"] != refused:
        raise ValueError("curve refused sequence changed")
    unknown = nominal == refused
    body = (["C_GenerateKeyPair"] if unknown else
            ["C_GenerateKeyPair"] * 2 + ["C_GetAttributeValue"] * 7
            + ["C_CreateObject"] * 2 + ["C_GetAttributeValue"]
            + ["C_SignInit", "C_Sign", "C_VerifyInit", "C_Verify"] * 2
            + ["C_DeriveKey", "C_GetAttributeValue"] * 2)
    if not unknown and nominal != prefix + body + ["C_DestroyObject"] * 8 + close:
        raise ValueError("curve nominal sequence changed")
    if terminal.get("status") == "PASS" and terminal.get("body") == "PASS":
        if (pairs, owned) == ((0, 0) if unknown else (2, 8)):
            return [nominal]
        raise ValueError("successful curve body has incomplete ownership")
    if terminal.get("status") != "FAIL" or terminal.get("body") != "FAIL":
        raise ValueError("curve body has no completed verdict")

    # Entry alone does not prove successful creation. Before/after ownership
    # are both possible at that boundary; the worker count and cleanup suffix
    # disambiguate them. Neither possibility changes the failed body verdict.
    possibilities = []
    current_owned = current_pairs = 0
    if (pairs, owned) == (0, 0):
        possibilities.append(prefix + close)
    for function in body:
        prefix = prefix + [function]
        before = current_pairs, current_owned
        if function == "C_GenerateKeyPair":
            current_pairs += 1
            current_owned += 2
        elif function in ("C_CreateObject", "C_DeriveKey"):
            current_owned += 1
        if (pairs, owned) in (before, (current_pairs, current_owned)):
            possibilities.append(prefix + ["C_DestroyObject"] * owned + close)
    selected = [sequence for sequence in possibilities if sequence == actual]
    if len(selected) != 1:
        raise ValueError("curve failure has no unique owned trace")
    return selected
