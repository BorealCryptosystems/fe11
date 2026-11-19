# SPDX-License-Identifier: Apache-2.0
"""Platform-independent validation of worker reports and observed native traces."""
import json
import re


def read_records(path, maximum=16 * 1024 * 1024):
    if not path.is_file() or path.stat().st_size > maximum:
        raise ValueError("missing or oversized worker record stream")
    with path.open(encoding="utf-8") as source:
        text = source.read(maximum + 1)
    if len(text) > maximum or not text.endswith("\n"):
        raise ValueError("incomplete record stream")
    return [json.loads(line) for line in text.splitlines()]


def verify_worker(path, process, expected, terminal_kind, require_success=True):
    if process["state"] != "EXITED" or process["exit_code"] not in (0, 1):
        raise ValueError("worker did not produce a regular outcome")
    records = read_records(path)
    if not records or records[-1].get("kind") != terminal_kind:
        raise ValueError("missing terminal worker record")
    for record in records:
        if record.get("schema") != 1 or any(record.get(key) != value for key, value in expected.items()):
            raise ValueError("worker identity mismatch")
    assertions = records[:-1]
    if any(row.get("kind") != "assertion" or row.get("sequence") != index
           for index, row in enumerate(assertions, 1)):
        raise ValueError("invalid assertion sequence")
    terminal = records[-1]
    if terminal.get("assertions") != len(assertions):
        raise ValueError("worker assertion count mismatch")
    body = "NOT_EXECUTED" if terminal_kind == "preparation_terminal" else "PASS"
    phases = tuple(terminal.get(key) for key in ("setup", "body", "cleanup"))
    if any(value not in ("PASS", "FAIL", "NOT_EXECUTED") for value in phases):
        raise ValueError("unknown worker phase result")
    success = phases == ("PASS", body, "PASS")
    failure = "PREREQUISITE_MISSING" if terminal_kind == "preparation_terminal" else "FAIL"
    if terminal.get("status") != ("PASS" if success else failure) or process["exit_code"] != (0 if success else 1):
        raise ValueError("worker phases, status and exit disagree")
    if require_success and not success:
        raise ValueError("worker outcome is not PASS")
    common = {"schema", "case", "source_sha256", "recipe_sha256", "module_sha256", "kind"}
    for record in assertions:
        if set(record) != common | {"sequence", "phase", "assertion", "producer", "value"}:
            raise ValueError("unknown assertion field")
        if record["phase"] not in ("setup", "body", "cleanup"):
            raise ValueError("unknown assertion phase")
        if record["producer"] not in (
            "fe11_local", "native", "published_vector", "supervisor",
            "test_oracle", "independent_reference",
        ):
            raise ValueError("unknown assertion producer")
        if not isinstance(record["assertion"], str) or not re.fullmatch(r"[A-Za-z0-9._:@/-]{1,512}", record["assertion"]):
            raise ValueError("invalid assertion identity")
        value = record["value"]
        if isinstance(value, dict) and set(value) == {"category", "cause"}:
            if (record["producer"] != "fe11_local" or value["category"] not in ("busy", "rejected")
                    or not isinstance(value["cause"], str)
                    or not re.fullmatch(r"[A-Za-z0-9_(): ]{1,256}", value["cause"])):
                raise ValueError("invalid typed local diagnostic")
            continue
        if type(value) is not bool and not (type(value) is int and 0 <= value < 2**64):
            if (not isinstance(value, dict) or set(value) != {"function", "code", "may_have_effect"}
                    or not isinstance(value["function"], str)
                    or not re.fullmatch(r"C_[A-Za-z0-9]+", value["function"])
                    or type(value["code"]) is not int or not 0 <= value["code"] < 2**64
                    or type(value["may_have_effect"]) is not bool):
                raise ValueError("invalid assertion value")
    fields = common | {"assertions", "setup", "body", "cleanup", "status"}
    if terminal_kind == "terminal":
        fields.add("attribution")
        if terminal.get("attribution") != ("NONE" if success else "UNKNOWN"):
            raise ValueError("worker failure attribution disagrees with phases")
    if set(terminal) != fields:
        raise ValueError("unknown terminal field")
    return records


def trace_matches(records, expected, module_sha256, observer_sha256, observation_set=None,
                  expected_exit_code=0):
    # Observation completeness and a successful test body are separate facts.
    # Existing callers require zero; an attributed failed body may request one.
    if type(expected_exit_code) is not int or expected_exit_code not in (0, 1):
        return False
    if len(records) < 2 or records[0].get("kind") != "observer" or records[-1].get("kind") != "observer_terminal":
        return False
    metadata = records[0]
    if metadata.get("module_sha256") != module_sha256 or metadata.get("script_sha256") != observer_sha256:
        return False
    if any(row.get("kind") not in ("entry", "location") for row in records[1:-1]):
        return False
    locations = [row for row in records if row.get("kind") == "location"]
    observed = set(expected if observation_set is None else observation_set)
    if ({row.get("function") for row in locations} != observed
            or any(row.get("module_sha256") != module_sha256 for row in locations)):
        return False
    terminal = records[-1]
    if (terminal.get("complete") is not True or terminal.get("exit_code") != expected_exit_code
            or terminal.get("resolved") != len(observed)):
        return False
    entries = [row for row in records if row.get("kind") == "entry"]
    return (terminal.get("events") == len(entries)
            and [row.get("function") for row in entries] == expected
            and [row.get("sequence") for row in entries] == list(range(1, len(entries) + 1)))


