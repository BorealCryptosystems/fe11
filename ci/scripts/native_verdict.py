# SPDX-License-Identifier: Apache-2.0
"""Compare a completed native observation with a documented SoftHSM result."""
import hashlib
import json
from pathlib import Path


def fingerprint(value):
    encoded = json.dumps(value, ensure_ascii=True, sort_keys=True, separators=(",", ":"), allow_nan=False)
    return hashlib.sha256(encoded.encode("ascii")).hexdigest()


def accepted_observation(row):
    """A documented missing prerequisite contributes zero exercised test bodies."""
    return (row["status"], row["ci_verdict"], row.get("body_started")) in {
        ("PASS", "PASS", True), ("FAIL", "DOCUMENTED_DIVERGENCE", True),
        ("FAIL", "DOCUMENTED_PREREQUISITE", False)}


def observation(result, work, runtime=None, prerequisite=False):
    from report_validation import read_records

    if (result["status"] != "FAIL" or result["body_started"] is not (not prerequisite)
            or (work / "tokens").exists()
            or json.loads((work / "token-cleanup.json").read_text()) != {"status": "REMOVED"}):
        raise ValueError("incomplete execution or token cleanup")
    config = json.loads((work / "observer.json").read_text())
    trace = read_records(work / "observation/trace.jsonl")
    return observation_digest(result, config, trace, runtime, prerequisite)


def observation_digest(result, config, trace, runtime=None, prerequisite=False):
    from report_validation import trace_matches
    records = result["worker_records"]
    terminal = records[-1]
    phases = ("FAIL", "NOT_EXECUTED") if prerequisite else ("PASS", "FAIL")
    if ((terminal["kind"], terminal["setup"], terminal["body"], terminal["cleanup"], terminal["status"])
            != ("terminal", *phases, "PASS", "FAIL") or result["body_started"] is not (not prerequisite)):
        raise ValueError("unattributable phase result")
    for name in ("observer_process", "provision_process"):
        if (result[name]["state"], result[name]["exit_code"]) != ("EXITED", 0):
            raise ValueError("failed native process")
    if not trace_matches(trace, result["native_sequence"], result["module_sha256"],
                         result["observer_script_sha256"], config["functions"], expected_exit_code=1):
        raise ValueError("incomplete native trace")
    # ASLR addresses and system thread IDs vary between executions. Keep the
    # scheduling order, runtime roles and any observed initialization arguments.
    trace_fields = {
        "observer": {"kind", "gdb_version", "python_version", "module_sha256", "script_sha256"},
        "location": {"kind", "function", "address", "module_sha256"},
        "entry": {"kind", "function", "sequence", "process", "thread"},
        "observer_terminal": {"kind", "exit_code", "events", "resolved", "complete"},
    }
    metadata = []
    threads = {}
    schedule = []
    for row in trace:
        fields = trace_fields[row["kind"]]
        if not fields.issubset(row):
            raise ValueError("incomplete native observation")
        extra = {key: value for key, value in row.items() if key not in fields}
        if extra:
            metadata.append((row["kind"], row.get("function"), row.get("sequence"), extra))
        if row["kind"] == "entry":
            thread = row["process"], tuple(row["thread"])
            schedule.append(threads.setdefault(thread, len(threads)))
    # Event payloads and ordering carry the failure's meaning. Bind the repeated
    # run identities before removing them from the portable observation.
    identities = ("case", "source_sha256", "recipe_sha256", "module_sha256")
    outcomes = []
    for record in records:
        if any(record[key] != result[key] for key in identities):
            raise ValueError("worker identity mismatch")
        outcomes.append({key: value for key, value in record.items() if key not in identities})
    run_fields = {"scope", "case", "context", "worker_sha256", "source_sha256", "gate_sha256",
                  "recipe_sha256", "manifest_sha256", "provision_process", "observer_process",
                  "provision_dependencies", "case_dependencies", "worker_records", "observer_script_sha256"}
    meaning = {key: value for key, value in result.items() if key not in run_fields}
    if metadata:
        meaning["trace_metadata"] = metadata
    if len(threads) > 1:
        meaning["thread_schedule"] = schedule
    if runtime is not None:
        if result["module_sha256"] != runtime["module"]:
            raise ValueError("observation uses a different module from the verified runtime")
        # Canonicalize only the image fields in the comparison. The trace above
        # was verified against the actual loaded image. The plan retains both
        # builds' hashes; the original worker and observer reports stay intact.
        meaning["module_sha256"] = runtime["reference_module"]
    for key in ("provision_dependencies", "case_dependencies"):
        libraries = []
        for name, sha in result[key].items():
            if runtime is None:
                libraries.append((Path(name).name, sha))
            else:
                loaded, reference_name, reference_sha = runtime["dependencies"][name]
                if sha != loaded:
                    raise ValueError("observed dependency differs from the verified runtime")
                libraries.append((reference_name, reference_sha))
        meaning[key] = sorted(libraries)
    meaning.update(records=outcomes, observed_functions=sorted(config["functions"]))
    return fingerprint(meaning)


def classify(catalogue, identity, context, definition_digest, result, work, runtime=None):
    if context in catalogue["requires_review"].get(identity, ()):
        return "REVIEW_REQUIRED"
    expected = catalogue["cases"].get(identity)
    profile = expected["contexts"].get(context) if expected else None
    if profile is None:
        return "PASS" if result["status"] == "PASS" else "UNEXPECTED_RESULT"
    if result["status"] == "PASS":
        return "DIVERGENCE_DISAPPEARED"
    if result["status"] != "FAIL" or definition_digest != expected["definition"]:
        return "DIVERGENCE_CHANGED"
    if result.get("case") != identity or result.get("context") != context:
        return "DIVERGENCE_CHANGED"
    expected_module = catalogue["module_sha256"] if runtime is None else runtime["module"]
    if result.get("module_sha256") != expected_module or (
            runtime is not None and runtime["reference_module"] != catalogue["module_sha256"]):
        return "DIVERGENCE_CHANGED"
    prerequisite = expected.get("coverage") == "prerequisite"
    observed = observation(result, work, runtime, prerequisite)
    if observed != profile:
        return "DIVERGENCE_CHANGED"
    return "DOCUMENTED_PREREQUISITE" if prerequisite else "DOCUMENTED_DIVERGENCE"
