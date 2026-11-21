# SPDX-License-Identifier: Apache-2.0
"""Schedule the native package's declared cases for one prepared SoftHSM context."""
import argparse
from collections import Counter
import json
from pathlib import Path
import re
import shutil
import sys
import tempfile
import traceback
from types import SimpleNamespace
from native_verdict import accepted_observation, classify, fingerprint, observation_details
from native_selection import selection
import native_qualification

POINT_BYTES = {"curve.operations.sect239k1": 61,
               "curve.operations.secp160k1": 41,
               "curve.operations.X9_62_prime192v2": 49,
               "curve.operations.X9_62_c2tnb239v2": 61}


def native_errors(result):
    """Expose native return values without copying untrusted worker output."""
    entries = []
    for record in result.get("worker_records", ()):
        if record.get("assertion") != "native_error" or record.get("producer") != "native":
            continue
        value = record.get("value")
        if (isinstance(value, dict) and isinstance(value.get("function"), str)
                and re.fullmatch(r"C_[A-Za-z0-9_]{1,64}", value["function"])
                and type(value.get("code")) is int and 0 <= value["code"] < 2**64
                and type(value.get("may_have_effect")) is bool):
            entries.append({key: value[key] for key in ("function", "code", "may_have_effect")})
    return entries


def ecdh_peer_shapes(result):
    """Retain one public shape per attempted agreement, in dispatch order."""
    names = ("ecdh_sec1_point_bytes", "ecdh_sec1_matches_der_header")
    records = [r for r in result.get("worker_records", ()) if r.get("assertion") in names]
    shapes = []
    if len(records) % 2:
        raise ValueError("incomplete ECDH point observation")
    for length, header in zip(records[::2], records[1::2]):
        if ((length["assertion"], header["assertion"]) != names
                or any(r["phase"] != "body" or r["producer"] != "test_oracle" for r in (length, header))
                or header["sequence"] != length["sequence"] + 1
                or type(length["value"]) is not int or length["value"] != POINT_BYTES[result["case"]]
                or type(header["value"]) is not bool):
            raise ValueError("invalid public point observation")
        shapes.append({"sec1_uncompressed_bytes": length["value"], "also_matches_der_header": header["value"]})
    if (len(shapes) > 2 or len(shapes) < result.get("native_sequence", []).count("C_DeriveKey")
            or (result.get("status") == "PASS" and len(shapes) != 2)):
        raise ValueError("inconsistent public point observations")
    return shapes


def montgomery_observation(result):
    """Join the module return, the worker's phase and the independent peer inventory."""
    rows = result["worker_records"]
    codes = result["generation_returns"]
    worker_codes = [r["value"] for r in rows if r.get("assertion") == "keypair_native_return"]
    if (codes != worker_codes or len(codes) != result["native_sequence"].count("C_GenerateKeyPair")
            or any(type(code) is not int or not 0 <= code < 2**64 for code in worker_codes)):
        raise ValueError("inconsistent key-pair return evidence")
    inventory = {}
    for record in rows:
        name = record.get("assertion")
        if name in ("keypair_namespace_objects", "keypair_namespace_remaining"):
            value = record["value"]
            if (name in inventory or record["phase"] != "cleanup" or record["producer"] != "test_oracle"
                    or type(value) is not int or not 0 <= value <= 8):
                raise ValueError("inconsistent key-pair inventory")
            inventory[name] = value
    if codes and rows[-1]["cleanup"] == "PASS" and (
            len(inventory) != 2 or inventory["keypair_namespace_remaining"] != 0):
        raise ValueError("incomplete key-pair cleanup evidence")
    return dict(native_returns=codes, transition=rows[-1]["body"], inventory=inventory)


def refused_generation_transition(row):
    """Count exercised refused-ticket transitions separately from creation."""
    evidence = row.get("keypair_generation", {})
    return (row["status"] == "PASS" and row["ci_verdict"] == "PASS"
            and row.get("body_started") is True and evidence.get("native_returns") == [0x70]
            and evidence.get("transition") == "PASS"
            and evidence.get("inventory") == {"keypair_namespace_objects": 0,
                                               "keypair_namespace_remaining": 0})


def run(args):
    driver = args.package.resolve(strict=True) / "tests/driver"
    sys.path.insert(0, str(driver))
    from case import run_case
    from native_catalogue import catalogue, sha

    rust, recipe, store, interface = args.rust, args.recipe_name, args.backend, args.interface
    context = f"linux.{rust}.{recipe}.{store}.{interface}"
    cases = catalogue()
    applicable, unavailable = selection(cases, context)
    if not applicable or args.shards < 1 or not 0 <= args.shard < args.shards <= len(applicable):
        raise ValueError("empty or invalid native partition")
    selected = applicable[args.shard::args.shards]
    root = args.output.resolve()
    root.mkdir(mode=0o700, exist_ok=False)
    gate = json.loads(args.gate.read_text(encoding="utf-8"))
    if gate["status"] != "RECIPE_READY" or gate["rust"] != rust or gate["backend"] != store:
        raise ValueError("gate does not qualify this compiler and backend")
    frozen = dict(rust=rust, recipe_name=recipe, backend=store, interface=interface,
                  source_sha256=args.source_sha256, worker=args.worker.resolve(strict=True),
                  worker_sha256=sha(args.worker), gate=args.gate.resolve(strict=True),
                  gate_sha256=sha(args.gate), recipe=args.recipe.resolve(strict=True),
                  verify_engine=args.verify_engine.resolve(strict=True),
                  verify_engine_sha256=sha(args.verify_engine))
    hashes = {manifest:sha(manifest) for manifest in {cases[key][0] for key in selected}}
    definitions = {row["id"]: fingerprint(row) for path in hashes
                   for row in json.loads(path.read_text(encoding="utf-8"))}
    policy = json.loads((Path(__file__).parent / "native-divergences.json").read_text(encoding="utf-8"))
    if gate["worker_sha256"] != frozen["worker_sha256"]:
        raise ValueError("gate belongs to a different worker")
    plan = {"context":context, "shard":args.shard, "shards":args.shards,
            "applicable":len(applicable), "expected":selected, "source_sha256":args.source_sha256,
            "worker_sha256":frozen["worker_sha256"], "gate_sha256":frozen["gate_sha256"]}
    plan["unavailable_prerequisites"] = unavailable
    runtime = getattr(args, "runtime", None)
    if runtime is not None:
        if gate["module_sha256"] != runtime["module"] or {d["path"]: d["sha256"] for d in gate["dependencies"]} != {
                path: values[0] for path, values in runtime["dependencies"].items()}:
            raise ValueError("qualified gate differs from the runtime selected for comparison")
        plan["runtime"] = runtime["receipt"]
    (root / "plan.json").write_text(json.dumps(plan, indent=2), encoding="utf-8")
    with (root / "results.jsonl").open("x", encoding="utf-8") as journal:
        for identity in selected:
            manifest = cases[identity][0]
            # Raw child streams and disposable token storage stay inside an owned directory.
            tmp = Path(tempfile.mkdtemp(dir=root))
            work = tmp / "case"
            options = SimpleNamespace(**frozen, case=identity, manifest=manifest,
                                      manifest_sha256=hashes[manifest], root=work)
            failure = None
            try:
                result = run_case(options)
            except Exception as error:
                origin = traceback.extract_tb(error.__traceback__)[-1]
                failure = {"type": type(error).__name__, "file": Path(origin.filename).name,
                           "function": origin.name, "line": origin.lineno}
                result = {"status":"INCOMPLETE"}
                partial = work / "result.json"
                if partial.is_file():
                    saved = json.loads(partial.read_text(encoding="utf-8"))
                    if saved.get("case") == identity and saved.get("worker_sha256") == frozen["worker_sha256"]:
                        result.update({key: saved[key] for key in ("body_started", "provision_dependencies")
                                       if key in saved})
            status = result.get("status")
            if status not in ("PASS", "FAIL", "INCOMPLETE"):
                raise ValueError("unexpected case verdict")
            row = {"case":identity, "status":status, "body_started":result.get("body_started") is True}
            if failure:
                row["driver_failure"] = failure
            if runtime is not None:
                row["provision_dependencies_verified"] = result.get("provision_dependencies") == {
                    path: values[0] for path, values in runtime["dependencies"].items()}
            row["native_errors"] = native_errors(result)
            row["native_sequence_matches"] = result.get("native_sequence_matches")
            if "prerequisite_unavailable" in result:
                row["prerequisite_unavailable"] = result["prerequisite_unavailable"]
            try:
                rule = native_qualification.rule_for(identity, context, definitions[identity])
                if rule is not None:
                    row["qualification"] = "NOT_QUALIFIED"
                if identity in POINT_BYTES:
                    row["ecdh_peer_points"] = ecdh_peer_shapes(result)
                if "generation_returns" in result:
                    row["keypair_generation"] = montgomery_observation(result)
                if rule is not None:
                    row["ci_verdict"] = native_qualification.classify(
                        rule, policy, identity, context, result, work, runtime)
                else:
                    row["ci_verdict"] = classify(policy, identity, context, definitions[identity], result, work, runtime)
            except (KeyError, OSError, TypeError, ValueError, IndexError):
                row["ci_verdict"] = "INSUFFICIENT_EVIDENCE"
            phases = [record for record in result.get("worker_records", [])
                      if record.get("kind") == "terminal"]
            if len(phases) == 1:
                row["phases"] = [phases[0][name] for name in ("setup", "body", "cleanup")]
            if status != "PASS" or row["ci_verdict"] != "PASS":
                # Structured, validated worker records contain public scalars,
                # typed diagnostics and hashes. Never upload child streams,
                # observer configuration, generated key data or token storage.
                receipt = {"case": identity, "context": context,
                           "definition_sha256": definitions[identity], "result": result,
                           "driver_failure": failure, "ci_verdict": row["ci_verdict"]}
                if "qualification" in row:
                    receipt["qualification"] = row["qualification"]
                if (work / "token-cleanup.json").is_file():
                    receipt["token_cleanup"] = json.loads((work / "token-cleanup.json").read_text())
                if status == "FAIL":
                    try:
                        receipt["comparison"] = observation_details(
                            result, work, runtime, prerequisite=not result.get("body_started"))
                    except (KeyError, OSError, TypeError, ValueError, IndexError) as error:
                        receipt["comparison_unavailable"] = type(error).__name__
                destination = root / "observations"
                destination.mkdir(exist_ok=True)
                (destination / (fingerprint(identity) + ".json")).write_text(
                    json.dumps(receipt, indent=2), encoding="utf-8")
            journal.write(json.dumps(row) + "\n")
            journal.flush()
            if (identity == selected[0] and runtime is not None
                    and not row["provision_dependencies_verified"]):
                raise ValueError("first case did not verify the worker's loaded dependencies")
            if status == "PASS" and row["ci_verdict"] == "PASS":
                shutil.rmtree(tmp)
    observed = [json.loads(line) for line in (root / "results.jsonl").read_text().splitlines()]
    if [row["case"] for row in observed] != selected:
        raise ValueError("incomplete or reordered shard report")
    accepted = all(accepted_observation(row) for row in observed)
    summary = {"context": context, "shard": args.shard, "total": len(observed),
               "refused_generation_transitions": sum(refused_generation_transition(row) for row in observed),
               "receipt_bytes": sum(p.stat().st_size for p in (root / "observations").glob("*.json")),
               "raw": dict(Counter(row["status"] for row in observed)),
               "ci": dict(Counter(row["ci_verdict"] for row in observed)),
               "not_qualified": [row["case"] for row in observed if row.get("qualification") == "NOT_QUALIFIED"],
               "accepted": accepted}
    (root / "summary.json").write_text(json.dumps(summary, indent=2), encoding="utf-8")
    return 0 if accepted else 1


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ("package", "output", "recipe", "gate", "worker", "verify-engine"):
        parser.add_argument("--" + name, type=Path, required=True)
    parser.add_argument("--source-sha256", required=True)
    parser.add_argument("--rust", choices=("1.81.0","1.100.0"), required=True)
    parser.add_argument("--recipe-name", choices=("openssl-full","openssl-gost"), required=True)
    parser.add_argument("--backend", choices=("file","db"), required=True)
    parser.add_argument("--interface", choices=("Legacy240","Standard32"), required=True)
    parser.add_argument("--shards", type=int, required=True)
    parser.add_argument("--shard", type=int, required=True)
    sys.exit(run(parser.parse_args()))

