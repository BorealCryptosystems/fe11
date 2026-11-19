# SPDX-License-Identifier: Apache-2.0
"""Prepare one public native shard and reconcile all shards against the source catalogue."""
import argparse
from collections import Counter
import json
import os
from pathlib import Path
import sys

sys.dont_write_bytecode = True
from common import digest, extract, save
from candidate_inputs import LIBRARY, SUITE
from soft_hsm_campaign import run
from soft_hsm_gate import prepare
from native_verdict import accepted_observation
from types import SimpleNamespace

RUST = ("1.81.0", "1.100.0")
STORES = ("file", "db")
INTERFACES = ("Legacy240", "Standard32")
SHARDS = 32
COMMIT = "7380895665c3094a6f57640085bee97dcfeb1496"


def partitions():
    return [dict(rust=rust, backend=store, interface=interface, shard=n)
            for rust in RUST for store in STORES for interface in INTERFACES for n in range(SHARDS)]


def group(row):
    return f"{row['rust']}-{row['backend']}-{row['interface']}-{row['shard']}"


def catalogue_for(package):
    sys.path.insert(0, str(package / "tests/driver"))
    from native_catalogue import catalogue
    return catalogue()


def context(row, recipe="openssl-full"):
    return f"linux.{row['rust']}.{recipe}.{row['backend']}.{row['interface']}"


def comparison_runtime(provenance, prefix):
    reference = json.loads(Path(__file__).with_name("native-runtime-reference.json").read_text())
    for key in ("recipe", "upstream_commit", "inputs", "recipe_driver", "recipe_support"):
        if provenance[key] != reference[key]:
            raise ValueError("runtime differs from the documented source recipe: " + key)
    images, baseline = provenance["images"], reference["images"]
    if set(images) != set(baseline) or images["openssl-full.cnf"] != baseline["openssl-full.cnf"]:
        raise ValueError("runtime image inventory or provider configuration changed")
    module = "softhsm-full/lib/softhsm/libsofthsm2.so"
    return dict(module=images[module], reference_module=baseline[module],
                dependencies={str((prefix / path).resolve(strict=True)): (images[path], name, baseline[path])
                              for path, name in reference["dependency_names"].items()},
                receipt=dict(recipe=provenance, reference_images=baseline,
                             changed_images=sorted(path for path in images if images[path] != baseline[path])))


def install(row, root):
    kit = root / "native-kit"
    identity = json.loads((kit / "identity.json").read_text())
    if identity.get("library_sha256") != LIBRARY or identity.get("suite.crate") != SUITE:
        raise ValueError("Native worker built from a different release candidate")
    if identity["rust"] != row["rust"] or any(identity[key] != digest(kit / key)
                                               for key in ("worker", "engine.so", "suite.crate")):
        raise ValueError("inconsistent native kit")
    extract(kit / "suite.crate", root / "suite")
    package, = (root / "suite").iterdir()
    package = package.resolve(strict=True)
    sys.path.insert(0, str(package / "tests/driver"))
    from fixture_archive import process
    process("unpack")
    prefix = root / "fe11-native-prefix"
    extract(root / "native-runtime/images.tar.gz", prefix)
    from recipes import OPENSSL_SHA, SOFTHSM_SHA, SQLITE_SHA3
    provenance = json.loads((root / "native-runtime/provenance.json").read_text())
    expected_images = {"openssl-full.cnf", "openssl/bin/openssl", "openssl/lib/libssl.so.3",
                       "openssl/lib/libcrypto.so.3", "openssl/lib/ossl-modules/legacy.so",
                       "sqlite/lib/libsqlite3.so.0", "softhsm-full/lib/softhsm/libsofthsm2.so"}
    if {p.relative_to(prefix).as_posix() for p in prefix.rglob("*") if p.is_file()} != expected_images:
        raise ValueError("unexpected file in native runtime search paths")
    if (provenance["upstream_commit"] != COMMIT or provenance["recipe"] != "openssl-full"
            or provenance["inputs"] != {"openssl.tar.gz": OPENSSL_SHA, "sqlite.tar.gz": SQLITE_SHA3,
                                         "softhsm.tar.gz": SOFTHSM_SHA}
            or provenance["recipe_driver"] != digest(package / "tests/driver/recipes.py")
            or provenance["recipe_support"] != digest(package / "tests/driver/recipe_support.py")
            or provenance["images"] != {name: digest(prefix / name) for name in expected_images}):
        raise ValueError("native runtime provenance differs from the package recipe")
    for executable in (kit / "worker", prefix / "openssl/bin/openssl"):
        executable.chmod(0o700)
    module = prefix / "softhsm-full/lib/softhsm/libsofthsm2.so"
    recipe = root / "recipe.json"
    save(recipe, dict(module=str(module), sha256=digest(module), environment={
        "OPENSSL_CONF": str(prefix / "openssl-full.cnf"), "OPENSSL_MODULES": str(prefix / "openssl/lib/ossl-modules"),
        "OPENSSL_ENGINES": str(prefix / "openssl/lib/engines-3"),
        "LD_LIBRARY_PATH": f"{prefix}/openssl/lib:{prefix}/sqlite/lib",
        "PKG_CONFIG_PATH": f"{prefix}/openssl/lib/pkgconfig:{prefix}/sqlite/lib/pkgconfig"}))
    opts = dict(rust=row["rust"], backend=row["backend"], package=package, prefix=prefix, recipe=recipe,
                worker=kit / "worker", source_sha256=identity["suite.crate"], recipe_name="openssl-full")
    runtime = comparison_runtime(provenance, prefix)
    for image in runtime["receipt"]["changed_images"]:
        print(f"Runtime image differs from the reference: {image} {provenance['images'][image]}", flush=True)
    return opts, runtime


def shard(row, root):
    opts, runtime = install(row, root)
    kit = root / "native-kit"
    gate = root / "native-gate"
    prepare(SimpleNamespace(**opts, output=gate))
    return run(SimpleNamespace(**opts, interface=row["interface"], shards=SHARDS, shard=row["shard"],
                               runtime=runtime,
                               gate=gate / "gate.json", verify_engine=kit / "engine.so", output=root / "out"))


def reconcile(root, package):
    cases = catalogue_for(package)
    counts = Counter()
    diagnostics = []
    workers = {}
    runtime = None
    exercised = 0
    unavailable = Counter(c for _, axes in cases.values() for c in axes if ".openssl-gost." in c)
    groups = partitions()
    inputs = {p.name for p in root.iterdir() if p.is_dir()}
    if inputs != {"native-result-" + group(row) for row in groups}:
        diagnostics.append("missing or unexpected shard directories")
    for row in groups:
        name = group(row)
        folder = root / ("native-result-" + name)
        expected = sorted(key for key, (_, axes) in cases.items() if context(row) in axes)[row["shard"]::SHARDS]
        try:
            plan = json.loads((folder / "plan.json").read_text())
            records = [json.loads(line) for line in (folder / "results.jsonl").read_text().splitlines()]
            summary = json.loads((folder / "summary.json").read_text())
            if (plan["expected"] != expected or plan["context"] != context(row) or plan["shards"] != SHARDS
                    or plan["shard"] != row["shard"] or [r["case"] for r in records] != expected):
                raise ValueError("case inventory mismatch")
            identity = (plan["worker_sha256"], plan["source_sha256"])
            if plan["source_sha256"] != SUITE:
                raise ValueError("Unexpected test package in shard results")
            if workers.setdefault(row["rust"], identity) != identity:
                raise ValueError("different worker or package used with the same compiler")
            observed_runtime = plan["runtime"]
            if runtime is None:
                runtime = observed_runtime
            if (observed_runtime != runtime or not isinstance(runtime, dict)
                    or set(runtime) != {"recipe", "reference_images", "changed_images"}):
                raise ValueError("shards disagree on the verified native runtime")
            images = runtime["recipe"]["images"]
            reference = runtime["reference_images"]
            if (set(images) != set(reference) or runtime["changed_images"] !=
                    sorted(key for key in images if images[key] != reference[key])):
                raise ValueError("image difference report disagrees with the recorded hashes")
            raw = Counter(r["status"] for r in records)
            outcomes = Counter(r["ci_verdict"] for r in records)
            if (summary["total"] != len(expected) or summary["raw"] != raw or summary["ci"] != outcomes
                    or summary["context"] != context(row) or summary["shard"] != row["shard"]):
                raise ValueError("shard totals disagree")
            counts.update((r["status"], r["ci_verdict"]) for r in records)
            exercised += sum(r.get("body_started") is True for r in records)
            if not (summary["accepted"] is True and all(accepted_observation(r) for r in records)):
                diagnostics.append(name + ": unaccepted observations")
        except (KeyError, ValueError, OSError, TypeError) as error:
            diagnostics.append(name + ": " + type(error).__name__)
    result = dict(status="FAIL" if diagnostics else "PASS", observations=sum(counts.values()),
                  bodies_exercised=exercised, runtime=runtime,
                  results=[dict(raw=k[0], ci=k[1], count=v) for k, v in sorted(counts.items())],
                  unavailable=dict(upstream=COMMIT, configuration="openssl-gost",
                                   reason="OSSLGOST::signInit declaration and definition differ",
                                   contexts=dict(unavailable)), findings=diagnostics)
    save(root / "acceptance.json", result)
    return int(bool(diagnostics))


if __name__ == "__main__":
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("command", choices=("matrix", "shard", "reconcile"))
    p.add_argument("--root", type=Path)
    p.add_argument("--package", type=Path)
    p.add_argument("--row", type=json.loads)
    args = p.parse_args()
    if args.command == "matrix":
        with Path(os.environ["GITHUB_OUTPUT"]).open("a") as out:
            print("matrix=" + json.dumps({"include": partitions()}, separators=(",", ":")), file=out)
    elif args.command == "shard":
        if args.row not in partitions():
            p.error("unknown shard")
        sys.exit(shard(args.row, args.root.resolve(strict=True)))
    else:
        sys.exit(reconcile(args.root, args.package.resolve(strict=True)))
