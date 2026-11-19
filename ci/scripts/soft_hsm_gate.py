# SPDX-License-Identifier: Apache-2.0
"""Calibrate the native observer and qualify a SoftHSM configuration for a worker."""
import argparse
import json
from pathlib import Path
import sys
from types import SimpleNamespace


def prepare(args):
    root = args.output.resolve()
    root.mkdir(mode=0o700, exist_ok=False)
    tests = args.package.resolve(strict=True) / "tests"
    sys.path.insert(0, str(tests / "driver"))
    from qualify import ALGORITHMS, qualify
    from run import digest, prepare_observer, save

    recipe = json.loads(args.recipe.read_text())
    prefix = args.prefix.resolve(strict=True)
    images = [prefix / path for path in ("openssl/lib/libcrypto.so.3", "sqlite/lib/libsqlite3.so.0",
                                          "openssl/lib/ossl-modules/legacy.so")]
    if args.recipe_name == "openssl-gost":
        images.append(prefix / "gost/lib/engines/gost.so")
    images = [path.resolve(strict=True) for path in images]
    if any(not path.is_relative_to(prefix) for path in images):
        raise ValueError("dependency outside selected native prefix")
    dependencies = [{"path":str(path), "sha256":digest(path)} for path in images]
    executable = (prefix / "openssl/bin/openssl").resolve(strict=True)
    reference = {"executable":str(executable), "sha256":digest(executable),
                 "dependencies":[item for item in dependencies if item["path"] != str(images[1])]}
    catalogue = tests / "recipes" / (args.recipe_name + "-mechanisms.tsv")
    shared = dict(recipe=args.recipe.resolve(strict=True), worker=args.worker.resolve(strict=True),
                  worker_sha256=digest(args.worker), source_sha256=args.source_sha256,
                  catalogue=catalogue, catalogue_sha256=digest(catalogue), backend=args.backend)
    observer = prepare_observer(SimpleNamespace(**shared, root=root / "observer"))
    if observer["status"] != "PASS":
        raise ValueError("observer calibration failed")
    for step in (None, *ALGORITHMS):
        destination = root / (step or "metadata")
        report = qualify(SimpleNamespace(**shared, root=destination, algorithm=step, catalogue_only=False))
        if report["status"] != ("ALGORITHM_AVAILABLE" if step else "METADATA_VERIFIED"):
            raise ValueError("native qualification failed")
    save(root / "gate.json", dict(status="RECIPE_READY", rust=args.rust, backend=args.backend,
                                  recipe_sha256=digest(args.recipe), module_sha256=recipe["sha256"],
                                  worker_sha256=shared["worker_sha256"], algorithms=ALGORITHMS,
                                  dependencies=dependencies, public_reference=reference, pqc_reference=reference))


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ("output", "package", "worker", "recipe", "prefix"):
        parser.add_argument("--" + name, type=Path, required=True)
    parser.add_argument("--rust", choices=("1.81.0","1.100.0"), required=True)
    parser.add_argument("--backend", choices=("file","db"), required=True)
    parser.add_argument("--recipe-name", choices=("openssl-full","openssl-gost"), required=True)
    parser.add_argument("--source-sha256", required=True)
    prepare(parser.parse_args())

