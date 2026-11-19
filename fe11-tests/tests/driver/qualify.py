# SPDX-License-Identifier: Apache-2.0
"""Qualify recipe metadata or one explicitly selected real algorithm witness."""
from pathlib import Path
import argparse
import json
import os
import re
import secrets
from process import execute, frames, erase
from run import digest, environment, save, verify_worker

ALGORITHMS = ("rsa", "ecdsa", "ed25519", "ed448", "dsa", "dh", "ecdh", "aes", "des", "des2", "des3", "hmac", "cmac") + tuple("digest-" + name for name in ("md5", "sha-1", "sha224", "sha256", "sha384", "sha512", "sha3-224", "sha3-256", "sha3-384", "sha3-512")) + tuple(
    f"{family}-{parameter}" for family, count in (("ml-dsa", 3), ("slh-dsa", 12), ("ml-kem", 3))
    for parameter in range(1, count + 1))


def qualify(args):
    if os.name != "posix" or "microsoft" in os.uname().release.lower():
        raise ValueError("use the selected Linux execution host")
    root = args.root.resolve()
    if args.root.is_symlink() or any(character in str(root) for character in "\r\n#="):
        raise ValueError("invalid isolated job path")
    root.mkdir(mode=0o700, parents=False, exist_ok=False)
    recipe = json.loads(args.recipe.read_text())
    module = Path(recipe["module"]).resolve(strict=True)
    if digest(module) != recipe["sha256"] or digest(args.worker) != args.worker_sha256:
        raise ValueError("worker or module identity mismatch")
    if digest(args.catalogue) != args.catalogue_sha256:
        raise ValueError("recipe catalogue identity mismatch")
    for value in (args.source_sha256, args.worker_sha256, recipe["sha256"], args.catalogue_sha256):
        if not re.fullmatch(r"[0-9a-f]{64}", value):
            raise ValueError("invalid provenance digest")
    recipe_digest = digest(args.recipe)
    token_directory = root / "tokens"
    token_directory.mkdir(mode=0o700)
    config = root / "softhsm.conf"
    config.write_text("directories.tokendir = " + str(token_directory) + "\n"
                      "objectstore.backend = " + args.backend + "\nlog.level = ERROR\n")
    env = environment(recipe, config, root)
    label = "fe11-" + secrets.token_hex(8)
    officer = bytearray(secrets.token_bytes(16))
    user = bytearray(secrets.token_bytes(16))
    wire = frames(officer, user)
    identity = dict(source_sha256=args.source_sha256, recipe_sha256=recipe_digest,
                    module_sha256=recipe["sha256"])
    result = dict(scope="algorithm_preparation" if args.algorithm else "recipe_metadata", worker_sha256=args.worker_sha256,
                  catalogue_sha256=args.catalogue_sha256, backend=args.backend,
                  fe11_cases_credited=0, **identity)
    observations = {}
    try:
        # Discovery does not need initialization; catalogue inspection requires
        # a unique initialized token. Each operation owns a distinct process.
        if args.algorithm:
            modes = ("provision", "algorithm-probe")
        else:
            modes = ("provision", "catalog-probe") if args.catalogue_only else ("discovery-probe", "provision", "catalog-probe")
        for mode in modes:
            case = args.algorithm if mode == "algorithm-probe" else mode
            command = [str(args.worker.resolve()), mode, case, args.source_sha256,
                       recipe_digest, str(module), recipe["sha256"], "Legacy240", label,
                       str(args.catalogue.resolve())]
            process = execute(command, env, root / mode, wire)
            observations[mode] = process
            records = verify_worker(root / mode / "stdout.raw", process,
                                    dict(identity, case=case), "preparation_terminal")
            # Only closed-schema records can enter the public preparation report.
            observations[mode]["records"] = records
        if args.algorithm:
            result.update(status="ALGORITHM_AVAILABLE", algorithm=args.algorithm,
                          coverage="One native generation/use witness; no Fe11 case or published-vector credit")
        else:
            result.update(status="CATALOGUE_VERIFIED" if args.catalogue_only else "METADATA_VERIFIED",
                          discovery="NOT_EXECUTED" if args.catalogue_only else "VERIFIED",
                          algorithm_qualification="NOT_EXECUTED")
    except Exception as error:
        result.update(status="PREPARATION_FAILED", failure_category=type(error).__name__)
        raise
    finally:
        erase(wire)
        erase(officer)
        erase(user)
        result["processes"] = observations
        save(root / "result.json", result)
    return result


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", type=Path, required=True)
    parser.add_argument("--recipe", type=Path, required=True)
    parser.add_argument("--worker", type=Path, required=True)
    parser.add_argument("--worker-sha256", required=True)
    parser.add_argument("--source-sha256", required=True)
    parser.add_argument("--catalogue", type=Path, required=True)
    parser.add_argument("--catalogue-sha256", required=True)
    parser.add_argument("--backend", choices=("file", "db"), required=True)
    mode = parser.add_mutually_exclusive_group()
    mode.add_argument("--catalogue-only", action="store_true",
                        help="Inspect mechanisms only; do not repeat or credit interface discovery")
    mode.add_argument("--algorithm", choices=ALGORITHMS,
                      help="Run one native algorithm witness, separately from metadata qualification")
    result = qualify(parser.parse_args())
    print(json.dumps({key: result[key] for key in ("scope", "status", "fe11_cases_credited")}))


if __name__ == "__main__":
    main()
