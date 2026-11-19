# SPDX-License-Identifier: Apache-2.0
"""Prepare an isolated token and qualify native call observation on real SoftHSM."""
from pathlib import Path
import argparse
import hashlib
import json
import os
import re
import secrets
import shlex
import shutil
from process import execute, frames, erase
from report_validation import read_records, verify_worker, trace_matches

HERE = Path(__file__).resolve().parent
CONTROL_SEQUENCE = ["C_DigestInit", "C_DigestUpdate", "C_DigestFinal", "C_DigestInit", "C_Digest"]


def digest(path):
    result = hashlib.sha256()
    with Path(path).open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            result.update(block)
    return result.hexdigest()


def save(path, data):
    descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(descriptor, "w", encoding="utf-8") as output:
        json.dump(data, output, indent=2)
        output.write("\n")


def environment(recipe, config, root):
    env = {key: value for key, value in os.environ.items()
           if not key.startswith(("FE11_", "SOFTHSM", "OPENSSL_", "LD_", "PKG_CONFIG_", "GDB", "DEBUGINFOD"))}
    allowed = {"LD_LIBRARY_PATH", "OPENSSL_CONF", "OPENSSL_MODULES", "OPENSSL_ENGINES", "PKG_CONFIG_PATH"}
    if set(recipe["environment"]) != allowed:
        raise ValueError("unexpected recipe environment")
    env.update(recipe["environment"])
    env.update(SOFTHSM2_CONF=str(config), TMPDIR=str(root), TMP=str(root), TEMP=str(root),
               DEBUGINFOD_URLS="", RUST_BACKTRACE="0", PYTHONDONTWRITEBYTECODE="1")
    return env


def prepare_observer(args):
    if os.name != "posix" or "microsoft" in os.uname().release.lower():
        raise ValueError("use the selected Linux execution host")
    root = args.root.resolve()
    if any(character in str(root) for character in "\r\n#="):
        raise ValueError("job path contains a SoftHSM configuration delimiter")
    if args.root.is_symlink():
        raise ValueError("job root must not be a symbolic link")
    root.mkdir(mode=0o700, parents=False, exist_ok=False)
    recipe = json.loads(args.recipe.read_text())
    module = Path(recipe["module"]).resolve(strict=True)
    if digest(module) != recipe["sha256"] or digest(args.worker) != args.worker_sha256:
        raise ValueError("worker or module identity mismatch")
    recipe_digest = digest(args.recipe)
    for value in (args.source_sha256, args.worker_sha256, recipe["sha256"]):
        if not re.fullmatch(r"[0-9a-f]{64}", value):
            raise ValueError("invalid provenance digest")
    token_directory = root / "tokens"
    token_directory.mkdir(mode=0o700)
    config = root / "softhsm.conf"
    config.write_text("directories.tokendir = " + str(token_directory) + "\n"
                      "objectstore.backend = " + args.backend + "\nlog.level = ERROR\n")
    env = environment(recipe, config, root)
    label = "fe11-" + secrets.token_hex(8)
    officer = bytearray(secrets.token_bytes(16))
    user = bytearray(secrets.token_bytes(16))
    # Mutable buffers are cleared below; no guarantee is made about interpreter
    # allocator or OS pipe copies. All credentials are ephemeral to this token.
    wire = frames(officer, user)
    identities = dict(source_sha256=args.source_sha256, recipe_sha256=recipe_digest,
                      module_sha256=recipe["sha256"])
    result = dict(scope="observer_preparation", worker_sha256=args.worker_sha256,
                  source_sha256=args.source_sha256, module_sha256=recipe["sha256"],
                  recipe_sha256=recipe_digest, backend=args.backend, fe11_cases_credited=0)
    def command(mode, case):
        return [str(args.worker.resolve()), mode, case, args.source_sha256, recipe_digest,
                str(module), recipe["sha256"], "Legacy240", label, str(config)]
    try:
        provision = execute(command("provision", "observer-provision"), env, root / "provision", wire)
        result["provision_process"] = provision
        verify_worker(root / "provision/stdout.raw", provision,
                      dict(identities, case="observer-provision"), "preparation_terminal")
        control = root / "control"
        trace = control / "trace.jsonl"
        observer_config = root / "observer.json"
        save(observer_config, dict(module=str(module), module_sha256=recipe["sha256"],
                                   functions=list(dict.fromkeys(CONTROL_SEQUENCE)), output=str(trace)))
        gdb = shutil.which("gdb", path=env["PATH"])
        if gdb is None:
            raise ValueError("GDB prerequisite missing")
        worker_report = control / "worker.jsonl"
        worker = command("observer-control", "observer-direct-digest")
        # GDB's inferior stdout is separated from debugger console diagnostics.
        # Every token is shell-quoted; no credential appears in this command.
        for value in worker + [str(worker_report)]:
            if "\n" in value or "\r" in value:
                raise ValueError("line delimiter in GDB argument")
        inferior_args = " ".join(shlex.quote(value) for value in worker[1:])
        inferior_args += " > " + shlex.quote(str(worker_report))
        observed_env = dict(env, FE11_OBSERVER_CONFIG=str(observer_config))
        invocation = [gdb, "-nx", "-nh", "-batch", "-iex", "set auto-load no",
                      "-iex", "set debuginfod enabled off", "-iex", "set print frame-arguments none",
                      "-iex", "set confirm off", "-iex", "set disable-randomization off",
                      "-ex", "set args " + inferior_args,
                      "-ex", "starti", "-x", str(HERE / "native_observer.py"), "-ex", "continue", worker[0]]
        process = execute(invocation, observed_env, control, wire)
        result["observer_process"] = process
        verify_worker(worker_report, process, dict(identities, case="observer-direct-digest"), "preparation_terminal")
        records = read_records(trace)
        observer_sha = digest(HERE / "native_observer.py")
        if not trace_matches(records, CONTROL_SEQUENCE, recipe["sha256"], observer_sha):
            raise ValueError("native observer sequence does not match the direct control")
        changed = list(records)
        del changed[next(index for index, row in enumerate(changed) if row.get("kind") == "entry")]
        if trace_matches(changed, CONTROL_SEQUENCE, recipe["sha256"], observer_sha):
            raise ValueError("observer comparison accepted an incomplete trace")
        result.update(status="PASS", observer_script_sha256=digest(HERE / "native_observer.py"),
                      positive_sequence=CONTROL_SEQUENCE, omitted_event_rejected=True,
                      coverage="Observer calibration only; recipe algorithm qualification remains separate")
    except Exception as error:
        # Fixed exception class only. Details remain in private raw streams and
        # source-specific investigation; no arbitrary provider text is published.
        result.update(status="PREREQUISITE_MISSING", failure_category=type(error).__name__)
        raise
    finally:
        erase(wire)
        erase(officer)
        erase(user)
        save(root / "result.json", result)
    return result


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--prepare-observer", action="store_true", required=True)
    parser.add_argument("--root", type=Path, required=True)
    parser.add_argument("--recipe", type=Path, required=True)
    parser.add_argument("--worker", type=Path, required=True)
    parser.add_argument("--worker-sha256", required=True)
    parser.add_argument("--source-sha256", required=True)
    parser.add_argument("--backend", choices=("file", "db"), required=True)
    result = prepare_observer(parser.parse_args())
    print(json.dumps({key: result[key] for key in ("scope", "status", "fe11_cases_credited")}))


if __name__ == "__main__":
    main()
