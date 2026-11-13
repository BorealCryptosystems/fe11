# SPDX-License-Identifier: Apache-2.0
"""Public CI entry point. Each invocation owns a new, isolated working directory."""
import argparse
import os
from pathlib import Path
import platform
import re
import subprocess
import sys

# A clean checkout is an input invariant. Importing this driver's local modules
# must not create untracked __pycache__ files in that checkout.
sys.dont_write_bytecode = True
if sys.version_info < (3, 11):
    raise SystemExit("Python 3.11 or later is required")

from common import Job, diagnostic, digest, extract, save
import documentation
import native
import rust_toolchain
import soft_hsm

SYS_SHA = "957bfd2d5312f1669aaeccef199b5c52943dd516e5420ca262218d3e2afdd664"
SCENARIOS = ("discovery", "authentication", "invalid_pin", "digest_single", "digest_multipart",
             "rsa_sign_verify", "invalid_signature", "aes_gcm", "invalid_gcm_tag", "object_search")


def identity(job):
    checkout = subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=job.repository, text=True).strip()
    expected = os.environ.get("FE11_EXPECTED_COMMIT", checkout)
    if job.github and not os.environ.get("FE11_EXPECTED_COMMIT"):
        raise ValueError("expected checkout missing")
    if checkout != expected or not re.fullmatch(r"[a-f0-9]{40}", checkout):
        raise ValueError("checkout identity mismatch")
    if subprocess.check_output(["git", "status", "--porcelain", "--untracked-files=all"], cwd=job.repository).strip():
        raise ValueError("checkout must be clean")
    value = {"checkout": checkout, "event_sha": os.environ.get("GITHUB_SHA"),
             "base_sha": os.environ.get("FE11_BASE_COMMIT"), "event": os.environ.get("GITHUB_EVENT_NAME", "local"),
             "cargo_lock_sha256": digest(job.repository / "Cargo.lock"),
             "python": sys.version, "system": platform.system(), "release": platform.release(), "machine": platform.machine(),
             "runner_image": os.environ.get("ImageOS"), "runner_image_version": os.environ.get("ImageVersion")}
    if sys.platform.startswith("linux"):
        value["system_packages"] = subprocess.check_output(["dpkg-query", "-W", "-f=${Package}=${Version}\n",
            "build-essential", "autoconf", "automake", "libtool", "pkg-config", "libssl-dev", "perl", "python3", "git"], text=True).splitlines()
    save(job.reports / "identity.json", value)


def standalone_sys(job):
    archive = job.root / "fe11-sys.crate"
    job.fetch("https://static.crates.io/crates/fe11-sys/fe11-sys-0.1.0.crate", archive, SYS_SHA)
    extract(archive, job.root / "sys")
    source = job.root / "sys/fe11-sys-0.1.0"
    manifest = str(source / "Cargo.toml")
    for action in ("build", "doc"):
        job.cargo("standalone-sys-" + action, action, "--manifest-path", manifest, "--locked", "--release",
                  *(["--no-deps"] if action == "doc" else []))
    job.cargo("standalone-sys-doctest", "test", "--manifest-path", manifest, "--locked", "--release", "--doc")
    save(job.reports / "sys.json", {"version": "0.1.0", "crate_sha256": SYS_SHA,
        "cargo_lock_sha256": digest(source / "Cargo.lock"), "standalone": True})


def build(job):
    native.build(job)
    job.cargo("core-and-api", "build", "--locked", "--release", "-p", "fe11", "-p", "fe11-verify-engine-api")
    job.cargo("public-examples", "build", "--locked", "--release", "-p", "fe11", "--examples")
    job.cargo("verification-engine", "build", "--locked", "--release", "-p", "fe11-verify-engine")
    native.inspect(job)
    standalone_sys(job)
    documentation.check(job)


def softhsm(job):
    soft_hsm.build(job)
    run_suite(job)


def run_suite(job):
    """Execute and validate all ten scenarios against the prepared module."""
    tokens = job.root / "tokens"
    tokens.mkdir(mode=0o700)
    job.env["FE11_CI_ROOT"] = str(tokens)
    seen, lines = [], []
    try:
        job.cargo("public-softhsm", "test", "--locked", "--release", "-p", "fe11-ci-softhsm",
                  "--test", "integration", inherit=True)
    finally:
        # Never copy child paths, logs or arbitrary fields into a public artifact.
        result = tokens / "results.tsv"
        if result.is_file():
            with result.open("rb") as stream:
                raw = stream.read(4097)
            if len(raw) > 4096:
                raise ValueError("result size limit")
            lines = raw.decode("ascii").splitlines()
            if not lines or lines[0] != "scenario\tstatus\tcause\tnative_code\tcleanup\tcleanup_native_code\tchild_exit":
                raise ValueError("result header")
            seen = []
            pattern = r"[a-z_]+\t(PASS|FAIL)\t(none|native_error|local_error|assertion|setup|prerequisite|panic)\t(-|0x[0-9a-f]{1,16})\t(PASS|FAIL)\t(-|0x[0-9a-f]{1,16})\t(PASS|FAIL)"
            for line in lines[1:]:
                if not re.fullmatch(pattern, line) or line.split("\t")[0] not in SCENARIOS:
                    raise ValueError("invalid result row")
                seen.append(line.split("\t")[0])
            if len(seen) != len(set(seen)):
                raise ValueError("duplicate result")
            (job.reports / "results.tsv").write_bytes(raw)
    if seen != list(SCENARIOS) or any(line.split("\t")[1:] != ["PASS", "none", "-", "PASS", "-", "PASS"] for line in lines[1:]):
        raise ValueError("suite incomplete or failed")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("mode", choices=("build", "softhsm"))
    parser.add_argument("--rust", choices=("1.81.0", "1.100.0"), required=True)
    parser.add_argument("--root", type=Path, required=True)
    args = parser.parse_args()
    if not args.root.is_absolute():
        parser.error("root must be absolute")
    job = Job(Path(__file__).resolve().parents[2], args.root, args.rust)
    status = "FAIL"
    cause = "none"
    try:
        identity(job)
        native.msvc(job)
        rust_toolchain.install(job)
        (build if args.mode == "build" else softhsm)(job)
        status = "PASS"
        return 0
    except (Exception, KeyboardInterrupt) as error:
        # Local paths and raw traces stay private. Hosted jobs use public inputs
        # and disposable runner paths; report the exception type/message there,
        # bounded and prefixed like command diagnostics. No token PIN is passed
        # to this Python driver or included in its exceptions.
        import traceback
        (job.logs / "failure.txt").write_text(traceback.format_exc(), encoding="utf-8")
        cause = "cancelled" if isinstance(error, KeyboardInterrupt) else (
            "timeout" if isinstance(error, (TimeoutError, subprocess.TimeoutExpired)) else "execution")
        if job.github:
            diagnostic(type(error).__name__ + ": " + str(error))
        print("CI job failed; inspect the failing step's console diagnostic." if job.github else
              "CI job failed; inspect private-logs locally.", file=sys.stderr)
        return 1
    finally:
        save(job.reports / "summary.json", {"mode": args.mode, "rust": args.rust, "status": status, "cause": cause})


if __name__ == "__main__":
    sys.exit(main())
