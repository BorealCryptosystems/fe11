# SPDX-License-Identifier: Apache-2.0
"""Confined build operations; public reports are separate from raw build logs."""
from pathlib import Path
import hashlib
import json
import os
import signal
import subprocess
import tarfile
import time
import urllib.request


def digest(path):
    value = hashlib.sha256()
    with Path(path).open("rb") as source:
        for chunk in iter(lambda: source.read(1024 * 1024), b""):
            value.update(chunk)
    return value.hexdigest()


def save(path, data):
    Path(path).write_text(json.dumps(data, indent=2) + "\n", encoding="utf-8")


def extract(archive, destination):
    """Only regular files/directories, with an explicit containment check."""
    destination = Path(destination).resolve()
    destination.mkdir(parents=True, exist_ok=False)
    with tarfile.open(archive) as source:
        for member in source:
            path = (destination / member.name).resolve()
            if not path.is_relative_to(destination) or not (member.isfile() or member.isdir()):
                raise ValueError("unsupported archive entry")
            if member.isdir():
                path.mkdir(parents=True, exist_ok=True)
            else:
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_bytes(source.extractfile(member).read())
                if os.name != "nt":
                    path.chmod(member.mode & 0o777)


class Job:
    def __init__(self, repository, root, rust):
        self.repository = Path(repository).resolve()
        self.root = Path(root).resolve()
        if self.root.is_relative_to(self.repository) or self.repository.is_relative_to(self.root):
            raise ValueError("job root and checkout must be disjoint")
        self.root.mkdir(mode=0o700, parents=True, exist_ok=False)
        (self.root / "owner.txt").write_text("fe11-public-ci\n", encoding="ascii")
        self.reports = self.root / "reports"
        self.reports.mkdir()
        self.logs = self.root / "private-logs"
        self.logs.mkdir()
        self.start = time.monotonic()
        self.github = os.environ.get("GITHUB_ACTIONS") == "true"
        self.commands = []
        self.rust = rust
        # Windows environment names are case-insensitive. Do not pass competing
        # Path/PATH entries to child tools that select their compiler by PATH.
        self.env = {k.upper(): v for k, v in os.environ.items()} if os.name == "nt" else dict(os.environ)
        for name in list(self.env):
            if name.upper().startswith(("CARGO_", "RUST", "OPENSSL_")):
                del self.env[name]
        for directory in ("tmp", "cargo", "target"):
            (self.root / directory).mkdir()
        self.env.update(CARGO_HOME=str(self.root / "cargo"), CARGO_TARGET_DIR=str(self.root / "target"),
                        CARGO_INCREMENTAL="0", RUSTFLAGS="-Dwarnings", RUSTDOCFLAGS="-Dwarnings",
                        TMP=str(self.root / "tmp"), TEMP=str(self.root / "tmp"), TMPDIR=str(self.root / "tmp"))
        self.toolchain = None
        if hasattr(signal, "SIGTERM"):
            signal.signal(signal.SIGTERM, self.interrupted)

    @staticmethod
    def interrupted(_number, _frame):
        raise KeyboardInterrupt

    def remaining(self):
        remaining = 3600 - (time.monotonic() - self.start)
        if remaining <= 0:
            raise TimeoutError("job time limit")
        return remaining

    def fetch(self, url, output, expected):
        with urllib.request.urlopen(url, timeout=3600 if self.github else self.remaining()) as source:
            with Path(output).open("xb") as target:
                while chunk := source.read(1024 * 1024):
                    target.write(chunk)
        if digest(output) != expected:
            raise ValueError("download checksum mismatch")

    def run(self, label, command, cwd=None, inherit=False):
        """One process group per command, killed and reaped on cancellation."""
        output = self.logs / (f"{len(self.commands):02}-" + label + ".log")
        options = {"start_new_session": True} if os.name != "nt" else {"creationflags": subprocess.CREATE_NEW_PROCESS_GROUP}
        with output.open("wb") as log:
            process = subprocess.Popen([str(x) for x in command], cwd=cwd or self.repository, env=self.env,
                                       stdin=subprocess.DEVNULL, stdout=None if inherit else log,
                                       stderr=None if inherit else subprocess.STDOUT, **options)
            try:
                code = process.wait(timeout=None if self.github else self.remaining())
            except BaseException as error:
                self.stop(process)
                process.wait()
                self.commands.append({"step": label, "exit_code": process.returncode,
                    "interruption": "timeout" if isinstance(error, (TimeoutError, subprocess.TimeoutExpired)) else "cancelled"})
                save(self.reports / "commands.json", self.commands)
                raise
            if code:
                self.stop(process)
        self.commands.append({"step": label, "exit_code": code})
        save(self.reports / "commands.json", self.commands)
        print(f"{label}: {'PASS' if code == 0 else 'FAIL'}", flush=True)
        if code:
            raise RuntimeError(f"{label} failed; inspect the local private build log")
        return output

    @staticmethod
    def stop(process):
        if os.name == "nt":
            subprocess.run(["taskkill", "/PID", str(process.pid), "/T", "/F"],
                           stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, check=False)
        else:
            try:
                os.killpg(process.pid, signal.SIGKILL)
            except ProcessLookupError:
                pass

    def cargo(self, label, *arguments, inherit=False):
        suffix = ".exe" if os.name == "nt" else ""
        return self.run(label, [self.toolchain / "bin" / ("cargo" + suffix), *arguments], inherit=inherit)
