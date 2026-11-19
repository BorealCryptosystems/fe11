# SPDX-License-Identifier: Apache-2.0
"""Confined native builds with immutable inputs and per-command evidence."""
from pathlib import Path
import hashlib
import json
import os
import signal
import subprocess
import tarfile


def digest(path, algorithm="sha256"):
    value = hashlib.new(algorithm)
    with Path(path).open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            value.update(block)
    return value.hexdigest()


def extract(archive, destination, strip_root=True):
    """Accept regular files/directories only, without archive-controlled links."""
    destination = Path(destination).resolve()
    destination.mkdir(parents=True, exist_ok=False)
    top = None
    with tarfile.open(archive) as stream:
        for member in stream:
            parts = Path(member.name).parts
            if not parts or Path(member.name).is_absolute() or ".." in parts:
                raise ValueError("invalid archive path")
            if strip_root:
                if top is None:
                    top = parts[0]
                if top != parts[0]:
                    raise ValueError("archive has multiple roots")
                parts = parts[1:]
            target = destination.joinpath(*parts).resolve()
            if not target.is_relative_to(destination):
                raise ValueError("archive escapes destination")
            if member.isdir():
                target.mkdir(parents=True, exist_ok=True)
            elif member.isfile() and parts:
                target.parent.mkdir(parents=True, exist_ok=True)
                with stream.extractfile(member) as source, target.open("xb") as output:
                    for block in iter(lambda: source.read(1024 * 1024), b""):
                        output.write(block)
                target.chmod(member.mode & 0o777)
            else:
                raise ValueError("unsupported archive entry")


class Build:
    """One Linux build directory; never install into the host or mutate its environment."""
    def __init__(self, root, inputs):
        if os.name != "posix" or "microsoft" in os.uname().release.lower():
            raise ValueError("native recipe requires the selected Linux execution host")
        self.root = Path(root).resolve()
        self.inputs = Path(inputs).resolve()
        if self.root.is_relative_to(self.inputs) or self.inputs.is_relative_to(self.root):
            raise ValueError("input archives and build outputs must be disjoint")
        self.root.mkdir(parents=True, exist_ok=False)
        for name in ("logs", "tmp", "sources", "prefix"):
            (self.root / name).mkdir()
        self.env = {k: v for k, v in os.environ.items()
                    if not k.startswith(("OPENSSL_", "LD_", "PKG_CONFIG_", "CARGO_", "RUST"))}
        self.env.update(TMPDIR=str(self.root / "tmp"), TMP=str(self.root / "tmp"),
                        TEMP=str(self.root / "tmp"))
        self.commands = []

    def input(self, name, expected, algorithm="sha256"):
        archive = self.inputs / name
        if archive.is_symlink() or not archive.is_file() or digest(archive, algorithm) != expected:
            raise ValueError("native input identity mismatch: " + name)
        return archive

    def run(self, name, command, cwd=None, env=None):
        log = self.root / "logs" / (f"{len(self.commands):02d}-" + name + ".txt")
        with log.open("xb") as output:
            process = subprocess.Popen([str(arg) for arg in command], cwd=cwd or self.root,
                                       env=env or self.env, stdin=subprocess.DEVNULL,
                                       stdout=output, stderr=subprocess.STDOUT, start_new_session=True)
            try:
                code = process.wait(timeout=3600)
            except BaseException:
                try:
                    os.killpg(process.pid, signal.SIGKILL)
                except ProcessLookupError:
                    pass
                process.wait()
                self.commands.append(dict(name=name, command=list(map(str, command)),
                                          status="INTERRUPTED", exit_code=process.returncode))
                self.save_commands()
                raise
        self.commands.append(dict(name=name, command=list(map(str, command)), exit_code=code))
        self.save_commands()
        print(name + (": OK" if code == 0 else ": FAILED"), flush=True)
        if code:
            raise RuntimeError("native build failed; inspect " + str(log))
        return log

    def save_commands(self):
        (self.root / "commands.json").write_text(json.dumps(self.commands, indent=2) + "\n")
