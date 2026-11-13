# SPDX-License-Identifier: Apache-2.0
"""Install exact official Rust components without altering the host toolchain."""
import hashlib
import os
from pathlib import Path, PurePosixPath
import subprocess
import tarfile
import tomllib
import urllib.request
from common import digest, save


# Release manifest identities; component hashes are read only after this check.
MANIFEST_SHA256 = {
    "1.81.0": "5596679723faf7e63772bacb1d0c898abaa51eb4ed193b328929d907c8c4bd5a",
    "1.100.0": "3051e859570f64a8c5acb9d09e87425db52c7d97287c67e8f6d57d7d34ef9258",
}


def install(job):
    target = "x86_64-pc-windows-msvc" if os.name == "nt" else "x86_64-unknown-linux-gnu"
    url = f"https://static.rust-lang.org/dist/channel-rust-{job.rust}.toml"
    timeout = 3600 if job.github else job.remaining()
    with urllib.request.urlopen(url, timeout=timeout) as stream:
        raw = stream.read()
    expected = MANIFEST_SHA256[job.rust]
    if hashlib.sha256(raw).hexdigest() != expected:
        raise ValueError("Rust manifest checksum mismatch")
    manifest = tomllib.loads(raw.decode("utf-8"))
    prefix = job.root / "rust"
    prefix.mkdir()
    receipts = []
    for name in ("rustc", "cargo", "rust-std"):
        package = manifest["pkg"][name]["target"][target]
        if not package["available"]:
            raise ValueError("Rust component unavailable")
        archive = job.root / (name + ".tar.xz")
        job.fetch(package["xz_url"], archive, package["xz_hash"])
        with tarfile.open(archive) as source:
            for member in source:
                parts = PurePosixPath(member.name).parts
                if len(parts) < 3 or parts[1] not in (name, name + "-" + target):
                    continue
                if parts[-1] == "manifest.in":
                    continue
                destination = (prefix / Path(*parts[2:])).resolve()
                if not destination.is_relative_to(prefix) or not (member.isdir() or member.isfile()):
                    raise ValueError("invalid Rust archive entry")
                if member.isdir():
                    destination.mkdir(parents=True, exist_ok=True)
                else:
                    destination.parent.mkdir(parents=True, exist_ok=True)
                    destination.write_bytes(source.extractfile(member).read())
                    if os.name != "nt":
                        destination.chmod(member.mode & 0o777)
        receipts.append({"component": name, "url": package["xz_url"], "sha256": package["xz_hash"]})
        archive.unlink()
    suffix = ".exe" if os.name == "nt" else ""
    job.toolchain = prefix
    job.env.update(PATH=str(prefix / "bin") + os.pathsep + job.env["PATH"],
                   RUSTC=str(prefix / "bin" / ("rustc" + suffix)),
                   RUSTDOC=str(prefix / "bin" / ("rustdoc" + suffix)))
    versions = {}
    for name in ("rustc", "cargo", "rustdoc"):
        binary = prefix / "bin" / (name + suffix)
        text = subprocess.check_output([str(binary), "-Vv" if name == "rustc" else "--version"], env=job.env, text=True)
        versions[name] = {"version": text.strip(), "sha256": digest(binary)}
    if "release: " + job.rust not in versions["rustc"]["version"]:
        raise ValueError("wrong compiler version")
    save(job.reports / "toolchain.json", {"manifest_url": url, "manifest_sha256": expected,
                                          "target": target, "components": receipts, "tools": versions})
