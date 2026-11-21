# SPDX-License-Identifier: Apache-2.0
"""Validate the exact Cargo archives selected for this hosted acceptance run."""
import hashlib
import json
from pathlib import Path, PurePosixPath
import tarfile
import tomllib

ROOT = Path(__file__).resolve().parents[2]
ARCHIVES = ROOT / "ci/candidate"
SUITE = "8b397a04a9108965fcac29c03583deccaef9c45f0e6013130e43cfd7f5687165"
LIBRARY = "488a427412968b4cf5881396d77d58e5538301629492761a0ef1bc875adb8da4"
EXPECTED = {"fe11": LIBRARY, "fe11-tests": SUITE}


def check():
    results = {}
    for name, expected in EXPECTED.items():
        path = ARCHIVES / f"{name}-0.1.1.crate"
        if hashlib.sha256(path.read_bytes()).hexdigest() != expected:
            raise ValueError(f"Unexpected candidate archive: {name}")
        source = ROOT / ("library" if name == "fe11" else name)
        files = set()
        with tarfile.open(path) as archive:
            if name == "fe11-tests":
                lock = tomllib.loads(archive.extractfile(f"{path.stem}/Cargo.lock").read().decode("utf-8"))
                selected = [p for p in lock["package"] if p["name"] == "fe11"]
                if (len(selected) != 1 or selected[0].get("version") != "0.1.1"
                        or selected[0].get("checksum") != LIBRARY
                        or selected[0].get("source") != "registry+https://github.com/rust-lang/crates.io-index"):
                    raise ValueError("Packaged test lockfile selects a different Fe11 archive")
            for entry in archive:
                relative = PurePosixPath(entry.name).relative_to(path.stem)
                if (not entry.isfile() or ".." in relative.parts or relative in files):
                    raise ValueError(f"Unexpected member: {entry.name}")
                files.add(relative)
                # Cargo generates these from the original manifest and resolution.
                if str(relative) in {".cargo_vcs_info.json", "Cargo.toml", "Cargo.lock"}:
                    continue
                target = source / ("Cargo.toml" if str(relative) == "Cargo.toml.orig" else relative)
                if target.read_bytes() != archive.extractfile(entry).read():
                    raise ValueError(f"Checkout differs from the candidate: {target.relative_to(ROOT)}")
        results[name] = {"sha256": expected, "members": len(files), "bytes": path.stat().st_size}
    return results


if __name__ == "__main__":
    print(json.dumps(check(), indent=2))
