# SPDX-License-Identifier: Apache-2.0
"""Validate the exact Cargo archives selected for this hosted acceptance run."""
import hashlib
import json
from pathlib import Path, PurePosixPath
import tarfile

ROOT = Path(__file__).resolve().parents[2]
ARCHIVES = ROOT / "ci/candidate"
SUITE = "897f377476eb4214e44a12f142ff153b6bd3ec8bd53496fdef444e975decc959"
LIBRARY = "3e1456f59220d0d59c37a57cbb487b8a714fea0d6d7eb7600c9c3d71b3278042"
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
