# SPDX-License-Identifier: Apache-2.0
"""Validate the exact Cargo archives selected for this hosted acceptance run."""
import hashlib
import json
from pathlib import Path, PurePosixPath
import tarfile

ROOT = Path(__file__).resolve().parents[2]
ARCHIVES = ROOT / "ci/candidate"
SUITE = "5ecee0a345927c9d57aae0887a20545552fc41a1de5566ab205ae4f3665480d9"
LIBRARY = "b681bd44f231e9ca1fd8eb5a2b02a79b5df7953519fdc38bddb9648159c13f44"
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
