# SPDX-License-Identifier: Apache-2.0
"""Pack, check, or unpack the native inputs included in the Fe11 source crate."""
import argparse
import hashlib
import io
import json
from pathlib import Path
import re
import tarfile
from tempfile import TemporaryDirectory

VECTORS = Path(__file__).resolve().parents[1] / "vectors"
FAMILIES = (
    "classical-sign", "dsa", "engine-retained", "mac", "oaep", "oaep-encrypt",
    "pqc", "pqc-absent", "pqc-binding-negatives", "pqc-random", "pqc-transition",
    "rsa-domain",
)
ARCHIVE = "native-inputs.tar.xz"


def inventory():
    expected = {}
    for family in FAMILIES:
        directory = VECTORS / family
        if directory.is_symlink() or directory.resolve().parent != VECTORS.resolve():
            raise ValueError("fixture directory must be local")
        manifest = json.loads((directory / "manifest.json").read_text(encoding="utf-8"))
        for case in manifest:
            digest = case["sha256"]
            if not re.fullmatch(r"[a-f0-9]{64}", digest) or case["file"] != digest + ".txt":
                raise ValueError("unexpected content-addressed fixture name")
            expected[family + "/" + case["file"]] = digest
    return expected


def checked(data, digest):
    if hashlib.sha256(data).hexdigest() != digest:
        raise ValueError("fixture differs from its public manifest")
    return data


def process(action):
    expected = inventory()
    if action == "pack":
        # Canonical metadata and ordering make the output independent of the checkout.
        with TemporaryDirectory(dir=VECTORS) as tmp:
            built = Path(tmp) / ARCHIVE
            with tarfile.open(built, "w:xz", format=tarfile.USTAR_FORMAT, preset=6) as bundle:
                for name, digest in sorted(expected.items()):
                    data = checked((VECTORS / name).read_bytes(), digest)
                    info = tarfile.TarInfo(name)
                    info.size = len(data)
                    bundle.addfile(info, io.BytesIO(data))
            built.replace(VECTORS / ARCHIVE)
        return

    with tarfile.open(VECTORS / ARCHIVE, "r|xz") as bundle:
        seen = set()
        for info in bundle:
            if info.name not in expected or info.name in seen or not info.isfile():
                raise ValueError("unexpected archive member")
            seen.add(info.name)
            if info.size > 16 * 1024 * 1024:
                raise ValueError("oversized fixture")
            with bundle.extractfile(info) as stream:
                data = checked(stream.read(), expected[info.name])
            path = VECTORS / info.name
            if path.is_symlink():
                raise ValueError("unexpected fixture symlink")
            if path.exists():
                checked(path.read_bytes(), expected[info.name])
            elif action == "unpack":
                # A fresh crate can be unpacked again after an interrupted run.
                with TemporaryDirectory(dir=path.parent) as tmp:
                    ready = Path(tmp) / "fixture"
                    ready.write_bytes(data)
                    ready.replace(path)
        if seen != expected.keys():
            raise ValueError("incomplete fixture archive")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("action", choices=("pack", "check", "unpack"))
    process(parser.parse_args().action)
