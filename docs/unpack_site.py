#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Verify the documentation archive and extract regular confined files."""
import argparse
import hashlib
import json
from pathlib import Path, PurePosixPath
import re
import stat
import zipfile


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--manifest", type=Path, required=True)
    parser.add_argument("--archive", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    manifest = json.loads(args.manifest.read_text(encoding="utf8"))
    expected = manifest["sha256"]
    version = manifest["version"]
    if not re.fullmatch(r"[0-9]+\.[0-9]+\.[0-9]+", version):
        raise ValueError("Expected a release version")
    if not re.fullmatch(r"[0-9a-f]{64}", expected):
        raise ValueError("Expected a SHA-256 identity")
    with args.archive.open("rb") as stream:
        digest = hashlib.file_digest(stream, "sha256").hexdigest()
    if digest != expected or args.archive.name != manifest["asset"]:
        raise ValueError("Archive identity differs from the manifest")
    root = args.output.resolve()
    if root.exists():
        raise ValueError("Output must be a new directory")
    with zipfile.ZipFile(args.archive) as archive:
        entries = archive.infolist()
        names = set()
        total = 0
        for entry in entries:
            path = PurePosixPath(entry.filename)
            mode = (entry.external_attr >> 16) & 0xFFFF
            if (path.is_absolute() or '..' in path.parts or '\\' in entry.filename or
                    ':' in entry.filename or entry.filename in names or
                    not path.parts or stat.S_ISLNK(mode) or
                    stat.S_IFMT(mode) not in (0, stat.S_IFREG, stat.S_IFDIR)):
                raise ValueError("Archive contains an invalid member")
            if not (root / Path(*path.parts)).resolve().is_relative_to(root):
                raise ValueError("Archive member escapes output")
            names.add(entry.filename)
            total += entry.file_size
        if len(entries) != manifest["files"] or total != manifest["uncompressed_bytes"]:
            raise ValueError("Archive inventory differs from the manifest")
        root.mkdir(parents=True)
        for entry in entries:
            path = root / entry.filename
            if entry.is_dir():
                path.mkdir(parents=True, exist_ok=True)
            else:
                path.parent.mkdir(parents=True, exist_ok=True)
                with archive.open(entry) as source, path.open("xb") as target:
                    while data := source.read(1024 * 1024):
                        target.write(data)
    if not (root / version / "api/fe11/index.html").is_file():
        raise ValueError("Fe11 API entry is missing")
    print("Verified and extracted the documentation site")


if __name__ == "__main__":
    main()
