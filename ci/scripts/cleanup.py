# SPDX-License-Identifier: Apache-2.0
"""Remove one completed CI job's reproducible files, preserving its reports."""
import argparse
from pathlib import Path
import shutil

parser = argparse.ArgumentParser(description=__doc__)
parser.add_argument("--root", type=Path, required=True)
parser.add_argument("--parent", type=Path, required=True)
args = parser.parse_args()
root, parent = args.root.resolve(), args.parent.resolve()
if root == parent or not root.is_relative_to(parent) or root == Path(root.anchor):
    raise ValueError("cleanup outside selected parent")
if not root.exists():
    raise SystemExit(0)
if (root / "owner.txt").read_text(encoding="ascii") != "fe11-public-ci\n":
    raise ValueError("not a CI job directory")
for name in ("tokens", "target", "tmp", "cargo", "rust", "openssl-source", "openssl", "softhsm-source", "softhsm", "sys"):
    path = root / name
    if path.exists():
        if path.is_symlink() or not path.resolve().is_relative_to(root):
            raise ValueError("cleanup target escapes job")
        shutil.rmtree(path)
