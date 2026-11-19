# SPDX-License-Identifier: Apache-2.0
"""Verify recipe library identities from the isolated Linux loader's file log."""
from pathlib import Path
import re
from run import digest


def verify(path, expected):
    """Read paths only; raw loader output remains in the private job directory.

    LD_DEBUG=files is applied only to the isolated native process. The supervisor
    and debugger keep their original loader environment. This does not inspect
    application buffers, credentials or function arguments.
    """
    if not expected or len(expected) > 16 or path.stat().st_size > 16 * 1024 * 1024:
        raise ValueError("invalid dependency observation input")
    wanted = {}
    for item in expected:
        image = Path(item["path"]).resolve(strict=True)
        if not image.is_absolute() or digest(image) != item["sha256"]:
            raise ValueError("recipe dependency bytes changed")
        if image in wanted:
            raise ValueError("duplicate recipe dependency")
        wanted[image] = item["sha256"]
    with path.open(encoding="utf-8", errors="strict") as stream:
        text = stream.read(16 * 1024 * 1024 + 1)
    initialized = set()
    for name in re.findall(r"^\s*\d+:\s+calling init:\s+(.+?)\s*$", text, re.MULTILINE):
        candidate = Path(name)
        # Only dependency images belong to this check. The module may be loaded
        # through an owned /proc/<pid>/fd descriptor that disappears at exit;
        # its identity is established separately by the native observer.
        if candidate.name.startswith(("libcrypto.so", "libsqlite3.so")) or candidate.name in ("legacy.so", "gost.so"):
            initialized.add(candidate.resolve(strict=True))
    if initialized != set(wanted):
        raise ValueError("loaded dependency identities differ from the selected recipe")
    return {str(image): value for image, value in wanted.items()}
