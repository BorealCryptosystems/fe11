# SPDX-License-Identifier: Apache-2.0
"""Remove only the token directory created by this case's supervisor.

The case parent is private and remains owned by the supervisor until cleanup.
Native children must have exited first. This is an ownership check against
accidental path substitution, not isolation from hostile code with the same
operating-system privileges. Symlinks inside the tree are removed, not followed.
"""
from pathlib import Path
import os
import shutil
import stat


def identity(path):
    value = path.lstat()
    if not stat.S_ISDIR(value.st_mode) or path.is_symlink():
        raise ValueError("owned storage must remain a directory")
    if getattr(value, 'st_file_attributes', 0) & getattr(stat, 'FILE_ATTRIBUTE_REPARSE_POINT', 0):
        raise ValueError("owned storage cannot be a reparse point")
    return value.st_dev, value.st_ino


class OwnedTokens:
    """Ownership is established by exclusive creation, never by finding a path."""

    def __init__(self, parent):
        parent = Path(parent)
        if not parent.is_absolute() or parent.resolve(strict=True) != parent:
            raise ValueError("case directory must be an absolute resolved path")
        self.parent = parent
        self.parent_identity = identity(parent)
        self.path = parent / 'tokens'
        self.path.mkdir(mode=0o700, exist_ok=False)
        self.token_identity = identity(self.path)
        self.closed = False

    def cleanup(self):
        """A failed identity check preserves the unknown directory for inspection."""
        if self.closed:
            return {'status': 'ALREADY_REMOVED'}
        if identity(self.parent) != self.parent_identity:
            raise ValueError("case directory identity changed")
        if identity(self.path) != self.token_identity:
            raise ValueError("token directory identity changed")
        # On POSIX, anchor the removal to the checked parent descriptor. rmtree's
        # fd-based walk also prevents a descendant link from redirecting removal.
        if os.name == 'posix':
            if not shutil.rmtree.avoids_symlink_attacks:
                raise ValueError("descriptor-based cleanup is unavailable")
            descriptor = os.open(self.parent, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
            try:
                value = os.fstat(descriptor)
                if (value.st_dev, value.st_ino) != self.parent_identity:
                    raise ValueError("case directory identity changed")
                shutil.rmtree('tokens', dir_fd=descriptor)
            finally:
                os.close(descriptor)
        else:
            # Windows rmtree removes directory junctions without traversing them.
            # The private parent and absence of concurrent children are required.
            shutil.rmtree(self.path)
        self.closed = True
        return {'status': 'REMOVED'}
