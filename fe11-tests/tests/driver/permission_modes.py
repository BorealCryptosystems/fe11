# SPDX-License-Identifier: Apache-2.0
"""Observe new token-store modes under an explicit child-only OS mask."""
import os
import stat
from collections import Counter

MASKS = {'umask-zero': 0, 'umask-private': 0o77,
         'umask-deny': 0o777, 'umask-invalid': 0}


def prepare(root, config, case, vector):
    from configuration_variants import VARIANTS
    variant = case['configuration_variant']
    if (variant not in MASKS or case['worker_mode'] != 'builder-runtime-choices'
            or vector.stat().st_size > 8192
            or vector.read_text().splitlines()[0] != 'configuration:' + variant):
        raise ValueError('permission fixture mismatch')
    if config.is_symlink() or config.resolve(strict=True) != root / 'softhsm.conf':
        raise ValueError('configuration outside owned case')
    if any((root / 'tokens').iterdir()):
        raise ValueError('permissions must be configured before token creation')
    # This partition observes creation modes, not access denial. Root in the
    # isolated CI container can finish provisioning a directory with mode 000.
    # An unprivileged run cannot claim the same successful provisioning oracle.
    if variant == 'umask-deny' and os.geteuid() != 0:
        raise ValueError('mode-000 provisioning requires the isolated root container')
    config.write_text(config.read_text() + VARIANTS[variant])


def inspect(root, variant):
    mask = MASKS[variant]
    token_root = root / 'tokens'
    if token_root.is_symlink() or token_root.resolve(strict=True).parent != root:
        raise ValueError('unexpected token root')
    counts = Counter()
    for path in token_root.rglob('*'):
        mode = path.lstat().st_mode
        if path.is_symlink() or not (stat.S_ISDIR(mode) or stat.S_ISREG(mode)):
            raise ValueError('unexpected token-store entry')
        kind = 'directory' if stat.S_ISDIR(mode) else 'file'
        expected = (0o777 if kind == 'directory' else 0o666) & ~mask
        actual = stat.S_IMODE(mode)
        if actual != expected:
            raise ValueError('created token-store permission mismatch')
        counts[kind] += 1
    if not counts['directory'] or not counts['file']:
        raise ValueError('no new token material to inspect')
    return dict(status='PASS', entries=dict(counts), mask_octal=oct(mask),
                directory_mode=oct(0o777 & ~mask), file_mode=oct(0o666 & ~mask),
                child_process_umask=0, effective_uid=os.geteuid(),
                scope='New token files and directories only; no global umask mutation. Invalid syntax maps to zero through the pinned module parser, not a PKCS#11 conformance rule.')
