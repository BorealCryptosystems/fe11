# SPDX-License-Identifier: Apache-2.0
"""Bounded scan of this case's logs; never include a matching secret in results."""
import base64
import json


def inspect(root, credentials, public_result):
    officer, user = credentials
    if len(officer) != 16 or len(user) != 16:
        raise ValueError('unexpected sentinel width')
    marker = bytearray(value ^ 0xa5 for value in user)
    # Python immutable encodings and native provider copies cannot be wiped by
    # this helper. They remain confined to the disposable supervisor process.
    try:
        needles = []
        for value in (officer, user, marker):
            raw = bytes(value)
            needles.extend((raw, raw.hex().encode(), raw.hex().upper().encode(),
                            base64.b64encode(raw), repr(raw)[2:-1].encode(),
                            json.dumps(list(raw)).encode()))
        paths = [root / 'module.log']
        for folder in ('provision', 'observation'):
            paths.extend(root / folder / name for name in ('stdout.raw', 'stderr.raw'))
        paths.extend(root / 'observation' / name for name in ('worker.jsonl', 'trace.jsonl'))
        total = 0
        secret_present = False
        for path in paths:
            if path.is_symlink() or not path.is_file() or path.stat().st_size > 16 * 1024 * 1024:
                raise ValueError('missing or unbounded owned diagnostic')
            data = path.read_bytes()
            if path.name == 'module.log' and not data:
                raise ValueError('debug log was not exercised')
            total += len(data)
            secret_present |= any(needle in data for needle in needles)
        if not isinstance(public_result, dict):
            raise ValueError('missing public result to inspect')
        public_bytes = json.dumps(public_result, sort_keys=True).encode()
        secret_present |= any(needle in public_bytes for needle in needles)
        return dict(status='FAIL' if secret_present else 'PASS',
                    files=len(paths), bytes=total, public_result_inspected=True, secret_present=secret_present,
                    scope='Ephemeral SO/user PIN and a distinct private-key marker: raw, hex, base64, Python bytes escapes and JSON byte arrays. Seven owned diagnostic files plus the pending public result; no claim about arbitrary encodings or unobserved paths.')
    finally:
        marker[:] = b'\0' * len(marker)
