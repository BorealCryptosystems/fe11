# SPDX-License-Identifier: Apache-2.0
"""Verify every positive PSS control surrounding isolated invalid-input calls."""
from rsa_reference import verify_pss
import hashlib


def verify(vector, directory):
    fields = vector.read_text().splitlines()
    if len(fields) not in (17, 18) or fields[3] not in (
            'changed-message', 'wrong-key', 'pss-digest-length', 'pss-hash-mismatch'):
        raise ValueError('invalid RSA negative fixture')
    if (fields[3] == 'wrong-key') != (len(fields) == 18):
        raise ValueError('invalid wrong-key fixture dimensions')
    output = directory / 'public-rsa-controls.bin'
    if fields[1] == 'verify':
        if output.exists() or output.is_symlink():
            raise ValueError('unexpected signature output from verification')
        return dict(status='PASS', scope='known valid signature before and after each native refusal')
    count = 3 if fields[3] == 'pss-digest-length' else 2
    if fields[1] != 'sign' or output.is_symlink() or not output.is_file() or output.stat().st_size != 256 * count:
        raise ValueError('invalid positive signature output')
    data = output.read_bytes()
    n, e = int(fields[6], 16), int(fields[7], 16)
    message = bytes.fromhex(fields[14])
    valid = all(verify_pss(data[i:i + 256], n, e, 'SHA-256', 'SHA-256', 32,
                           message, fields[3] == 'pss-digest-length')
                for i in range(0, len(data), 256))
    return dict(status='PASS' if valid else 'FAIL', output_bytes=len(data),
                output_sha256=hashlib.sha256(data).hexdigest(),
                scope='independent RFC8017 verification of every same-owner positive control')
