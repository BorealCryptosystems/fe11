# SPDX-License-Identifier: Apache-2.0
"""Verify the public-key PSS result following per-operation authentication."""
from rsa_reference import verify_pss
import hashlib


def verify(vector, directory):
    fields = vector.read_text().splitlines()
    if (len(fields) != 17 or fields[1:6] != [
            'sign', 'CKM_SHA256_RSA_PKCS_PSS', 'randomized', 'SHA256', '32']):
        raise ValueError('unexpected context-authentication reference')
    path = directory / 'public-context-signature.bin'
    if path.is_symlink() or not path.is_file() or path.stat().st_size != 256:
        raise ValueError('missing context-authentication signature')
    data = path.read_bytes()
    valid = verify_pss(data, int(fields[6], 16), int(fields[7], 16),
                       'SHA-256', 'SHA-256', 32, bytes.fromhex(fields[14]))
    return dict(status='PASS' if valid else 'FAIL',
                output_sha256=hashlib.sha256(data).hexdigest(), output_bytes=len(data),
                scope='Independent RFC8017 signature verification; public fixture key only')
