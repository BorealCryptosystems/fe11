# SPDX-License-Identifier: Apache-2.0
"""Decode a public OAEP wrapping fixture independently of the native library."""
from pathlib import Path
import hashlib
from rsa_reference import decrypt_oaep, representative


def verify(case, vector, observation):
    source = Path(__file__).with_name('rsa_reference.py')
    if hashlib.sha256(source.read_bytes()).hexdigest() != case['reference_sha256']:
        raise ValueError('RSA reference source changed')
    fields = vector.read_text().splitlines()
    if len(fields) != 12 or not (
        (fields[0] == 'oaep' and fields[1] in ('label-session', 'label-advanced'))
        or (fields[0] in ('pkcs', 'oaep') and fields[1] == 'generic-secret')
    ):
        raise ValueError('unexpected OAEP wrap fixture')
    output = observation / 'public-wrap-ciphertext.bin'
    if output.is_symlink() or not output.is_file() or output.stat().st_size > 2048:
        raise ValueError('invalid public wrap output')
    ciphertext = output.read_bytes()
    valid = False
    try:
        if fields[0] == 'oaep':
            label = b'' if fields[1] == 'generic-secret' else b'wrap\0label'
            plaintext = decrypt_oaep(ciphertext, int(fields[2], 16), int(fields[4], 16),
                                     'SHA-256', 'SHA-256', label)
        else:
            block = representative(ciphertext, int(fields[2], 16), int(fields[4], 16))
            separator = block.find(b'\x00', 2)
            if not block.startswith(b'\x00\x02') or separator < 10:
                raise ValueError("invalid public PKCS1-v1_5 encoding")
            plaintext = block[separator + 1:]
        valid = plaintext == bytes.fromhex(fields[11])
    except ValueError:
        pass
    return dict(status='PASS' if valid else 'FAIL',
                source_sha256=hashlib.sha256(source.read_bytes()).hexdigest(),
                output_sha256=hashlib.sha256(ciphertext).hexdigest(),
                output_bytes=len(ciphertext),
                boundary='Python RSA integer operation and RFC8017 encryption decoding; hashlib may share OpenSSL hashes')
