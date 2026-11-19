# SPDX-License-Identifier: Apache-2.0
"""Minimal DER construction and exclusive public reference-file creation."""
import os

def der(tag, value):
    length = len(value)
    encoded = bytes([length]) if length < 128 else length.to_bytes((length.bit_length()+7)//8, "big")
    if length >= 128:
        encoded = bytes([0x80 | len(encoded)]) + encoded
    return bytes([tag]) + encoded + value


def write(path, data):
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(fd, "wb") as output:
        output.write(data)

