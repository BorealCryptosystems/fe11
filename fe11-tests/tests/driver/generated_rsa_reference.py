# SPDX-License-Identifier: Apache-2.0
"""RFC 8017 verification of a generated key's public modulus and signature."""
import hashlib
from rsa_reference import representative


def verify(directory, bits):
    if bits not in (512, 1024, 2048, 3072, 4096, 16384):
        raise ValueError("generated RSA fixture size")
    width = bits // 8
    path = directory / "public-generated-rsa.bin"
    if path.is_symlink() or not path.is_file() or path.stat().st_size != 2 * width:
        raise ValueError("generated RSA output dimensions")
    data = path.read_bytes()
    modulus = int.from_bytes(data[:width], "big")
    if modulus.bit_length() != bits:
        raise ValueError("generated RSA modulus bits")
    # Published SHA-256("abc") and DER DigestInfo, not a native digest callback.
    digest_info = bytes.fromhex("3031300d060960864801650304020105000420"
                               "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad")
    expected = b"\x00\x01" + b"\xff" * (width - len(digest_info) - 3) + b"\x00" + digest_info
    signature = data[width:]
    valid = representative(signature, modulus, 65537) == expected
    altered = bytearray(signature)
    altered[-1] ^= 1
    try:
        invalid = representative(altered, modulus, 65537) != expected
    except ValueError:
        invalid = True
    return {"status": "PASS" if valid and invalid else "FAIL", "modulus_bits": bits,
            "output_sha256": hashlib.sha256(data).hexdigest(),
            "scope": "Independent integer exponentiation, exact RFC8017 encoding and altered-signature control"}
