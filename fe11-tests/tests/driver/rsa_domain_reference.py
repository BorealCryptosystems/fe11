# SPDX-License-Identifier: Apache-2.0
"""Verify the bounded public outputs of the RSA parameter-domain cases."""
from pathlib import Path
import hashlib
from rsa_reference import decrypt_oaep, verify_pss

HASHES = {"SHA1": "SHA-1", "SHA224": "SHA-224", "SHA256": "SHA-256",
          "SHA384": "SHA-384", "SHA512": "SHA-512", "SHA3_224": "SHA3-224",
          "SHA3_256": "SHA3-256", "SHA3_384": "SHA3-384", "SHA3_512": "SHA3-512"}


def verify(vector, directory):
    fields = vector.read_text().splitlines()
    if len(fields) != 15 or fields[0] not in ("pss", "oaep") or fields[4] not in ("valid", "oversize"):
        raise ValueError("invalid RSA domain fixture")
    output = Path(directory) / "public-rsa-domain.bin"
    if fields[4] == "oversize":
        return {"status": "PASS" if not output.exists() and not output.is_symlink() else "FAIL",
                "oracle": "native refusal without output; worker checks exact allowed code/producer"}
    expected = 512 if fields[0] == "pss" else 256
    if output.is_symlink() or not output.is_file() or output.stat().st_size != expected:
        raise ValueError("invalid RSA domain output")
    blob = output.read_bytes()
    modulus, exponent, private = (int(fields[i], 16) for i in (5, 6, 7))
    hash_name, mgf_name = HASHES[fields[1]], HASHES[fields[2]]
    message, prehash = bytes.fromhex(fields[13]), bytes.fromhex(fields[14])
    try:
        if fields[0] == "pss":
            salt = int(fields[3])
            valid = (verify_pss(blob[:256], modulus, exponent, hash_name, mgf_name, salt, prehash, True)
                     and verify_pss(blob[256:], modulus, exponent, hash_name, mgf_name, salt, message))
        else:
            valid = decrypt_oaep(blob, modulus, private, hash_name, mgf_name, b"") == message
    except ValueError:
        valid = False
    return {"status": "PASS" if valid else "FAIL", "output_bytes": len(blob),
            "output_sha256": hashlib.sha256(blob).hexdigest(),
            "oracle": "RFC8017 integer/encoding reference; hashlib may share OpenSSL hashes"}
