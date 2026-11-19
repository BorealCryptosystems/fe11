# SPDX-License-Identifier: Apache-2.0
"""Independent randomized RSA output checks, using explicitly public fixture keys."""
from rsa_reference import representative, verify_pss
import hashlib


def verify(vector, directory):
    fields = vector.read_text().splitlines()
    if len(fields) != 17:
        raise ValueError("RSA known fixture dimensions")
    output = directory / "public-rsa-known.bin"
    if fields[3] in ("exact", "length-boundaries", "cipher-length", "cipher-range"):
        if output.exists() or output.is_symlink():
            raise ValueError("unexpected randomized output")
        return {"status": "PASS", "scope": "native refusal checked by worker" if fields[3].startswith("cipher-") else "exact known answer checked by worker"}
    if fields[3] != "randomized" or output.is_symlink() or not output.is_file():
        raise ValueError("missing randomized RSA output")
    width = 256
    count = 2 if fields[1] == "sign" else 1
    if output.stat().st_size != count * width:
        raise ValueError("randomized RSA output length")
    data = output.read_bytes()
    n, e, d = (int(fields[i], 16) for i in (6, 7, 8))
    message = bytes.fromhex(fields[14])
    valid = True
    try:
        if fields[1] == "encrypt" and fields[2] == "CKM_RSA_PKCS":
            # RFC 8017 7.2.2: nonzero PS of at least eight octets, then 0.
            decoded = representative(data, n, d)
            delimiter = decoded.find(b"\x00", 2)
            valid = (decoded[:2] == b"\x00\x02" and delimiter >= 10
                     and decoded[delimiter + 1:] == message)
        elif fields[1] == "sign" and fields[2].endswith("_RSA_PKCS_PSS"):
            name = fields[4].replace("SHA3_", "SHA3-")
            if not name.startswith("SHA3-"):
                name = name.replace("SHA", "SHA-")
            valid = all(verify_pss(data[i:i + width], n, e, name, name,
                                   int(fields[5]), message)
                        for i in range(0, len(data), width))
        else:
            raise ValueError("unexpected randomized RSA operation")
    except ValueError:
        valid = False
    return {"status": "PASS" if valid else "FAIL",
            "output_bytes": len(data), "output_sha256": hashlib.sha256(data).hexdigest(),
            "scope": "independent RSA/encoding reference; public fixture keys only"}
