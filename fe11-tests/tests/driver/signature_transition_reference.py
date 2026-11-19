# SPDX-License-Identifier: Apache-2.0
"""Validate P-256 transition signatures through the pinned OpenSSL CLI.

Published NIST positives and a corrupted signature are controls. The reference
shares SoftHSM's crypto backend, but does not use Fe11 or its PKCS#11 adapter.
"""
from pathlib import Path
import hashlib
from classical_reference import signature, point
from dependencies import verify as verify_dependencies
from process import execute
from reference_encoding import der, write
from run import digest


def verify(vector, directory, reference, environment, expected_count):
    fields = vector.read_text().splitlines()
    if (len(fields) != 9 or fields[3] not in ("ECDSA-P256", "ECDSA-SHA256-P256") or fields[6]
            or fields[2] not in ("sign", "verify") or expected_count not in (0, 1, 2)):
        raise ValueError("ECDSA transition reference input")
    public = bytes.fromhex(fields[4]); message = bytes.fromhex(fields[7])
    if len(message) > 4096:
        raise ValueError("ECDSA transition input size")
    # Raw ECDSA receives a digest; the combined mechanism receives its preimage.
    hashed = hashlib.sha256(message).digest() if fields[3] == "ECDSA-SHA256-P256" else message
    known = bytes.fromhex(fields[8])
    if len(public) != 67 or len(hashed) != 32 or len(known) != 64:
        raise ValueError("ECDSA transition dimensions")
    output = directory / "public-transition-signatures.bin"
    if fields[2] == "sign":
        if output.is_symlink() or not output.is_file() or output.stat().st_size != expected_count*64:
            raise ValueError("ECDSA transition publication count")
        native = output.read_bytes()
    else:
        if expected_count != 0 or output.exists():
            raise ValueError("verification cannot publish a signature")
        native = b""
    executable = Path(reference["executable"]).resolve(strict=True)
    if not executable.is_absolute() or digest(executable) != reference["sha256"]:
        raise ValueError("signature reference binary changed")
    root = directory / "signature-reference"; root.mkdir(mode=0o700)
    algorithm = der(0x30, bytes.fromhex("06072a8648ce3d020106082a8648ce3d030107"))
    write(root/"key.der", der(0x30, algorithm+der(3, b"\0"+point(public))))
    write(root/"digest.bin", hashed)
    changed = bytearray(known); changed[-1] ^= 1
    controls = [("published", known, 0), ("corrupted", changed, 1)]
    controls += [("native-"+str(i), native[i*64:(i+1)*64], 0) for i in range(expected_count)]
    results = []
    for name, value, expected in controls:
        sig = root/(name+".sig"); write(sig, signature(value, 32))
        command = [str(executable), "pkeyutl", "-verify", "-pubin", "-keyform", "DER",
                   "-inkey", str(root/"key.der"), "-in", str(root/"digest.bin"), "-sigfile", str(sig)]
        env = dict(environment, LD_DEBUG="files"); env.pop("LD_DEBUG_OUTPUT", None)
        process = execute(command, env, root/name, bytearray())
        loaded = verify_dependencies(root/name/"stderr.raw", reference["dependencies"])
        results.append(dict(control=name, expected_exit=expected, **process, loaded_dependencies=loaded))
    valid = all(v["state"] == "EXITED" and v["exit_code"] == v["expected_exit"] for v in results)
    return dict(status="PASS" if valid else "FAIL", controls=results,
                native_signatures_checked=expected_count, executable_sha256=reference["sha256"],
                boundary="Separate CLI and published controls; shared crypto backend")
