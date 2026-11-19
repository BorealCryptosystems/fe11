# SPDX-License-Identifier: Apache-2.0
"""Public PQC signature verification outside Fe11 and the PKCS#11 interface.

The pinned CLI shares SoftHSM's cryptographic backend. Published NIST positives
and altered-signature negatives control that boundary; this is not a claim of
independently implemented FIPS 204/205 arithmetic.
"""
from pathlib import Path
import hashlib
from dependencies import verify as verify_dependencies
from process import execute
from run import digest
from reference_encoding import der, write


def parameter(name):
    ml = {"ML-DSA-44": (17, 1312, 2420), "ML-DSA-65": (18, 1952, 3309),
          "ML-DSA-87": (19, 2592, 4627)}
    if name in ml:
        return ml[name]
    order = [("128s", 32, 7856), ("128f", 32, 17088), ("192s", 48, 16224),
             ("192f", 48, 35664), ("256s", 64, 29792), ("256f", 64, 49856)]
    for family, base in (("SHA2", 20), ("SHAKE", 26)):
        for index, (suffix, public, signature) in enumerate(order):
            if name == "SLH-DSA-" + family + "-" + suffix:
                return base + index, public, signature
    raise ValueError("unknown PQC reference parameter set")


def verify(vector, directory, reference, environment):
    fields = vector.read_text().splitlines()
    if len(fields) != 9 or fields[1] != "sign" or fields[2] not in ("randomized", "preferred"):
        raise ValueError("unexpected randomized PQC fixture")
    oid, public_length, signature_length = parameter(fields[3])
    public, context, message, known = (bytes.fromhex(fields[i]) for i in (4, 6, 7, 8))
    output = directory / "public-pqc-signature.bin"
    if (len(public) != public_length or len(known) != signature_length or len(context) > 255
            or output.is_symlink() or not output.is_file() or output.stat().st_size != signature_length):
        raise ValueError("PQC reference dimensions")
    signature = output.read_bytes()
    executable = Path(reference["executable"]).resolve(strict=True)
    if not executable.is_absolute() or digest(executable) != reference["sha256"]:
        raise ValueError("PQC reference binary changed")
    # NIST signature OIDs: 2.16.840.1.101.3.4.3.{17..31}; absent parameters.
    algorithm = der(0x30, der(0x06, bytes.fromhex("6086480165030403") + bytes([oid])))
    spki = der(0x30, algorithm + der(0x03, b"\0" + public))
    root = directory / "pqc-reference"
    root.mkdir(mode=0o700)
    write(root/"key.der", spki); write(root/"message.bin", message)
    changed = bytearray(signature); changed[-1] ^= 1
    results = []
    for name, value, expected in (("known", known, 0), ("native", signature, 0), ("changed", changed, 1)):
        sig = root/(name+".sig"); write(sig, value)
        command = [str(executable), "pkeyutl", "-verify", "-rawin", "-pubin", "-keyform", "DER",
                   "-inkey", str(root/"key.der"), "-in", str(root/"message.bin"), "-sigfile", str(sig),
                   "-pkeyopt", "hexcontext-string:"+context.hex()]
        env = dict(environment, LD_DEBUG="files")
        env.pop("LD_DEBUG_OUTPUT", None)
        process = execute(command, env, root/name, bytearray())
        loaded = verify_dependencies(root/name/"stderr.raw", reference["dependencies"])
        results.append(dict(control=name, expected_exit=expected, **process, loaded_dependencies=loaded))
    valid = all(r["state"] == "EXITED" and r["exit_code"] == r["expected_exit"] for r in results)
    return dict(status="PASS" if valid else "FAIL", controls=results, executable_sha256=reference["sha256"],
                output_sha256=hashlib.sha256(signature).hexdigest(), output_bytes=len(signature),
                boundary="Separate CLI interface; shared backend; published NIST positive and corrupted negative controls")
