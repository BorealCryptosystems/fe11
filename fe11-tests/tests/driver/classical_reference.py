# SPDX-License-Identifier: Apache-2.0
"""DSA/ECDSA signature checks through a pinned, separate OpenSSL CLI process.

The reference shares SoftHSM's crypto implementation, not its PKCS#11 adapter.
Published NIST signatures and corrupted native signatures are mandatory controls.
"""
from pathlib import Path
import hashlib
from dependencies import verify as verify_dependencies
from process import execute
from reference_encoding import der, write
from run import digest


def integer(value):
    value = value.lstrip(b"\0") or b"\0"
    return der(2, (b"\0" if value[0] & 0x80 else b"") + value)


def signature(value, width):
    if len(value) != 2*width:
        raise ValueError("classical signature dimensions")
    return der(0x30, integer(value[:width]) + integer(value[width:]))


def point(value):
    if len(value) < 3 or value[0] != 4:
        raise ValueError("EC point OCTET STRING")
    count = value[1]
    if count < 128:
        offset = 2
    elif count == 129 and len(value) > 3 and value[2] >= 128:
        count, offset = value[2], 3
    else:
        raise ValueError("EC point DER length")
    if len(value) != offset+count or value[offset] != 4:
        raise ValueError("EC uncompressed point dimensions")
    return value[offset:]


def verify(vector, directory, reference, environment):
    fields = vector.read_text().splitlines()
    if len(fields) != 14 or fields[1] not in ("ecdsa", "dsa") or fields[3] not in ("single", "both"):
        raise ValueError("classical reference fixture")
    width = int(fields[4]);count = 2 if fields[3] == "both" else 1
    output = directory/"public-classical-signatures.bin"
    if not 1 <= width <= 72 or output.is_symlink() or not output.is_file() or output.stat().st_size != count*2*width:
        raise ValueError("classical reference output")
    values = [bytes.fromhex(fields[i]) for i in range(7,14)]
    p, q, g, public, _private, message, known = values
    if fields[1] == "ecdsa":
        algorithm = der(0x30, bytes.fromhex("06072a8648ce3d0201")+p)
        public_value = point(public)
    else:
        algorithm = der(0x30, bytes.fromhex("06072a8648ce380401")+der(0x30,integer(p)+integer(q)+integer(g)))
        public_value = integer(public)
    spki = der(0x30,algorithm+der(3,b"\0"+public_value))
    hashed = message if fields[2] in ("CKM_DSA", "CKM_ECDSA") else hashlib.new(fields[6],message).digest()
    if len(hashed) > 64:
        raise ValueError("classical digest width")
    executable = Path(reference["executable"]).resolve(strict=True)
    if not executable.is_absolute() or digest(executable) != reference["sha256"]:
        raise ValueError("classical reference binary changed")
    root = directory/"classical-reference";root.mkdir(mode=0o700)
    write(root/"key.der",spki);write(root/"digest.bin",hashed)
    native = output.read_bytes()
    controls = [("known",known,0)] + [("native-"+str(i),native[i*2*width:(i+1)*2*width],0) for i in range(count)]
    changed = bytearray(controls[1][1]);changed[-1] ^= 1
    controls.append(("changed",changed,1))
    results = []
    for name, value, expected in controls:
        sig = root/(name+".sig");write(sig,signature(value,width))
        command = [str(executable),"pkeyutl","-verify","-pubin","-keyform","DER", "-inkey",str(root/"key.der"),
                   "-in",str(root/"digest.bin"),"-sigfile",str(sig)]
        env = dict(environment,LD_DEBUG="files");env.pop("LD_DEBUG_OUTPUT",None)
        process = execute(command,env,root/name,bytearray())
        loaded = verify_dependencies(root/name/"stderr.raw",reference["dependencies"])
        results.append(dict(control=name,expected_exit=expected,**process,loaded_dependencies=loaded))
    valid = all(r["state"]=="EXITED" and r["exit_code"]==r["expected_exit"] for r in results)
    return dict(status="PASS" if valid else "FAIL",controls=results,output_bytes=len(native),
                output_sha256=hashlib.sha256(native).hexdigest(),executable_sha256=reference["sha256"],
                boundary="Separate CLI interface; shared backend; published NIST positive and corrupted negative controls")
