# SPDX-License-Identifier: Apache-2.0
"""Execute the process-isolated public engine contract with identified native images."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import subprocess


def run(binary, engine, host, output):
    output = output.resolve()
    output.mkdir(mode=0o700, exist_ok=False)
    config = output / "openssl.cnf"
    config.write_text("openssl_conf = host_init\n[host_init]\nalg_section = host_properties\n"
                      "[host_properties]\ndefault_properties = provider=provider_that_is_not_loaded\n")
    env = {k:v for k,v in os.environ.items() if not k.startswith(("OPENSSL_", "FE11_", "LD_"))}
    env["OPENSSL_CONF"] = str(config)
    hashes = {}
    for variable, image in (("FE11_PUBLIC_HOST_CRYPTO",host), ("FE11_PUBLIC_VERIFY_ENGINE",engine)):
        image = image.resolve(strict=True)
        hashes[variable] = hashlib.sha256(image.read_bytes()).hexdigest()
        env[variable], env[variable + "_SHA256"] = str(image), hashes[variable]
    test = "engine_host::host_context_isolation"
    result = subprocess.run([str(binary.resolve(strict=True)), "--ignored", "--exact", test],
                            env=env, cwd=output, stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=3600)
    passed = result.returncode == 0 and ("test " + test + " ... ok") in result.stdout.decode().splitlines()
    (output / "result.json").write_text(json.dumps({"test":test, "images":hashes,
                                                    "status":"PASS" if passed else "FAIL"}))
    return 0 if passed else 1


if __name__ == "__main__":
    p = argparse.ArgumentParser(description=__doc__)
    for name in ("binary","engine","host","output"):
        p.add_argument("--" + name, type=Path, required=True)
    args = p.parse_args()
    raise SystemExit(run(args.binary,args.engine,args.host,args.output))

