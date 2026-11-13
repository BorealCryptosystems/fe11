# SPDX-License-Identifier: Apache-2.0
"""Build an unmodified upstream module; this prefix is independent of the engine."""
import os
import subprocess
from common import digest, save

COMMIT = "31293555b3822fcd687057e0b64462a114359c17"
URL = "https://github.com/softhsm/SoftHSMv2.git"


def build(job):
    if os.name == "nt":
        raise RuntimeError("SoftHSM suite requires Linux")
    source = job.root / "softhsm-source"
    prefix = job.root / "softhsm"
    job.run("softhsm-fetch", ["git", "clone", "--no-checkout", URL, source])
    job.run("softhsm-checkout", ["git", "checkout", "--detach", COMMIT], cwd=source)
    actual = subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=source, text=True).strip()
    if actual != COMMIT:
        raise ValueError("SoftHSM source identity mismatch")
    job.run("softhsm-autogen", ["sh", "autogen.sh"], cwd=source)
    job.run("softhsm-configure", ["sh", "configure", "--prefix=" + str(prefix),
        "--with-crypto-backend=openssl", "--disable-p11-kit"], cwd=source)
    job.run("softhsm-build", ["make", "-j2"], cwd=source)
    job.run("softhsm-install", ["make", "install"], cwd=source)
    if subprocess.check_output(["git", "diff", "--name-only"], cwd=source).strip():
        raise ValueError("SoftHSM tracked sources modified")
    modules = list(prefix.rglob("libsofthsm2.so"))
    if len(modules) != 1:
        raise ValueError("ambiguous module location")
    module = modules[0].resolve()
    utility = prefix / "bin/softhsm2-util"
    version = subprocess.check_output([str(utility), "--version"], env=job.env, text=True).strip()
    if version != "2.7.0":
        raise ValueError("unexpected SoftHSM version")
    job.env.update(FE11_CI_MODULE=str(module), FE11_CI_MODULE_SHA256=digest(module),
                   FE11_CI_SOFTHSM_UTIL=str(utility))
    save(job.reports / "softhsm.json", {"repository": URL, "commit": actual, "utility_version": version,
         "release_tag": None,
         "module_sha256": digest(module), "utility_sha256": digest(utility),
         "backend": "openssl", "object_store": "file", "source_patched": False})
