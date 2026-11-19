# SPDX-License-Identifier: Apache-2.0
"""Build the public test recipe once and transport its runtime images to Linux jobs."""
import json
import os
from pathlib import Path
import shutil
import sys
import tarfile
import urllib.request

sys.dont_write_bytecode = True
suite = Path(__file__).resolve().parents[2] / "fe11-tests/tests/driver"
sys.path.insert(0, str(suite))
from recipe_support import Build, digest
from recipes import build_dependencies, build_module

REVISION = "7380895665c3094a6f57640085bee97dcfeb1496"
SOURCES = {
    "sqlite.tar.gz": "https://www.sqlite.org/2026/sqlite-autoconf-3540100.tar.gz",
    "openssl.tar.gz": "https://github.com/openssl/openssl/releases/download/openssl-3.5.9/openssl-3.5.9.tar.gz",
    "softhsm.tar.gz": f"https://codeload.github.com/softhsm/SoftHSMv2/tar.gz/{REVISION}",
}


def package_runtime(output, prefix, configuration, module, sources):
    files = {name: prefix / name for name in (
        "openssl/bin/openssl", "openssl/lib/libssl.so.3", "openssl/lib/libcrypto.so.3",
        "openssl/lib/ossl-modules/legacy.so", "sqlite/lib/libsqlite3.so.0")}
    files["openssl-full.cnf"] = configuration
    files["softhsm-full/lib/softhsm/libsofthsm2.so"] = module
    output.mkdir()
    archive = output / "images.tar.gz"
    with tarfile.open(archive, "x:gz", dereference=True) as bundle:
        for name, path in files.items():
            bundle.add(path.resolve(strict=True), arcname=name, recursive=False)
    (output / "SHA256SUMS").write_text(digest(archive) + "  images.tar.gz\n")
    manifest = {"upstream_commit": REVISION, "recipe": "openssl-full",
                "inputs": {name: digest(sources / name, "sha3_256" if name == "sqlite.tar.gz" else "sha256")
                           for name in SOURCES},
                "recipe_driver": digest(suite / "recipes.py"),
                "recipe_support": digest(suite / "recipe_support.py"),
                "images": {name: digest(path) for name, path in files.items()}}
    (output / "provenance.json").write_text(json.dumps(manifest, indent=2))


def main():
    root = Path(os.environ["RUNNER_TEMP"]).resolve(strict=True) / "fe11-native-build"
    root.mkdir(mode=0o700)
    sources = root / "inputs"
    sources.mkdir()
    for name, url in SOURCES.items():
        with urllib.request.urlopen(url, timeout=3600) as source, (sources / name).open("xb") as dest:
            shutil.copyfileobj(source, dest)
    job = Build(root / "build", sources)
    env = build_dependencies(job)
    recipe = build_module(job, "full", env)
    package_runtime(root / "runtime", job.root / "prefix", Path(env["OPENSSL_CONF"]), Path(recipe["module"]), sources)


if __name__ == "__main__":
    main()
