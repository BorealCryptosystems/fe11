# SPDX-License-Identifier: Apache-2.0
"""Run the public Rust contracts and validate the independently extracted crate."""
import json
import os
from pathlib import Path
import sys
import tomllib

from common import digest, extract, save
from candidate_inputs import ARCHIVES, EXPECTED


MAX_CRATE_BYTES = 10_000_000


def use_packed_library(lockfile):
    """Keep the packaged resolution, replacing only the Fe11 registry origin with its local crate."""
    text = lockfile.read_text(encoding="utf-8")
    sections = text.split("[[package]]")
    matches = [i for i, section in enumerate(sections[1:], 1)
               if tomllib.loads(section).get("name") == "fe11"]
    if len(matches) != 1:
        raise ValueError("Missing unique Fe11 dependency in packaged lockfile")
    i = matches[0]
    record = tomllib.loads(sections[i])
    if (record["version"] != "0.1.1" or record["checksum"] != EXPECTED["fe11"]
            or record["source"] != "registry+https://github.com/rust-lang/crates.io-index"):
        raise ValueError("Packaged test lockfile selects a different Fe11 archive")
    sections[i] = "".join(line for line in sections[i].splitlines(keepends=True)
                          if not line.startswith(("source = ", "checksum = ")))
    lockfile.write_text("[[package]]".join(sections), encoding="utf-8", newline="\n")


def test_sources(root):
    return {p.relative_to(root).as_posix(): digest(p) for p in root.rglob("*") if p.is_file()
            and "__pycache__" not in p.parts and p.suffix != ".pyc"}


def validate(job):
    inputs = test_sources(job.repository / "fe11-tests/tests")
    check_packages(job, ARCHIVES, inputs)
    if sys.platform == "linux":
        check_host_isolation(job)


def check_host_isolation(job):
    import shutil

    from engine_isolation import run

    manifest, = (job.root / "standalone-fe11-tests").glob("*/Cargo.toml")
    library, = (job.root / "standalone-fe11").glob("*/Cargo.toml")
    override = "patch.crates-io.fe11.path=" + json.dumps(library.parent.as_posix())
    log = job.run("locate-local-harness", [job.toolchain / "bin/cargo", "--config", override, "test",
                  "--locked", "--release", "--test", "local", "--no-run", "--message-format=json"], cwd=manifest.parent)
    messages = [json.loads(line) for line in log.read_text().splitlines() if line.startswith("{")]
    binary, = [Path(obj["executable"]) for obj in messages if obj.get("reason") == "compiler-artifact"
               and obj["target"]["name"] == "local" and obj.get("executable")]
    log = job.run("locate-host-crypto", ["cc", "-print-file-name=libcrypto.so.3"])
    host = Path(log.read_text().strip())
    if not host.is_absolute():
        raise ValueError("host libcrypto not found")
    output = job.root / "engine-isolation"
    status = run(binary, job.root / "target/release/libfe11_verify_engine.so", host, output)
    shutil.copyfile(output / "result.json", job.reports / "engine-isolation.json")
    if status:
        raise ValueError("engine host-context isolation failed")


def check_packages(job, archives, expected_tests):
    suffix = ".exe" if os.name == "nt" else ""
    extracted = {}
    records = {}
    for name in ("fe11", "fe11-tests"):
        candidates = list(archives.glob(name + "-[0-9]*.crate"))
        if len(candidates) != 1 or candidates[0].stat().st_size > MAX_CRATE_BYTES:
            raise ValueError(f"expected one {name} archive of at most 10,000,000 bytes")
        archive = candidates[0]
        if digest(archive) != EXPECTED[name]:
            raise ValueError(f"Archive identity mismatch: {name}")
        destination = job.root / ("standalone-" + name)
        extract(archive, destination)
        extracted[name] = destination / archive.stem
        records[name] = {"sha256": digest(archive), "bytes": archive.stat().st_size}
    library, package = extracted["fe11"], extracted["fe11-tests"]
    if (library / "tests").exists():
        raise ValueError("library archive contains the separate test suite")
    tests = package / "tests"
    job.run("unpack-public-inputs", [sys.executable, "-B", tests / "driver/fixture_archive.py", "unpack"])
    files = test_sources(tests)
    if files != expected_tests:
        raise ValueError("packaged tests or inputs differ from the frozen checkout")
    cargo = job.toolchain / "bin" / ("cargo" + suffix)
    # A local override exercises the packed library before either package is released.
    # Both extractions are outside the checkout and the published manifest retains =0.1.1.
    override = ["--config", "patch.crates-io.fe11.path=" + json.dumps(library.as_posix())]
    use_packed_library(package / "Cargo.lock")
    graph = job.run("check-packed-graph", [cargo, *override, "metadata", "--locked", "--format-version=1"], cwd=package)
    metadata, = (json.loads(line) for line in graph.read_text(encoding="utf-8").splitlines()
                 if line.startswith("{"))
    selected = [Path(p["manifest_path"]).resolve() for p in metadata["packages"] if p["name"] == "fe11"]
    if selected != [(library / "Cargo.toml").resolve()]:
        raise ValueError("tests resolved a different library")
    job.run("packaged-local-contracts", [cargo, *override, "test", "--release", "--locked", "--test", "local"],
            cwd=package)
    worker_log = job.run("packaged-native-worker", [cargo, *override, "test", "--release", "--locked",
                         "--test", "native", "--no-run", "--message-format=json"], cwd=package)
    if sys.platform == "linux" and job.github:
        import shutil

        records_out = [json.loads(line) for line in worker_log.read_text().splitlines() if line.startswith("{")]
        worker, = [Path(row["executable"]) for row in records_out if row.get("reason") == "compiler-artifact"
                   and row["target"]["name"] == "native" and row.get("executable")]
        kit = job.root / "native-kit"
        kit.mkdir()
        shutil.copyfile(worker, kit / "worker")
        target_engine = job.root / "target/release/libfe11_verify_engine.so"
        shutil.copyfile(target_engine, kit / "engine.so")
        suite, = archives.glob("fe11-tests-[0-9]*.crate")
        shutil.copyfile(suite, kit / "suite.crate")
        save(kit / "identity.json", {"rust": job.rust, "library_sha256": records["fe11"]["sha256"], "worker": digest(worker),
             "engine.so": digest(target_engine), "suite.crate": digest(suite)})
    artifacts = job.run("packaged-library", [cargo, "build", "--locked", "--release", "--lib",
                                             "--message-format=json"], cwd=library)
    compiler_outputs = [json.loads(line) for line in artifacts.read_text(encoding="utf-8").splitlines()
                        if line.startswith("{")]
    libraries = [Path(f) for obj in compiler_outputs if obj.get("reason") == "compiler-artifact"
                 and obj["target"]["name"] == "fe11" for f in obj["filenames"] if f.endswith(".rlib")]
    if len(libraries) != 1:
        raise ValueError("expected one compiler-identified Fe11 library")
    contracts = compiler_contracts(job, tests, libraries[0], compiler_outputs)
    save(job.reports / "public-contracts.json", dict(packages=records, test_files=len(files), compiler_contracts=contracts,
        local="PASS", native_worker="COMPILED"))


def compiler_contracts(job, tests, library, compiler_outputs):
    # Cargo layouts differ between toolchains. Use the actual dependency artifacts
    # of this library build, including procedural macros used by public types.
    directories = {Path(f).parent for obj in compiler_outputs if obj.get("reason") == "compiler-artifact"
                   for f in obj["filenames"] if Path(f).suffix in {".rlib", ".rmeta", ".dll", ".so", ".dylib"}}
    search = [arg for directory in sorted(directories) for arg in ("--dependency", directory)]
    contracts = {}
    for manifest in sorted((tests / "vectors").glob("compile-*/manifest.json")):
        name = manifest.parent.name
        output = job.root / name
        job.run(name, [sys.executable, "-B", tests / "driver/compile_contracts.py",
                       "--rustc", job.toolchain / "bin" / ("rustc.exe" if os.name == "nt" else "rustc"),
                       "--rlib", library, *search, "--manifest", manifest, "--output", output])
        report = json.loads((output / "result.json").read_text())
        contracts[name] = len(report["results"])
    if not contracts:
        raise ValueError("missing public type contracts")
    return contracts
