# SPDX-License-Identifier: Apache-2.0
"""Check documented Rust examples as well as the generated API reference."""
import json
import os
from pathlib import Path
import re
from common import save


def fences(path):
    result = []
    inside = False
    for number, line in enumerate(path.read_text(encoding="utf-8").splitlines(), 1):
        line = re.sub(r"^\s*(?:///|//!)\s?", "", line)
        if line.strip().startswith("```"):
            if not inside:
                language = line.strip()[3:].strip()
                rust = not language or language.split(",")[0] in ("rust", "no_run", "compile_fail", "should_panic", "ignore")
                if rust:
                    if "ignore" in language.split(","):
                        raise ValueError("ignored public Rust example")
                    result.append({"line": number, "attributes": language})
            inside = not inside
    if inside:
        raise ValueError("unclosed documentation fence")
    return result


def artifact_paths(output):
    """Resolve only artifacts reported by the selected Cargo invocation."""
    externs = {}
    dependency_directories = set()
    for line in output.read_text(encoding="utf-8").splitlines():
        if not line.startswith("{"):
            continue
        entry = json.loads(line)
        if entry.get("reason") == "compiler-artifact":
            for name in entry["filenames"]:
                if name.endswith((".rlib", ".rmeta", ".dll", ".so", ".dylib")):
                    dependency_directories.add(str(Path(name).parent))
                if name.endswith(".rlib"):
                    externs[entry["target"]["name"]] = name
    for name in ("fe11", "fe11_sys", "fe11_verify_engine_api"):
        if name not in externs:
            raise ValueError("documentation dependency artifact missing")
    return externs, dependency_directories


def inventory(job):
    inventory = {}
    documents = []
    for directory in ("library", "verify-engine-api", "verify-engine", "docs", "ci"):
        for path in sorted((job.repository / directory).rglob("*")):
            if path.suffix in (".rs", ".md"):
                entries = fences(path)
                if entries:
                    inventory[path.relative_to(job.repository).as_posix()] = entries
                    if path.suffix == ".md":
                        documents.append(path)
    for path in sorted(job.repository.glob("*.md")):
        entries = fences(path)
        if entries:
            inventory[path.name] = entries
            documents.append(path)
    save(job.reports / "documentation.json", inventory)
    return documents


def markdown(job, documents, externs, dependency_directories):
    suffix = ".exe" if os.name == "nt" else ""
    for index, path in enumerate(documents):
        command = [job.toolchain / "bin" / ("rustdoc" + suffix), "--test", "--edition=2021", "-Dwarnings"]
        # Cargo's directory layout is not a public API and differs by version.
        # Include the directories actually reported for transitive dependencies
        # and procedural macros, rather than assuming target/release/deps.
        for directory in sorted(dependency_directories):
            command += ["-L", "dependency=" + directory]
        for name in ("fe11", "fe11_sys", "fe11_verify_engine_api"):
            command += ["--extern", name + "=" + externs[name]]
        job.run(f"markdown-{index:03}", [*command, path])


def check(job):
    output = job.cargo("documentation-artifacts", "build", "--locked", "--release", "-p", "fe11",
                       "-p", "fe11-verify-engine-api", "--message-format=json")
    externs, directories = artifact_paths(output)
    documents = inventory(job)
    for package in ("fe11", "fe11-verify-engine-api"):
        job.cargo("doctest-" + package, "test", "--locked", "--release", "--doc", "-p", package)
    markdown(job, documents, externs, directories)
    job.cargo("api-reference", "doc", "--locked", "--release", "--no-deps", "-p", "fe11",
              "-p", "fe11-verify-engine-api", "-p", "fe11-verify-engine")
