# SPDX-License-Identifier: Apache-2.0
"""Platform-specific static engine recipe and inspection of its actual binary."""
from pathlib import Path
import os
import re
import shutil
import subprocess
from common import digest, extract, save

OPENSSL_URL = "https://github.com/openssl/openssl/releases/download/openssl-3.5.9/openssl-3.5.9.tar.gz"
OPENSSL_SHA = "603f5602e2eef00d77fbd429d34dcd5822bb301757a1bc9cdb24c670f1eb859a"


def msvc(job):
    if os.name != "nt":
        return
    locator = Path(os.environ["ProgramFiles(x86)"]) / "Microsoft Visual Studio/Installer/vswhere.exe"
    installation = subprocess.check_output([str(locator), "-latest", "-products", "*", "-requires",
        "Microsoft.VisualStudio.Component.VC.Tools.x86.x64", "-property", "installationPath"], text=True).strip()
    script = Path(installation) / "VC/Auxiliary/Build/vcvars64.bat"
    if not script.is_file() or any(c in str(script) for c in '\r\n"'):
        raise ValueError("invalid MSVC installation")
    configured = subprocess.check_output('cmd.exe /d /s /c ""' + str(script) + '" >nul && set"', text=True)
    for line in configured.splitlines():
        key, separator, value = line.partition("=")
        if separator and key.upper() in ("PATH", "INCLUDE", "LIB", "LIBPATH", "VCTOOLSVERSION", "WINDOWSSDKVERSION"):
            job.env[key.upper()] = value


def build(job):
    prefix = job.root / "openssl"
    archive = job.root / "openssl.tar.gz"
    job.fetch(OPENSSL_URL, archive, OPENSSL_SHA)
    extracted = job.root / "openssl-source"
    extract(archive, extracted)
    source = extracted / "openssl-3.5.9"
    perl = shutil.which("perl", path=job.env["PATH"])
    if not perl:
        raise ValueError("Perl prerequisite missing")
    switches = ["no-shared", "no-engine", "no-autoload-config", "no-tests"]
    if os.name == "nt":
        switches += ["no-module", "no-asm"]
        make = shutil.which("nmake", path=job.env["PATH"])
        target = "VC-WIN64A"
    else:
        switches += ["-fPIC"]
        make = shutil.which("make", path=job.env["PATH"])
        target = "linux-x86_64"
    if not make:
        raise ValueError("native make prerequisite missing")
    tools = {}
    names = ["perl", "nmake", "cl", "link", "lib", "dumpbin"] if os.name == "nt" else ["perl", "make", "cc", "ld", "as", "ar", "ranlib", "readelf"]
    for name in names:
        path = shutil.which(name, path=job.env["PATH"])
        if not path:
            raise ValueError("native tool prerequisite missing: " + name)
        tools[name] = {"file": Path(path).name, "sha256": digest(path)}
        if os.name != "nt":
            option = "-v" if name == "perl" else "--version"
            text = subprocess.check_output([path, option], env=job.env, text=True)
            tools[name]["version"] = text.strip().splitlines()[0]
        else:
            probe = subprocess.run([path, "-v" if name == "perl" else "/?"],
                env=job.env, stdin=subprocess.DEVNULL, capture_output=True, text=True,
                timeout=3600 if job.github else job.remaining())
            lines = [line.strip() for line in (probe.stdout + probe.stderr).splitlines() if line.strip()]
            if not lines:
                raise ValueError("native tool version unavailable: " + name)
            tools[name]["version"] = lines[0]
    job.run("openssl-configure", [perl, "Configure", target, *switches,
        "--prefix=" + str(prefix), "--openssldir=" + str(prefix / "ssl"), "--libdir=lib"], cwd=source)
    job.run("openssl-build", [make, *( ["/nologo"] if os.name == "nt" else ["-j2"] ), "build_libs"], cwd=source)
    job.run("openssl-install", [make, "install_dev"], cwd=source)
    job.env.update(OPENSSL_DIR=str(prefix), OPENSSL_LIB_DIR=str(prefix / "lib"),
                   OPENSSL_INCLUDE_DIR=str(prefix / "include"), OPENSSL_STATIC="1", OPENSSL_NO_VENDOR="1")
    headers = prefix / "include/openssl"
    if '"3.5.9"' not in (headers / "opensslv.h").read_text():
        raise ValueError("wrong OpenSSL headers")
    receipt = {"source_url": OPENSSL_URL, "source_sha256": OPENSSL_SHA, "version": "3.5.9",
        "target": target, "options": switches, "tools": tools,
        "sdk": job.env.get("WINDOWSSDKVERSION"), "msvc": job.env.get("VCTOOLSVERSION"),
        "files": {p.relative_to(prefix).as_posix(): digest(p) for p in prefix.rglob("*")
                  if p.is_file() and (p.suffix in (".a", ".lib") or p.name in ("opensslv.h", "configuration.h"))}}
    save(job.reports / "native.json", receipt)


def inspect(job):
    release = job.root / "target/release"
    if os.name == "nt":
        binary = release / "fe11_verify_engine.dll"
        tool = shutil.which("dumpbin", path=job.env["PATH"])
        texts = [subprocess.check_output([tool, flag, str(binary)], env=job.env, text=True)
                 for flag in ("/dependents", "/imports", "/exports")]
        if any(word in (texts[0] + texts[1]).lower() for word in ("libcrypto", "libssl")):
            raise ValueError("shared OpenSSL import")
        exports = re.findall(r"^\s+\d+\s+[0-9a-f]+\s+[0-9a-f]+\s+(\S+)", texts[2], re.I | re.M)
    else:
        binary = release / "libfe11_verify_engine.so"
        texts = [subprocess.check_output(["readelf", option, "--wide", str(binary)], env=job.env, text=True)
                 for option in ("-d", "--dyn-syms", "--syms")]
        if any(word in texts[0].lower() for word in ("libcrypto", "libssl")):
            raise ValueError("shared OpenSSL dependency")
        if "(SYMBOLIC)" not in texts[0] and not re.search(r"\(FLAGS\).*\bSYMBOLIC\b", texts[0]):
            raise ValueError("symbolic binding missing")
        entries = [line.split() for line in texts[1].splitlines() if re.match(r"^\s*\d+:", line)]
        exports = [entry[-1] for entry in entries if entry[4] in ("GLOBAL", "WEAK") and entry[6] != "UND"]
        for name in ("EVP_DigestVerify", "EVP_MD_fetch", "d2i_PUBKEY_ex"):
            if not re.search(r"FUNC\s+LOCAL\s+DEFAULT\s+\d+\s+" + name + r"\s*$", texts[2], re.M):
                raise ValueError("nonlocal OpenSSL symbol: " + name)
    if exports != ["Fe11_VerifyEngine_GetInterface"]:
        raise ValueError("unexpected engine export")
    # Full dumps can contain build paths. Publish properties and hashes, not dumps.
    save(job.reports / "native-inspection.json", {"binary_sha256": digest(binary), "exports": exports,
        "shared_openssl": False, "native_symbol_isolation": "PASS"})
