# SPDX-License-Identifier: Apache-2.0
"""Build the pinned SoftHSM native dependencies; qualification is a separate step."""
from pathlib import Path
import argparse
import json
from recipe_support import Build, digest, extract

OPENSSL_SHA = "603f5602e2eef00d77fbd429d34dcd5822bb301757a1bc9cdb24c670f1eb859a"
SQLITE_SHA3 = "b6ced585c750916b1052667239a12c25a7ff34e7f06e1e6e01ecb0427657d9c4"
SOFTHSM_SHA = "4a13de4512cbfcc29b6cc674f2f5f56972ab82c4081e8d25c486c96792718ee8"
GOST_SHA = "71c329a31646f4308a7b20ee4cd6192027730a754cd81cca3a724f5bf471363f"
LIBPROV_SHA = "8514c1b4b1f88242c487d2afce4f1d8953f94294f37bfbf029c9b43175030666"


def build_dependencies(job):
    sqlite = job.root / "sources/sqlite"
    extract(job.input("sqlite.tar.gz", SQLITE_SHA3, "sha3_256"), sqlite)
    sqlite_prefix = job.root / "prefix/sqlite"
    job.run("sqlite-configure", [sqlite / "configure", "--prefix=" + str(sqlite_prefix),
                                 "--enable-shared"], cwd=sqlite)
    job.run("sqlite-build", ["make", "-j2"], cwd=sqlite)
    job.run("sqlite-install", ["make", "install"], cwd=sqlite)
    job.run("sqlite-version", [sqlite_prefix / "bin/sqlite3", "--version"])

    openssl = job.root / "sources/openssl"
    extract(job.input("openssl.tar.gz", OPENSSL_SHA), openssl)
    prefix = job.root / "prefix/openssl"
    job.run("openssl-configure", ["perl", openssl / "Configure", "linux-x86_64", "shared",
                                  "enable-legacy", "--prefix=" + str(prefix),
                                  "--openssldir=" + str(prefix / "ssl"), "--libdir=lib"], cwd=openssl)
    job.run("openssl-build", ["make", "-j2"], cwd=openssl)
    job.run("openssl-install", ["make", "install_sw"], cwd=openssl)
    environment = dict(job.env, LD_LIBRARY_PATH=str(prefix / "lib") + ":" + str(sqlite_prefix / "lib"),
                       OPENSSL_MODULES=str(prefix / "lib/ossl-modules"),
                       OPENSSL_ENGINES=str(job.root / "prefix/gost/lib/engines"),
                       PKG_CONFIG_PATH=str(prefix / "lib/pkgconfig") + ":" + str(sqlite_prefix / "lib/pkgconfig"))
    config = job.root / "openssl-full.cnf"
    config.write_text("openssl_conf = openssl_init\n[openssl_init]\nproviders = providers\n"
                      "[providers]\ndefault = default_provider\nlegacy = legacy_provider\n"
                      "[default_provider]\nactivate = 1\n[legacy_provider]\nactivate = 1\n")
    environment["OPENSSL_CONF"] = str(config)
    job.run("openssl-version", [prefix / "bin/openssl", "version", "-a"], env=environment)
    job.run("openssl-providers", [prefix / "bin/openssl", "list", "-providers"], env=environment)
    job.run("openssl-digests", [prefix / "bin/openssl", "list", "-digest-algorithms"], env=environment)
    job.run("openssl-signatures", [prefix / "bin/openssl", "list", "-signature-algorithms"], env=environment)
    return environment


def build_gost(job, environment):
    source = job.root / "sources/gost"
    extract(job.input("gost.tar.gz", GOST_SHA), source)
    submodule = source / "libprov"
    # A Git archive contains only an empty directory for the submodule.
    if submodule.is_dir() and not any(submodule.iterdir()):
        submodule.rmdir()
    extract(job.input("libprov.tar.gz", LIBPROV_SHA), submodule)
    build = job.root / "gost-build"
    prefix = job.root / "prefix/gost"
    job.run("gost-configure", ["cmake", "-S", source, "-B", build,
                              "-DCMAKE_BUILD_TYPE=Release", "-DCMAKE_INSTALL_PREFIX=" + str(prefix),
                              "-DOPENSSL_ROOT_DIR=" + str(job.root / "prefix/openssl"),
                              "-DOPENSSL_ENGINES_DIR=" + str(prefix / "lib/engines"),
                              "-DGOST_BUILD_ENGINE=ON"], env=environment)
    job.run("gost-build", ["cmake", "--build", build, "--parallel", "2"], env=environment)
    job.run("gost-install", ["cmake", "--install", build], env=environment)
    engines = list((prefix / "lib/engines").glob("gost.so"))
    if len(engines) != 1:
        raise ValueError("expected exactly one installed GOST engine")
    config = job.root / "openssl-gost.cnf"
    full = (job.root / "openssl-full.cnf").read_text()
    full = full.replace("providers = providers\n", "providers = providers\nengines = engines\n")
    config.write_text(full + "[engines]\ngost = gost_engine\n[gost_engine]\nengine_id = gost\n"
                      "dynamic_path = " + str(engines[0]) + "\ninit = 1\ndefault_algorithms = ALL\n")
    gost_env = dict(environment, OPENSSL_CONF=str(config))
    job.run("gost-engine-capabilities", [job.root / "prefix/openssl/bin/openssl", "engine", "-t", "-c", "gost"], env=gost_env)
    return gost_env


def build_module(job, name, environment, source_suffix=""):
    if name not in ("full", "gost") or source_suffix not in ("", "-official"):
        raise ValueError("unsupported build variant")
    source = job.root / ("sources/softhsm-" + name + source_suffix)
    extract(job.input("softhsm.tar.gz", SOFTHSM_SHA), source)
    prefix = job.root / ("prefix/softhsm-" + name)
    job.run(name + "-autogen", ["sh", source / "autogen.sh"], cwd=source, env=environment)
    switches = ["--prefix=" + str(prefix), "--with-crypto-backend=openssl",
                "--with-openssl=" + str(job.root / "prefix/openssl"), "--disable-p11-kit",
                "--enable-ecc", "--enable-eddsa", "--enable-sha3", "--enable-mldsa",
                "--enable-slhdsa", "--enable-mlkem", "--disable-fips",
                "--with-objectstore-backend-db", "--with-sqlite3=" + str(job.root / "prefix/sqlite")]
    switches += (["--enable-gost", "--enable-openssl-engines"] if name == "gost"
                 else ["--disable-gost", "--disable-openssl-engines"])
    job.run(name + "-configure", [source / "configure", *switches], cwd=source, env=environment)
    job.run(name + "-build", ["make", "-j2"], cwd=source, env=environment)
    job.run(name + "-install", ["make", "install"], cwd=source, env=environment)
    modules = list(prefix.rglob("libsofthsm2.so"))
    images = {p.resolve() for p in modules}
    if len(images) != 1:
        raise ValueError("unexpected number of SoftHSM module images")
    module = images.pop()
    job.run(name + "-dependencies", ["ldd", module], env=environment)
    configuration = {key: environment[key] for key in
                     ("LD_LIBRARY_PATH", "OPENSSL_CONF", "OPENSSL_MODULES", "OPENSSL_ENGINES", "PKG_CONFIG_PATH")}
    return dict(module=str(module), sha256=digest(module), environment=configuration,
                status="BUILT_AWAITING_RECIPE_QUALIFICATION")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", required=True, type=Path)
    parser.add_argument("--inputs", required=True, type=Path)
    args = parser.parse_args()
    job = Build(args.root, args.inputs)
    environment = build_dependencies(job)
    gost = build_gost(job, environment)
    recipes = {"openssl-full": build_module(job, "full", environment),
               "openssl-gost": build_module(job, "gost", gost)}
    (job.root / "recipes.json").write_text(json.dumps(recipes, indent=2) + "\n")


if __name__ == "__main__":
    main()
