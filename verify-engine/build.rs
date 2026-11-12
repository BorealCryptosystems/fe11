// SPDX-License-Identifier: Apache-2.0
//! Build constraints belong to this optional component, never its consumers.
//! Archive/header checks are prerequisites; final ELF/PE inspection must also
//! establish local binding and the absence of a shared OpenSSL dependency.
use std::{
    env, fs,
    path::{Path, PathBuf},
};

fn defines(header: &str, name: &str) -> bool {
    header.lines().any(|line| {
        let line = line.trim_start();
        let Some(directive) = line.strip_prefix('#') else {
            return false;
        };
        let mut tokens = directive.split_whitespace();
        tokens.next() == Some("define") && tokens.next() == Some(name)
    })
}

fn require_file(path: &Path) {
    assert!(
        path.is_file(),
        "required native build file missing: {}",
        path.display()
    );
    println!("cargo:rerun-if-changed={}", path.display());
}

fn main() {
    for name in [
        "OPENSSL_STATIC",
        "OPENSSL_DIR",
        "OPENSSL_NO_VENDOR",
        "OPENSSL_LIB_DIR",
        "OPENSSL_INCLUDE_DIR",
        "DEP_OPENSSL_INCLUDE",
        "DEP_OPENSSL_VERSION_NUMBER",
        "TARGET",
    ] {
        println!("cargo:rerun-if-env-changed={name}");
    }
    let target = env::var("TARGET").expect("Cargo target metadata");
    assert!(
        matches!(
            target.as_str(),
            "x86_64-unknown-linux-gnu" | "x86_64-pc-windows-msvc"
        ),
        "verify-engine packaging is defined for Linux GNU and Windows MSVC x86_64"
    );
    assert_eq!(
        env::var("OPENSSL_STATIC").as_deref(),
        Ok("1"),
        "the optional component requires its private static OpenSSL build"
    );
    assert_eq!(
        env::var("OPENSSL_NO_VENDOR").as_deref(),
        Ok("1"),
        "select an explicit inventoried OpenSSL installation"
    );
    let prefix = PathBuf::from(env::var_os("OPENSSL_DIR").expect("explicit OpenSSL prefix"));
    assert!(prefix.is_absolute(), "OpenSSL prefix must be absolute");
    let include =
        PathBuf::from(env::var_os("DEP_OPENSSL_INCLUDE").expect("binding include metadata"));
    assert_eq!(
        include.canonicalize().expect("binding include directory"),
        prefix
            .join("include")
            .canonicalize()
            .expect("selected include directory"),
        "binding headers must belong to the selected native build"
    );
    let version = env::var("DEP_OPENSSL_VERSION_NUMBER").expect("native version metadata");
    let version = u64::from_str_radix(version.trim_start_matches("0x"), 16)
        .expect("hexadecimal OpenSSL version metadata");
    assert!(
        version >= 0x3050_0000 && version < 0x4000_0000,
        "the engine requires the OpenSSL 3.5+ API within major version 3"
    );
    let config = include.join("openssl/configuration.h");
    require_file(&config);
    let header = fs::read_to_string(&config).expect("native configuration header");
    for required in ["OPENSSL_NO_ENGINE", "OPENSSL_NO_AUTOLOAD_CONFIG"] {
        assert!(
            defines(&header, required),
            "native configuration must define {required}"
        );
    }
    // openssl-sys links both archives. They must resolve from this explicit build,
    // even though the component only calls libcrypto's public API.
    let lib = env::var_os("OPENSSL_LIB_DIR")
        .map(PathBuf::from)
        .unwrap_or_else(|| prefix.join("lib"));
    assert!(
        lib.is_absolute(),
        "OpenSSL archive directory must be absolute"
    );
    let selected = lib.canonicalize().expect("selected archive directory");
    let prefix = prefix.canonicalize().expect("selected OpenSSL prefix");
    assert!(
        selected.starts_with(&prefix),
        "archives must belong to the selected native build"
    );
    let archives = if target.ends_with("msvc") {
        ["libcrypto.lib", "libssl.lib"]
    } else {
        ["libcrypto.a", "libssl.a"]
    };
    for archive in archives {
        require_file(&selected.join(archive));
    }
    if target.ends_with("linux-gnu") {
        // Scoped to this cdylib. Hiding exports alone cannot prevent symbol
        // preemption by libcrypto already loaded in the hosting application.
        println!("cargo:rustc-link-arg-cdylib=-Wl,--exclude-libs,ALL");
        println!("cargo:rustc-link-arg-cdylib=-Wl,-Bsymbolic");
    }
}
