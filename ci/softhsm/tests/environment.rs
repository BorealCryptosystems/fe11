// SPDX-License-Identifier: Apache-2.0
//! One filesystem token per child, with independent ephemeral administrative PINs.
use crate::report::{Cause, Failure};
use std::{
    fs,
    io::{Read, Write},
    os::unix::fs::{DirBuilderExt, OpenOptionsExt},
    path::PathBuf,
    process::{Command, Stdio},
};

pub struct Environment {
    pub module: PathBuf,
    pub digest: [u8; 32],
    pub label: String,
    pub user_pin: Vec<u8>,
}

fn random_hex() -> Result<String, Failure> {
    let mut bytes = [0u8; 16];
    fs::File::open("/dev/urandom")
        .and_then(|mut f| f.read_exact(&mut bytes))
        .map_err(|_| Failure::new(Cause::Setup))?;
    Ok(bytes.iter().map(|b| format!("{b:02x}")).collect())
}

impl Environment {
    pub fn prepare(id: &str) -> Result<Self, Failure> {
        let setup = || Failure::new(Cause::Setup);
        let root = PathBuf::from(std::env::var_os("FE11_CI_ROOT").ok_or_else(setup)?);
        let directory = root.join(id);
        if !root.is_absolute() || directory.exists() {
            return Err(setup());
        }
        fs::DirBuilder::new()
            .mode(0o700)
            .create(&directory)
            .map_err(|_| setup())?;
        let tokens = directory.join("tokens");
        fs::DirBuilder::new()
            .mode(0o700)
            .create(&tokens)
            .map_err(|_| setup())?;
        let token_path = tokens.to_str().ok_or_else(setup)?;
        if token_path.contains(['\r', '\n']) {
            return Err(setup());
        }
        let config = directory.join("softhsm.conf");
        let mut file = fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(&config)
            .map_err(|_| setup())?;
        write!(file, "directories.tokendir = {token_path}\nobjectstore.backend = file\nlog.level = ERROR\nslots.removable = false\n")
            .map_err(|_| setup())?;
        let user = random_hex()?;
        let so = random_hex()?;
        if user == so {
            return Err(setup());
        }
        if std::env::var("GITHUB_ACTIONS").as_deref() == Ok("true") {
            println!("::add-mask::{user}");
            println!("::add-mask::{so}");
            std::io::stdout().flush().map_err(|_| setup())?;
        }
        let label = format!("fe11-{}", &random_hex()?[..20]);
        let utility = std::env::var_os("FE11_CI_SOFTHSM_UTIL").ok_or_else(setup)?;
        // No shell and no command echo: arguments contain ephemeral PINs.
        let status = Command::new(utility)
            .args([
                "--init-token",
                "--free",
                "--label",
                &label,
                "--so-pin",
                &so,
                "--pin",
                &user,
            ])
            .env("SOFTHSM2_CONF", &config)
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status()
            .map_err(|_| setup())?;
        if !status.success() {
            return Err(setup());
        }
        // This child is single-threaded; set the module configuration before loading it.
        std::env::set_var("SOFTHSM2_CONF", config);
        let module = PathBuf::from(std::env::var_os("FE11_CI_MODULE").ok_or_else(setup)?);
        let encoded = std::env::var("FE11_CI_MODULE_SHA256").map_err(|_| setup())?;
        if encoded.len() != 64 || !encoded.bytes().all(|b| b.is_ascii_hexdigit()) {
            return Err(setup());
        }
        let mut digest = [0; 32];
        for (i, b) in digest.iter_mut().enumerate() {
            *b = u8::from_str_radix(&encoded[i * 2..i * 2 + 2], 16).map_err(|_| setup())?;
        }
        Ok(Self {
            module,
            digest,
            label,
            user_pin: user.into_bytes(),
        })
    }
}
