// SPDX-License-Identifier: Apache-2.0
//! Fixed, bounded output vocabulary. No secret or free-form native diagnostic.
use std::{fs, io::Read, path::Path};

pub const SCENARIOS: [&str; 10] = [
    "discovery",
    "authentication",
    "invalid_pin",
    "digest_single",
    "digest_multipart",
    "rsa_sign_verify",
    "invalid_signature",
    "aes_gcm",
    "invalid_gcm_tag",
    "object_search",
];
pub const HEADER: &str = "scenario\tstatus\tcause\tnative_code\tcleanup\tcleanup_native_code\n";

#[derive(Clone, Copy)]
pub enum Cause {
    Native,
    Local,
    Assertion,
    Setup,
    Prerequisite,
    Panic,
}
impl Cause {
    fn as_str(self) -> &'static str {
        match self {
            Self::Native => "native_error",
            Self::Local => "local_error",
            Self::Assertion => "assertion",
            Self::Setup => "setup",
            Self::Prerequisite => "prerequisite",
            Self::Panic => "panic",
        }
    }
}

#[derive(Clone, Copy)]
pub struct Failure {
    pub kind: Cause,
    pub code: Option<u64>,
}
impl Failure {
    pub fn new(kind: Cause) -> Self {
        Self { kind, code: None }
    }
}
impl From<fe11::Error> for Failure {
    fn from(error: fe11::Error) -> Self {
        // Fe11's public Error contract contains static categories and public
        // status codes, never PINs, key bytes or native attribute contents.
        // Keep this diagnostic separate from the bounded verdict channel.
        eprintln!("fe11_error: {error}");
        match error {
            fe11::Error::Native { code, .. } => Self {
                kind: Cause::Native,
                code: Some(code),
            },
            _ => Self::new(Cause::Local),
        }
    }
}
pub type Outcome = Result<(), Failure>;

pub fn require(condition: bool) -> Outcome {
    if condition {
        Ok(())
    } else {
        Err(Failure::new(Cause::Assertion))
    }
}

pub fn encode(id: &str, operation: Outcome, cleanup: Outcome) -> String {
    let code = |failure: Option<Failure>| {
        failure
            .and_then(|f| f.code)
            .map_or_else(|| "-".to_owned(), |n| format!("0x{n:x}"))
    };
    let failure = operation.err();
    format!(
        "{}\t{}\t{}\t{}\t{}\t{}\n",
        id,
        if operation.is_ok() && cleanup.is_ok() {
            "PASS"
        } else {
            "FAIL"
        },
        failure.map_or("none", |f| f.kind.as_str()),
        code(failure),
        if cleanup.is_ok() { "PASS" } else { "FAIL" },
        code(cleanup.err())
    )
}

pub fn read(path: &Path, expected: &str) -> Result<String, ()> {
    let file = fs::File::open(path).map_err(|_| ())?;
    let mut data = Vec::new();
    file.take(257).read_to_end(&mut data).map_err(|_| ())?;
    if data.len() > 256 {
        return Err(());
    }
    let text = String::from_utf8(data).map_err(|_| ())?;
    if !text.ends_with('\n') || text.matches('\n').count() != 1 {
        return Err(());
    }
    let fields: Vec<_> = text.trim_end_matches('\n').split('\t').collect();
    if fields.len() != 6 || fields[0] != expected {
        return Err(());
    }
    if !["PASS", "FAIL"].contains(&fields[1]) || !["PASS", "FAIL"].contains(&fields[4]) {
        return Err(());
    }
    if ![
        "none",
        "native_error",
        "local_error",
        "assertion",
        "setup",
        "prerequisite",
        "panic",
    ]
    .contains(&fields[2])
    {
        return Err(());
    }
    for code in [fields[3], fields[5]] {
        if code != "-" {
            let digits = code.strip_prefix("0x").ok_or(())?;
            if digits.is_empty()
                || digits.len() > 16
                || !digits.bytes().all(|b| b.is_ascii_hexdigit())
            {
                return Err(());
            }
        }
    }
    if fields[1] == "PASS"
        && (fields[2] != "none" || fields[3] != "-" || fields[4] != "PASS" || fields[5] != "-")
    {
        return Err(());
    }
    Ok(text)
}
