// SPDX-License-Identifier: Apache-2.0
//! Explicit native session states and bounded authentication transition fixtures.
use super::outcome::Failure;
use fe11_sys::*;
use std::{fs::File, io::Read, path::Path};

pub struct Case {
    pub before: u64,
    pub after: u64,
    pub action: String,
    pub expected: u64,
}

pub fn state(value: &str) -> Result<u64, Failure> {
    Ok(match value {
        "RO_PUBLIC" => CKS_RO_PUBLIC_SESSION,
        "RO_USER" => CKS_RO_USER_FUNCTIONS,
        "RW_PUBLIC" => CKS_RW_PUBLIC_SESSION,
        "RW_USER" => CKS_RW_USER_FUNCTIONS,
        "RW_SO" => CKS_RW_SO_FUNCTIONS,
        _ => return Err(Failure::Input("authentication_state")),
    } as u64)
}

impl Case {
    pub fn read(path: &Path) -> Result<Self, Failure> {
        let mut bytes = Vec::new();
        File::open(path)
            .map_err(|_| Failure::Input("fixture_open"))?
            .take(1025)
            .read_to_end(&mut bytes)
            .map_err(|_| Failure::Input("fixture_read"))?;
        if bytes.len() > 1024 {
            return Err(Failure::Input("fixture_size"));
        }
        let text = std::str::from_utf8(&bytes).map_err(|_| Failure::Input("fixture_encoding"))?;
        let f: Vec<_> = text.split_terminator('\n').collect();
        if f.len() != 4
            || !matches!(
                f[1],
                "login_user"
                    | "login_so"
                    | "login_user_wrong_pin"
                    | "login_so_with_ro_peer"
                    | "login_named_empty"
                    | "login_named_ascii"
                    | "login_named_utf8"
                    | "login_named_wrong_pin"
                    | "logout"
                    | "open_ro"
                    | "open_rw"
                    | "close_last"
                    | "close_with_peer"
                    | "create_public_session"
                    | "create_private_session"
                    | "create_public_token"
                    | "create_private_token"
                    | "set_pin"
                    | "init_pin"
            )
        {
            return Err(Failure::Input("authentication_fields"));
        }
        let expected = match f[3] {
            "CKR_OK" => CKR_OK,
            "CKR_PIN_INCORRECT" => CKR_PIN_INCORRECT,
            "CKR_SESSION_READ_ONLY_EXISTS" => CKR_SESSION_READ_ONLY_EXISTS,
            "CKR_USER_NOT_LOGGED_IN" => CKR_USER_NOT_LOGGED_IN,
            "CKR_SESSION_READ_ONLY" => CKR_SESSION_READ_ONLY,
            "CKR_USER_ALREADY_LOGGED_IN" => CKR_USER_ALREADY_LOGGED_IN,
            "CKR_USER_ANOTHER_ALREADY_LOGGED_IN" => CKR_USER_ANOTHER_ALREADY_LOGGED_IN,
            "CKR_SESSION_READ_WRITE_SO_EXISTS" => CKR_SESSION_READ_WRITE_SO_EXISTS,
            _ => return Err(Failure::Input("authentication_expected_code")),
        } as u64;
        Ok(Self {
            before: state(f[0])?,
            after: state(f[2])?,
            action: f[1].into(),
            expected,
        })
    }

    pub fn writable(&self) -> bool {
        matches!(self.before, value if value == CKS_RW_PUBLIC_SESSION as u64
            || value == CKS_RW_USER_FUNCTIONS as u64 || value == CKS_RW_SO_FUNCTIONS as u64)
    }

    pub fn function(&self) -> &'static str {
        match self.action.as_str() {
            "login_user" | "login_so" | "login_user_wrong_pin" | "login_so_with_ro_peer" => {
                "C_Login"
            }
            "login_named_empty"
            | "login_named_ascii"
            | "login_named_utf8"
            | "login_named_wrong_pin" => "C_LoginUser",
            "logout" => "C_Logout",
            "open_ro" | "open_rw" => "C_OpenSession",
            "close_last" | "close_with_peer" => "C_CloseSession",
            "set_pin" => "C_SetPIN",
            "init_pin" => "C_InitPIN",
            _ => "C_CreateObject",
        }
    }
}
