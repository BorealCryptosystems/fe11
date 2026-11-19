// SPDX-License-Identifier: Apache-2.0
//! Shared checks for real-module preparation controls; no Fe11 test credit.
use super::{configuration::Configuration, outcome::Failure};
use fe11_sys::*;
use sha2::{Digest, Sha256};
use std::{fs::File, io::Read};

pub(super) fn status(function: &'static str, value: CK_RV) -> std::result::Result<(), Failure> {
    if value == CKR_OK {
        Ok(())
    } else {
        // The probe does not have Fe11's effect classifier. Record the exact
        // return separately instead of inventing an API may_have_effect value.
        Err(Failure::DirectNative {
            function,
            code: value as u64,
        })
    }
}

pub(super) fn required<T: Copy>(entry: Option<T>) -> std::result::Result<T, Failure> {
    entry.ok_or(Failure::Input("direct_function_absent"))
}

pub(super) fn verify_image(config: &Configuration) -> std::result::Result<(), Failure> {
    let mut source = File::open(&config.module).map_err(|_| Failure::Input("direct_image_open"))?;
    let mut digest = Sha256::new();
    let mut block = [0u8; 65536];
    loop {
        let count = source
            .read(&mut block)
            .map_err(|_| Failure::Input("direct_image_read"))?;
        if count == 0 {
            break;
        }
        digest.update(&block[..count]);
    }
    let actual: [u8; 32] = digest.finalize().into();
    if actual != config.module_sha256 {
        return Err(Failure::Input("direct_image_digest"));
    }
    Ok(())
}
