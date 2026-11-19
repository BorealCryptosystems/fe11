// SPDX-License-Identifier: Apache-2.0
//! Both recovery initializers receive real RSA keys and preserve native refusal.
use super::super::{
    arguments::hex,
    object_owner::Owner,
    outcome::{self, Failure},
    report::{Phase, Producer, Report},
    single_key_case::SingleKeyCase,
};
use fe11::*;
use std::{
    fs::File,
    io::{Read, Write},
    path::Path,
};

pub(super) fn selected(path: &Path) -> bool {
    let mut prefix = [0; 13];
    File::open(path)
        .and_then(|mut file| file.read_exact(&mut prefix))
        .is_ok()
        && &prefix == b"recover-init\n"
}

pub(super) struct Case {
    advanced: bool,
    sign: bool,
    key: Vec<Vec<u8>>,
    message: Vec<u8>,
    signature: Vec<u8>,
}

impl SingleKeyCase for Case {
    const ASSERTION: &'static str = "recover_init_native_refusal";
    const PRODUCER: Producer = Producer::TestOracle;
    fn read(path: &Path) -> std::result::Result<Self, Failure> {
        let mut bytes = Vec::new();
        File::open(path)
            .map_err(|_| Failure::Input("recover_init_open"))?
            .take(8193)
            .read_to_end(&mut bytes)
            .map_err(|_| Failure::Input("recover_init_read"))?;
        if bytes.len() > 8192 {
            return Err(Failure::Input("recover_init_size"));
        }
        let text =
            std::str::from_utf8(&bytes).map_err(|_| Failure::Input("recover_init_encoding"))?;
        let f: Vec<_> = text.split_terminator('\n').collect();
        if f.len() != 13
            || f[0] != "recover-init"
            || !matches!(f[1], "session" | "advanced")
            || !matches!(f[2], "sign" | "verify")
        {
            return Err(Failure::Input("recover_init_fields"));
        }
        let key = f[3..11]
            .iter()
            .map(|value| hex(value, 256).map_err(Failure::Input))
            .collect::<std::result::Result<Vec<_>, _>>()?;
        let message = hex(f[11], 245).map_err(Failure::Input)?;
        let signature = hex(f[12], 256).map_err(Failure::Input)?;
        if key.iter().any(Vec::is_empty) || key[0].len() != 256 || signature.len() != 256 {
            return Err(Failure::Input("recover_init_dimensions"));
        }
        Ok(Self {
            advanced: f[1] == "advanced",
            sign: f[2] == "sign",
            key,
            message,
            signature,
        })
    }
    fn advanced(&self) -> bool {
        self.advanced
    }
    fn import(&self, owner: &Owner) -> std::result::Result<NativeObjectRef, Failure> {
        Ok(if self.sign {
            owner.import_rsa_private(&self.key, StandardAttribute::SIGN_RECOVER)?
        } else {
            owner.import_rsa_public_usage(
                &self.key[0],
                &self.key[1],
                StandardAttribute::VERIFY_RECOVER,
            )?
        })
    }
    fn check<W: Write>(
        &self,
        owner: &Owner,
        key: &NativeObjectRef,
        report: &mut Report<W>,
    ) -> std::result::Result<(), Failure> {
        let parameters =
            || NativeSignatureParameters::Parameterless(NativeSignatureAlgorithm::RSA_PKCS);
        let input = if self.sign {
            self.message.as_slice()
        } else {
            self.signature.as_slice()
        };
        let limits = InputLimits {
            maximum_parts: 1,
            maximum_total_bytes: input.len(),
        };
        let result = match (owner, self.sign) {
            (Owner::Session(s), true) => s
                .sign_native_recover(key, parameters(), input, limits, 256, None)
                .map(|_| ()),
            (Owner::Advanced(s), true) => s
                .sign_native_recover(key, parameters(), input, limits, 256, None)
                .map(|_| ()),
            (Owner::Session(s), false) => s
                .verify_native_recover(key, parameters(), input, limits, 256, None)
                .map(|_| ()),
            (Owner::Advanced(s), false) => s
                .verify_native_recover(key, parameters(), input, limits, 256, None)
                .map(|_| ()),
        };
        let expected = if self.sign {
            "C_SignRecoverInit"
        } else {
            "C_VerifyRecoverInit"
        };
        match result {
            Err(
                error @ Error::Native {
                    function,
                    code: 84,
                    may_have_effect: false,
                },
            ) if function == expected => {
                outcome::record(report, Phase::Body, &Failure::Product(error))
                    .map_err(|_| Failure::Input("report_write"))?;
                Ok(())
            }
            Err(error) => Err(error.into()),
            Ok(()) => Err(Failure::Oracle("recover_init_unexpected_success")),
        }
    }
}
