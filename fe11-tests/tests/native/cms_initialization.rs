// SPDX-License-Identifier: Apache-2.0
//! Unsupported CMS entry points are distinguished from content decoding errors.
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
    let mut prefix = [0; b"cms-init\n".len()];
    File::open(path)
        .and_then(|mut f| f.read_exact(&mut prefix))
        .is_ok()
        && prefix.as_slice() == b"cms-init\n"
}

pub(super) struct Case {
    advanced: bool,
    sign: bool,
    recover: bool,
    key: Vec<Vec<u8>>,
    message: Vec<u8>,
    signature: Vec<u8>,
}

fn parameters() -> NativeCmsParameters<'static> {
    NativeCmsParameters {
        certificate: None,
        signing: NativeNestedMechanism::Signature(NativeSignatureParameters::Parameterless(
            NativeSignatureAlgorithm::SHA256_RSA_PKCS,
        )),
        digest: Some(NativeNestedMechanism::Digest(NativeDigestAlgorithm::Sha256)),
        content_type: None,
        requested_attributes: None,
        required_attributes: None,
    }
}

impl SingleKeyCase for Case {
    const ASSERTION: &'static str = "cms_initializer_exact_native_refusal";
    const PRODUCER: Producer = Producer::TestOracle;
    fn read(path: &Path) -> std::result::Result<Self, Failure> {
        let mut data = Vec::new();
        File::open(path)
            .map_err(|_| Failure::Input("cms_fixture_open"))?
            .take(8193)
            .read_to_end(&mut data)
            .map_err(|_| Failure::Input("cms_fixture_read"))?;
        if data.len() > 8192 {
            return Err(Failure::Input("cms_fixture_size"));
        }
        let text = std::str::from_utf8(&data).map_err(|_| Failure::Input("cms_fixture_utf8"))?;
        let fields: Vec<_> = text.split_terminator('\n').collect();
        if fields.len() != 13
            || fields[0] != "cms-init"
            || !matches!(fields[1], "session" | "advanced")
            || !matches!(
                fields[2],
                "sign" | "verify" | "sign-recover" | "verify-recover"
            )
        {
            return Err(Failure::Input("cms_fixture_fields"));
        }
        let key = fields[3..11]
            .iter()
            .map(|v| hex(v, 256).map_err(Failure::Input))
            .collect::<std::result::Result<Vec<_>, _>>()?;
        let message = hex(fields[11], 245).map_err(Failure::Input)?;
        let signature = hex(fields[12], 256).map_err(Failure::Input)?;
        if key.iter().any(Vec::is_empty) || key[0].len() != 256 || signature.len() != 256 {
            return Err(Failure::Input("cms_fixture_dimensions"));
        }
        Ok(Self {
            advanced: fields[1] == "advanced",
            sign: fields[2].starts_with("sign"),
            recover: fields[2].ends_with("recover"),
            key,
            message,
            signature,
        })
    }
    fn advanced(&self) -> bool {
        self.advanced
    }
    fn import(&self, owner: &Owner) -> std::result::Result<NativeObjectRef, Failure> {
        let usage = match (self.sign, self.recover) {
            (true, false) => StandardAttribute::SIGN,
            (true, true) => StandardAttribute::SIGN_RECOVER,
            (false, false) => StandardAttribute::VERIFY,
            (false, true) => StandardAttribute::VERIFY_RECOVER,
        };
        Ok(if self.sign {
            owner.import_rsa_private(&self.key, usage)?
        } else {
            owner.import_rsa_public_usage(&self.key[0], &self.key[1], usage)?
        })
    }
    fn check<W: Write>(
        &self,
        owner: &Owner,
        key: &NativeObjectRef,
        report: &mut Report<W>,
    ) -> std::result::Result<(), Failure> {
        let limits = InputLimits {
            maximum_parts: 1,
            maximum_total_bytes: if self.recover && !self.sign {
                self.signature.len()
            } else {
                self.message.len()
            },
        };
        let parts = [self.message.as_slice()];
        // The expected refusal is at Init, before any message/signature bytes
        // are submitted. This is not a CMS encoding or signature-validity test.
        let result = match (owner, self.sign, self.recover) {
            (Owner::Session(s), true, false) => s
                .sign_native_cms(
                    key,
                    parameters(),
                    MessageRoute::Single,
                    &parts,
                    limits,
                    4096,
                    None,
                )
                .map(|_| ()),
            (Owner::Advanced(s), true, false) => s
                .sign_native_cms(
                    key,
                    parameters(),
                    MessageRoute::Single,
                    &parts,
                    limits,
                    4096,
                    None,
                )
                .map(|_| ()),
            (Owner::Session(s), false, false) => s.verify_native_cms(
                key,
                parameters(),
                MessageRoute::Single,
                &parts,
                &self.signature,
                limits,
            ),
            (Owner::Advanced(s), false, false) => s.verify_native_cms(
                key,
                parameters(),
                MessageRoute::Single,
                &parts,
                &self.signature,
                limits,
            ),
            (Owner::Session(s), true, true) => s
                .sign_native_cms_recover(key, parameters(), &self.message, limits, 4096, None)
                .map(|_| ()),
            (Owner::Advanced(s), true, true) => s
                .sign_native_cms_recover(key, parameters(), &self.message, limits, 4096, None)
                .map(|_| ()),
            (Owner::Session(s), false, true) => s
                .verify_native_cms_recover(key, parameters(), &self.signature, limits, 4096)
                .map(|_| ()),
            (Owner::Advanced(s), false, true) => s
                .verify_native_cms_recover(key, parameters(), &self.signature, limits, 4096)
                .map(|_| ()),
        };
        let function = match (self.sign, self.recover) {
            (true, false) => "C_SignInit",
            (false, false) => "C_VerifyInit",
            (true, true) => "C_SignRecoverInit",
            (false, true) => "C_VerifyRecoverInit",
        };
        let expected = if self.recover {
            fe11_sys::CKR_FUNCTION_NOT_SUPPORTED
        } else {
            fe11_sys::CKR_MECHANISM_INVALID
        } as u64;
        match result {
            Err(error @ Error::Native { .. }) if matches!(&error,Error::Native { function:f,code,.. } if *f==function && *code==expected) =>
            {
                outcome::record(report, Phase::Body, &Failure::Product(error))
                    .map_err(|_| Failure::Input("cms_report_write"))?;
                Ok(())
            }
            Err(error) => Err(error.into()),
            Ok(()) => Err(Failure::Oracle("cms_initializer_unexpected_success")),
        }
    }
}
