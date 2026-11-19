// SPDX-License-Identifier: Apache-2.0
//! Independent native refusal paths with real, correctly typed key objects.
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
        .and_then(|mut f| f.read_exact(&mut prefix))
        .is_ok()
        && &prefix == b"message-init\n"
}

pub(super) struct Case {
    advanced: bool,
    action: String,
    key: Vec<u8>,
    exponent: Vec<u8>,
}

impl SingleKeyCase for Case {
    const ASSERTION: &'static str = "native_initialization_refusal";
    const PRODUCER: Producer = Producer::TestOracle;

    fn read(path: &Path) -> std::result::Result<Self, Failure> {
        let mut bytes = Vec::new();
        File::open(path)
            .map_err(|_| Failure::Input("message_init_open"))?
            .take(2049)
            .read_to_end(&mut bytes)
            .map_err(|_| Failure::Input("message_init_read"))?;
        if bytes.len() > 2048 {
            return Err(Failure::Input("message_init_size"));
        }
        let text =
            std::str::from_utf8(&bytes).map_err(|_| Failure::Input("message_init_encoding"))?;
        let f: Vec<_> = text.split_terminator('\n').collect();
        if f.len() != 5
            || f[0] != "message-init"
            || !matches!(f[1], "Session" | "AdvancedSession")
            || !matches!(
                f[2],
                "decrypt" | "mac_verify" | "mac_sign" | "rsa_verify" | "verify_signature"
            )
        {
            return Err(Failure::Input("message_init_fields"));
        }
        let key = hex(f[3], 256).map_err(Failure::Input)?;
        let exponent = hex(f[4], 8).map_err(Failure::Input)?;
        let rsa = matches!(f[2], "rsa_verify" | "verify_signature");
        if key.len() != if rsa { 256 } else { 16 }
            || (rsa && exponent != [1, 0, 1])
            || (!rsa && !exponent.is_empty())
        {
            return Err(Failure::Input("message_init_key"));
        }
        Ok(Self {
            advanced: f[1] == "AdvancedSession",
            action: f[2].into(),
            key,
            exponent,
        })
    }

    fn advanced(&self) -> bool {
        self.advanced
    }

    fn import(&self, owner: &Owner) -> std::result::Result<NativeObjectRef, Failure> {
        if matches!(self.action.as_str(), "rsa_verify" | "verify_signature") {
            owner
                .import_rsa_public(&self.key, &self.exponent)
                .map_err(Failure::from)
        } else if self.action == "decrypt" {
            owner
                .import_secret(
                    &self.key,
                    fe11_sys::CKK_AES,
                    [StandardAttribute::ENCRYPT, StandardAttribute::DECRYPT],
                )
                .map_err(Failure::from)
        } else {
            owner
                .import_secret(
                    &self.key,
                    fe11_sys::CKK_GENERIC_SECRET,
                    [StandardAttribute::SIGN, StandardAttribute::VERIFY],
                )
                .map_err(Failure::from)
        }
    }

    fn check<W: Write>(
        &self,
        owner: &Owner,
        key: &NativeObjectRef,
        report: &mut Report<W>,
    ) -> std::result::Result<(), Failure> {
        let signature = vec![
            0;
            if matches!(self.action.as_str(), "mac_verify" | "mac_sign") {
                32
            } else {
                256
            }
        ];
        let limits = InputLimits {
            maximum_parts: 1,
            maximum_total_bytes: 3,
        };
        let parameters =
            || NativeSignatureParameters::Parameterless(NativeSignatureAlgorithm::RSA_PKCS);
        macro_rules! invoke {
            ($session:expr, $poll:ident) => {{
                let s = $session;
                match self.action.as_str() {
                    "decrypt" => s
                        .begin_aead_decrypt_message_stream(
                            key,
                            MessageAeadMechanism::Gcm,
                            MessageRoute::Single,
                            MessageAeadInit::WithoutParameters,
                        )
                        .and_then(|mut ticket| s.$poll(&mut ticket).map(|_| ())),
                    "verify_signature" => s
                        .verify_signature_native(
                            key,
                            parameters(),
                            MessageRoute::Single,
                            &[b"abc"],
                            &signature,
                            limits,
                            None,
                        )
                        .map(|_| ()),
                    _ => s
                        .execute_native_message(
                            key,
                            if matches!(self.action.as_str(), "mac_verify" | "mac_sign") {
                                NativeMessageParameters::Mac(NativeMacParameters::Full(
                                    NativeMacAlgorithm::SHA256_HMAC,
                                ))
                            } else {
                                NativeMessageParameters::Signature(parameters())
                            },
                            NativeMessageRoute::Single(NativeMessagePart {
                                data: b"abc",
                                parameters: None,
                            }),
                            if self.action == "mac_sign" {
                                NativeMessageAction::Sign {
                                    output_capacity: 32,
                                }
                            } else {
                                NativeMessageAction::Verify {
                                    signature: &signature,
                                }
                            },
                            limits,
                            None,
                        )
                        .map(|_| ()),
                }
            }};
        }
        let result = match owner {
            Owner::Session(s) => invoke!(s, poll_aead),
            Owner::Advanced(s) => invoke!(s, poll),
        };
        let expected = match self.action.as_str() {
            "decrypt" => "C_MessageDecryptInit",
            "mac_sign" => "C_MessageSignInit",
            "verify_signature" => "C_VerifySignatureInit",
            _ => "C_MessageVerifyInit",
        };
        match result {
            Err(error @ Error::Native { function, code, .. })
                if function == expected && code == fe11_sys::CKR_FUNCTION_NOT_SUPPORTED as u64 =>
            {
                outcome::record(report, Phase::Body, &Failure::Product(error))
                    .map_err(|_| Failure::Input("report_write"))
            }
            Err(error) => Err(error.into()),
            Ok(()) => Err(Failure::Oracle("message_init_unexpected_success")),
        }
    }
}
