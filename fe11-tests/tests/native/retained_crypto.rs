// SPDX-License-Identifier: Apache-2.0
//! Recover exactly one cipher/signature continuation after native buffer refusal.
use super::{
    arguments::hex,
    configuration::{select_token, Configuration},
    credentials::Credentials,
    object_owner::Owner,
    outcome::{self, Failure},
    report::{Phase, PhaseResult, Report},
    rsa_known_fixture::Vector,
};
use fe11::*;
use std::{
    fs::File,
    io::{self, Read, Write},
    path::Path,
};

enum Case {
    Cipher {
        advanced: bool,
        key: Vec<u8>,
        expected: Vec<u8>,
    },
    Signature(Vector),
}
impl Case {
    fn read(path: &Path, signature: bool) -> std::result::Result<Self, Failure> {
        if signature {
            let v = Vector::read(path)?;
            if v.action != "sign"
                || v.input != b"abc"
                || v.expected.len() != 256
                || !matches!(v.signature()?, NativeSignatureParameters::Parameterless(algorithm) if algorithm==NativeSignatureAlgorithm::SHA256_RSA_PKCS)
            {
                return Err(Failure::Input("retained_signature_fixture"));
            }
            return Ok(Self::Signature(v));
        }
        let mut bytes = Vec::new();
        File::open(path)
            .map_err(|_| Failure::Input("retained_cipher_open"))?
            .take(257)
            .read_to_end(&mut bytes)
            .map_err(|_| Failure::Input("retained_cipher_read"))?;
        let text =
            std::str::from_utf8(&bytes).map_err(|_| Failure::Input("retained_cipher_encoding"))?;
        let fields: Vec<_> = text.split_terminator('\n').collect();
        if fields.len() != 3 || !matches!(fields[0], "session" | "advanced") {
            return Err(Failure::Input("retained_cipher_fields"));
        }
        let key = hex(fields[1], 16).map_err(Failure::Input)?;
        let expected = hex(fields[2], 16).map_err(Failure::Input)?;
        if key.len() != 16 || expected.len() != 16 {
            return Err(Failure::Input("retained_cipher_width"));
        }
        Ok(Self::Cipher {
            advanced: fields[0] == "advanced",
            key,
            expected,
        })
    }
    fn advanced(&self) -> bool {
        match self {
            Self::Cipher { advanced, .. } => *advanced,
            Self::Signature(v) => v.advanced,
        }
    }
    fn signature(&self) -> bool {
        matches!(self, Self::Signature(_))
    }
    fn expected(&self) -> &[u8] {
        match self {
            Self::Cipher { expected, .. } => expected,
            Self::Signature(v) => &v.expected,
        }
    }
    fn import(&self, owner: &Owner) -> Result<NativeObjectRef> {
        match self {
            Self::Cipher { key, .. } => owner.import_secret(
                key,
                fe11_sys::CKK_AES,
                [StandardAttribute::ENCRYPT, StandardAttribute::DECRYPT],
            ),
            Self::Signature(v) => owner.import_rsa_private(&v.key, StandardAttribute::SIGN),
        }
    }
    fn start(&self, module: &Module, owner: &Owner, key: &NativeObjectRef) -> Result<()> {
        match self {
            Self::Signature(_) => {
                let parameters = NativeSignatureParameters::Parameterless(
                    NativeSignatureAlgorithm::SHA256_RSA_PKCS,
                );
                let parts: [&[u8]; 1] = [b"abc"];
                let limits = InputLimits {
                    maximum_parts: 1,
                    maximum_total_bytes: 3,
                };
                match owner {
                    Owner::Session(s) => s.sign_native(
                        key,
                        parameters,
                        MessageRoute::Single,
                        &parts,
                        limits,
                        255,
                        None,
                    ),
                    Owner::Advanced(s) => s.sign_native(
                        key,
                        parameters,
                        MessageRoute::Single,
                        &parts,
                        limits,
                        255,
                        None,
                    ),
                }
                .map(|_| ())
            }
            Self::Cipher { .. } => {
                // SAFETY: standard AES ECB is parameterless in every selected
                // edition. The declared route is exactly EncryptInit/Encrypt.
                let contract = unsafe {
                    module.declare_mechanism_extension(
                        fe11_sys::CKM_AES_ECB as u64,
                        (2, 40),
                        ExtensionOperation::Encrypt,
                        false,
                    )
                }?;
                // SAFETY: NULL/0 parameters accurately describe AES ECB; the
                // borrowed key/input below are retained by Fe11 before dispatch.
                let request = unsafe {
                    ExtensionRequest::new(
                        &contract,
                        ExtensionParameters {
                            blocks: &[],
                            pointers: &[],
                            root: None,
                            outputs: &[],
                        },
                    )
                };
                let input = ExtensionInput::Encrypt {
                    key,
                    input: &[0u8; 16],
                    output_capacity: 15,
                };
                let limits = InputLimits {
                    maximum_parts: 1,
                    maximum_total_bytes: 16,
                };
                match owner {
                    Owner::Session(s) => s.execute_extension(request, input, limits, None),
                    Owner::Advanced(s) => s.execute_extension(request, input, limits, None),
                }
                .map(|_| ())
            }
        }
    }
}
fn take(owner: &Owner, signature: bool) -> Result<OperationTicket> {
    match (owner, signature) {
        (Owner::Session(s), true) => s.take_signature_ticket(),
        (Owner::Advanced(s), true) => s.take_signature_ticket(),
        (Owner::Session(s), false) => s.take_cipher_ticket(),
        (Owner::Advanced(s), false) => s.take_cipher_ticket(),
    }
}
fn check(
    module: &Module,
    owner: &Owner,
    key: &NativeObjectRef,
    case: &Case,
    ticket: &mut Option<OperationTicket>,
) -> std::result::Result<(), Failure> {
    let signature = case.signature();
    match case.start(module, owner, key) {
        Err(Error::SignatureBufferRequired(r))
            if signature
                && r.function == "C_Sign"
                && r.code == fe11_sys::CKR_BUFFER_TOO_SMALL as u64
                && r.required == 256
                && r.previous_capacity == 255 =>
        {
            ()
        }
        Err(Error::CipherBufferRequired(r))
            if !signature
                && r.function == "C_Encrypt"
                && r.code == fe11_sys::CKR_BUFFER_TOO_SMALL as u64
                && r.required == 16
                && r.previous_capacity == 15 =>
        {
            ()
        }
        Err(error) => return Err(error.into()),
        Ok(()) => return Err(Failure::Oracle("short_output_not_retained")),
    }
    let before = module.call_counts()?;
    *ticket = Some(take(owner, signature)?);
    match take(owner, signature) {
        Err(Error::Rejected(RejectionReason::SignatureContinuation(
            SignatureContinuationRejection::SignatureContinuationTicketUnavailable,
        ))) if signature => (),
        Err(Error::Rejected(RejectionReason::CipherContinuation(
            CipherContinuationRejection::CipherTicketAlreadyHeldByCaller,
        ))) if !signature => (),
        Err(error) => return Err(error.into()),
        Ok(_) => return Err(Failure::Oracle("retained_ticket_transferred_twice")),
    }
    let ticket = ticket
        .as_mut()
        .ok_or(Failure::Input("retained_crypto_ticket"))?;
    match (owner, signature) {
        (Owner::Session(s), true) => s.provide_signature_output_capacity(ticket, 256),
        (Owner::Advanced(s), true) => s.provide_signature_output_capacity(ticket, 256),
        (Owner::Session(s), false) => s.resize_cipher_output(ticket, 16),
        (Owner::Advanced(s), false) => s.resize_cipher_output(ticket, 16),
    }?;
    if module.call_counts()? != before {
        return Err(Failure::Oracle("retained_local_action_dispatched"));
    }
    let output = match (owner, signature) {
        (Owner::Session(s), true) => s.poll_signature(ticket),
        (Owner::Advanced(s), true) => s.poll_signature(ticket),
        (Owner::Session(s), false) => s.poll_cipher(ticket),
        (Owner::Advanced(s), false) => s.poll(ticket),
    }?;
    let value = match output {
        OperationProgress::NativeSignature(v) if signature => v,
        OperationProgress::ExtensionEncrypted(v) if !signature => v,
        _ => return Err(Failure::Oracle("retained_result_kind")),
    };
    if value.as_bytes() != case.expected() {
        return Err(Failure::Oracle("retained_exact_known_answer"));
    }
    let mut expected = before;
    *expected
        .entry(if signature { "C_Sign" } else { "C_Encrypt" })
        .or_default() += 1;
    if module.call_counts()? != expected {
        return Err(Failure::Oracle("retained_init_or_input_replayed"));
    }
    Ok(())
}
pub fn execute<W: Write>(
    module: Module,
    config: &Configuration,
    path: &Path,
    signature: bool,
    pins: &Credentials,
    mut report: Report<W>,
) -> io::Result<bool> {
    let mut owner = None;
    let mut context = None;
    let mut key = None;
    let mut ticket = None;
    let mut logged_in = false;
    let setup = (|| -> std::result::Result<Case, Failure> {
        let case = Case::read(path, signature)?;
        let token =
            select_token(&module, &config.label).ok_or(Failure::Input("retained_crypto_token"))?;
        context = Some(module.select(&token)?);
        let session = context
            .as_ref()
            .ok_or(Failure::Input("retained_token_context"))?
            .open_session(true)?;
        owner = Some(Owner::Session(session));
        if signature {
            let Some(Owner::Session(s)) = owner.as_ref() else {
                return Err(Failure::Input("retained_login_owner"));
            };
            s.login_as(LoginRole::User, SecretPin::new(pins.user.to_vec()))?;
            logged_in = true;
        }
        if case.advanced() {
            let Some(Owner::Session(s)) = owner.take() else {
                return Err(Failure::Input("retained_advanced_owner"));
            };
            owner = Some(Owner::Advanced(s.into_advanced()?));
        }
        key = Some(
            case.import(
                owner
                    .as_ref()
                    .ok_or(Failure::Input("retained_import_owner"))?,
            )?,
        );
        Ok(case)
    })();
    let body = match (&setup, &owner, &key) {
        (Ok(case), Some(owner), Some(key)) => check(&module, owner, key, case, &mut ticket),
        (Err(_), _, _) => Ok(()),
        _ => Err(Failure::Input("retained_crypto_setup")),
    };
    drop(ticket);
    let mut cleanup = Vec::new();
    if logged_in {
        if let Some(context) = &context {
            if let Err(error) = context.logout() {
                cleanup.push(error.into());
            }
        }
    }
    if let Some(owner) = &owner {
        cleanup.extend(owner.close(key.as_ref()));
    }
    drop(key);
    drop(owner);
    drop(context);
    if let Err(error) = module.close() {
        cleanup.push(error.into());
    }
    if let Err(error) = &setup {
        outcome::record(&mut report, Phase::Setup, error)?;
    }
    if let Err(error) = &body {
        outcome::record(&mut report, Phase::Body, error)?;
    }
    for error in &cleanup {
        outcome::record(&mut report, Phase::Cleanup, error)?;
    }
    report.finish(
        if setup.is_ok() {
            PhaseResult::Passed
        } else {
            PhaseResult::Failed
        },
        if setup.is_err() {
            PhaseResult::NotExecuted
        } else if body.is_ok() {
            PhaseResult::Passed
        } else {
            PhaseResult::Failed
        },
        if cleanup.is_empty() {
            PhaseResult::Passed
        } else {
            PhaseResult::Failed
        },
    )
}
