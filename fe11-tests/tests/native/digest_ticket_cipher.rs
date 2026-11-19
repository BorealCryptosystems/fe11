// SPDX-License-Identifier: Apache-2.0
//! Digest method guards preserve an independently owned, initialized AES operation.
use super::{
    arguments::hex,
    configuration::{select_token, Configuration},
    credentials::Credentials,
    generation_transition_spec,
    object_owner::Owner,
    outcome::{self, Failure},
    report::{Observation, Phase, PhaseResult, Producer, Report},
};
use fe11::*;
use std::{
    fs::File,
    io::{self, Read, Write},
    path::Path,
};

struct Case {
    advanced: bool,
    foreign: bool,
    method: String,
}
impl Case {
    fn read(path: &Path) -> std::result::Result<Self, Failure> {
        let mut bytes = Vec::new();
        File::open(path)
            .map_err(|_| Failure::Input("fixture_open"))?
            .take(513)
            .read_to_end(&mut bytes)
            .map_err(|_| Failure::Input("fixture_read"))?;
        if bytes.len() > 512 {
            return Err(Failure::Input("fixture_size"));
        }
        let text = std::str::from_utf8(&bytes).map_err(|_| Failure::Input("fixture_encoding"))?;
        let f: Vec<_> = text.split_terminator('\n').collect();
        if f.len() != 3
            || !matches!(f[0], "session" | "advanced")
            || !matches!(f[1], "family" | "foreign" | "transitive")
            || !matches!(
                f[2],
                "finish_digest"
                    | "finish_native_digest"
                    | "finish_extension_digest_stream"
                    | "provide_digest_output_capacity"
                    | "provide_extension_digest_output_capacity"
                    | "digest_update"
                    | "digest_key"
            )
            || (f[1] == "transitive")
                != matches!(
                    f[2],
                    "provide_digest_output_capacity"
                        | "provide_extension_digest_output_capacity"
                        | "digest_update"
                        | "digest_key"
                )
        {
            return Err(Failure::Input("digest_ticket_fixture"));
        }
        Ok(Self {
            advanced: f[0] == "advanced",
            foreign: f[1] == "foreign",
            method: f[2].into(),
        })
    }
}

#[derive(Default)]
struct Fixture {
    login: Option<Session>,
    logged: bool,
    owner: Option<Owner>,
    peer: Option<Owner>,
    native_key: Option<NativeObjectRef>,
    digest_operand: Option<NativeObjectRef>,
    key: Option<SymmetricKey>,
    ticket: Option<OperationTicket>,
}
impl Fixture {
    fn owner(&self) -> std::result::Result<&Owner, Failure> {
        self.owner.as_ref().ok_or(Failure::Input("cipher_owner"))
    }
    fn prepare(
        &mut self,
        module: &Module,
        config: &Configuration,
        pins: &Credentials,
        case: &Case,
    ) -> std::result::Result<(), Failure> {
        let token =
            select_token(module, &config.label).ok_or(Failure::Input("token_not_unique"))?;
        self.login = Some(module.select(&token)?.open_session(true)?);
        self.login
            .as_ref()
            .ok_or(Failure::Input("login_session"))?
            .login_as(LoginRole::User, SecretPin::new(pins.user.to_vec()))?;
        self.logged = true;
        self.owner = Some(Owner::open(module, config, false)?);
        // All key material is public fixture data. Session scope and the exact
        // returned reference confine cleanup; a search never authorizes deletion.
        let material = hex("000102030405060708090a0b0c0d0e0f", 16).map_err(Failure::Input)?;
        let attr = |attribute: StandardAttribute, value| AttributeInput {
            attribute: attribute.into(),
            value,
        };
        let attrs = [
            attr(
                StandardAttribute::CLASS,
                AttributeInputValue::Unsigned(fe11_sys::CKO_SECRET_KEY as u64),
            ),
            attr(
                StandardAttribute::KEY_TYPE,
                AttributeInputValue::Unsigned(fe11_sys::CKK_AES as u64),
            ),
            attr(
                StandardAttribute::TOKEN,
                AttributeInputValue::Boolean(false),
            ),
            attr(
                StandardAttribute::PRIVATE,
                AttributeInputValue::Boolean(false),
            ),
            attr(
                StandardAttribute::ENCRYPT,
                AttributeInputValue::Boolean(true),
            ),
            attr(
                StandardAttribute::DECRYPT,
                AttributeInputValue::Boolean(true),
            ),
            attr(
                StandardAttribute::SENSITIVE,
                AttributeInputValue::Boolean(true),
            ),
            attr(
                StandardAttribute::EXTRACTABLE,
                AttributeInputValue::Boolean(false),
            ),
            attr(
                StandardAttribute::ID,
                AttributeInputValue::Bytes(config.label.as_bytes()),
            ),
            attr(
                StandardAttribute::LABEL,
                AttributeInputValue::Bytes(config.label.as_bytes()),
            ),
            attr(
                StandardAttribute::VALUE,
                AttributeInputValue::Bytes(&material),
            ),
        ];
        self.native_key = Some(self.owner()?.create(
            &attrs,
            AttributeTemplateLimits {
                maximum_depth: 0,
                maximum_attributes: attrs.len(),
                maximum_value_bytes: 4096,
            },
        )?);
        let mut spec = generation_transition_spec::key(&config.label);
        spec.persistent = false;
        self.key = Some(match self.owner()? {
            Owner::Session(session) => session.find_symmetric_key(spec)?,
            _ => return Err(Failure::Input("initial_session_owner")),
        });
        if case.advanced {
            let Some(Owner::Session(session)) = self.owner.take() else {
                return Err(Failure::Input("initial_session_owner"));
            };
            self.owner = Some(Owner::Advanced(session.into_advanced()?));
            if let Some(Owner::Advanced(session)) = &mut self.owner {
                session.set_pacing(OperationPacing::Cooperative)?;
                session.set_validation_capture(ValidationCaptureMode::Disabled)?;
            }
        }
        if case.method == "digest_key" {
            self.digest_operand = Some(self.owner()?.import_secret(
                &[0; 16],
                fe11_sys::CKK_GENERIC_SECRET,
                [StandardAttribute::SIGN, StandardAttribute::VERIFY],
            )?);
        }
        if case.foreign {
            self.peer = Some(Owner::open(module, config, case.advanced)?);
        }
        let key = self.key.as_ref().ok_or(Failure::Input("cipher_key"))?;
        let limits = InputLimits {
            maximum_parts: 1,
            maximum_total_bytes: 16,
        };
        let before = module.call_counts()?;
        self.ticket = Some(match self.owner()? {
            Owner::Session(s) => s.begin_encrypt_aes(
                key,
                AesCipherParameters::Ecb,
                MessageRoute::Single,
                &[&[0; 16]],
                limits,
            )?,
            Owner::Advanced(s) => s.start_encrypt_aes(
                key,
                AesCipherParameters::Ecb,
                MessageRoute::Single,
                &[&[0; 16]],
                limits,
            )?,
        });
        let after = module.call_counts()?;
        if after
            .values()
            .sum::<u64>()
            .checked_sub(before.values().sum())
            != Some(1)
            || count(&after, "C_EncryptInit").checked_sub(count(&before, "C_EncryptInit"))
                != Some(1)
        {
            return Err(Failure::Oracle("cipher_stopped_after_init"));
        }
        let ticket = self
            .ticket
            .as_ref()
            .ok_or(Failure::Input("cipher_ticket"))?;
        if ticket.cipher_progress()? != (StreamInputStatus::Closed, StreamProgress::default()) {
            return Err(Failure::Oracle("cipher_input_not_consumed"));
        }
        Ok(())
    }
    fn check<W: Write>(
        &mut self,
        module: &Module,
        case: &Case,
        report: &mut Report<W>,
    ) -> std::result::Result<(), Failure> {
        let receiver = self
            .peer
            .as_ref()
            .or(self.owner.as_ref())
            .ok_or(Failure::Input("ticket_receiver"))?;
        let ticket = self
            .ticket
            .as_mut()
            .ok_or(Failure::Input("cipher_ticket"))?;
        let progress = ticket.cipher_progress()?;
        let before = module.call_counts()?;
        let attempted = invoke(receiver, &case.method, ticket, self.digest_operand.as_ref());
        let after = module.call_counts()?;
        let expected = if case.foreign {
            RejectionReason::OperationOwnership(
                OperationOwnershipRejection::ForeignOrConsumedDigestTicket,
            )
        } else if matches!(
            case.method.as_str(),
            "provide_digest_output_capacity"
                | "provide_extension_digest_output_capacity"
                | "digest_update"
                | "digest_key"
        ) {
            RejectionReason::OperationOwnership(OperationOwnershipRejection::DigestTicketRequired)
        } else {
            RejectionReason::DigestContinuation(
                DigestContinuationRejection::DigestResultContractMismatch,
            )
        };
        let assertion = match attempted {
            Err(error @ Failure::Product(Error::Rejected(reason))) if reason == expected => {
                outcome::record(report, Phase::Body, &error)
                    .map_err(|_| Failure::Input("report_write"))?;
                if before != after || ticket.cipher_progress()? != progress {
                    Err(Failure::Oracle("wrong_digest_finish_changed_cipher"))
                } else {
                    Ok(())
                }
            }
            Err(error) => Err(error),
            Ok(()) => Err(Failure::Oracle("cipher_ticket_accepted_as_digest")),
        };
        // Even a failed guard assertion must attempt the original continuation.
        // Cleanup alone cannot prove preservation of its retained input.
        let continuation = self.complete(module);
        if let Err(error) = &continuation {
            outcome::record(report, Phase::Body, error)
                .map_err(|_| Failure::Input("report_write"))?;
        }
        assertion?;
        continuation
    }
    fn complete(&mut self, module: &Module) -> std::result::Result<(), Failure> {
        let owner = self.owner.as_ref().ok_or(Failure::Input("cipher_owner"))?;
        let ticket = self
            .ticket
            .as_mut()
            .ok_or(Failure::Input("cipher_ticket"))?;
        let before = module.call_counts()?;
        let value = match owner {
            Owner::Session(s) => s.poll_aes(ticket)?,
            Owner::Advanced(s) => s.poll(ticket)?,
        };
        let expected = hex("c6a13b37878f5b826f4f8162a1c8d879", 16).map_err(Failure::Input)?;
        match value {
            OperationProgress::CipherEncrypted(value) if value.as_bytes() == expected => (),
            _ => return Err(Failure::Oracle("retained_cipher_exact_result")),
        }
        let after = module.call_counts()?;
        if count(&after, "C_Encrypt").checked_sub(count(&before, "C_Encrypt")) != Some(1)
            || count(&after, "C_EncryptInit") != count(&before, "C_EncryptInit")
        {
            return Err(Failure::Oracle("cipher_continuation_dispatch_count"));
        }
        Ok(())
    }
    fn cleanup(&mut self) -> Vec<Failure> {
        self.ticket.take();
        self.key.take();
        let mut failures = Vec::new();
        if let (Some(owner), Some(key)) = (&self.owner, &self.digest_operand) {
            if let Err(error) = super::key_wrap_fixture::destroy(owner, key) {
                failures.push(error.into());
            }
        }
        self.digest_operand.take();
        failures.extend(
            self.owner
                .as_ref()
                .map_or_else(Vec::new, |owner| owner.close(self.native_key.as_ref())),
        );
        self.native_key.take();
        if let Some(peer) = &self.peer {
            failures.extend(peer.close(None));
        }
        if let Some(login) = &self.login {
            if self.logged {
                if let Err(error) = login.logout() {
                    failures.push(error.into());
                }
            }
            if let Err(error) = login.close() {
                failures.push(error.into());
            }
        }
        failures
    }
}
fn count(map: &std::collections::BTreeMap<&str, u64>, function: &str) -> u64 {
    map.get(function).copied().unwrap_or(0)
}
fn invoke(
    owner: &Owner,
    method: &str,
    ticket: &mut OperationTicket,
    operand: Option<&NativeObjectRef>,
) -> std::result::Result<(), Failure> {
    let limits = InputLimits {
        maximum_parts: 1,
        maximum_total_bytes: 3,
    };
    match (owner, method) {
        (Owner::Session(s), "finish_digest") => s.finish_digest(ticket).map(|_| ()),
        (Owner::Session(s), "finish_native_digest") => s.finish_native_digest(ticket).map(|_| ()),
        (Owner::Session(s), "finish_extension_digest_stream") => {
            s.finish_extension_digest_stream(ticket).map(|_| ())
        }
        (Owner::Advanced(s), "finish_digest") => s.finish_digest(ticket).map(|_| ()),
        (Owner::Advanced(s), "finish_native_digest") => s.finish_native_digest(ticket).map(|_| ()),
        (Owner::Advanced(s), "finish_extension_digest_stream") => {
            s.finish_extension_digest_stream(ticket).map(|_| ())
        }
        (Owner::Session(s), "provide_digest_output_capacity") => {
            s.provide_digest_output_capacity(ticket, 32)
        }
        (Owner::Advanced(s), "provide_digest_output_capacity") => {
            s.provide_digest_output_capacity(ticket, 32)
        }
        (Owner::Session(s), "provide_extension_digest_output_capacity") => {
            s.provide_extension_digest_output_capacity(ticket, 32)
        }
        (Owner::Advanced(s), "provide_extension_digest_output_capacity") => {
            s.provide_extension_digest_output_capacity(ticket, 32)
        }
        (Owner::Session(s), "digest_update") => s.digest_update(ticket, b"abc", limits),
        (Owner::Advanced(s), "digest_update") => s.digest_update(ticket, b"abc", limits),
        // The fixture constructs a real object before Init; no native key
        // operation is allowed during this wrong-family invocation.
        (Owner::Session(s), "digest_key") => {
            s.digest_key(ticket, operand.ok_or(Failure::Input("digest_operand"))?)
        }
        (Owner::Advanced(s), "digest_key") => {
            s.digest_key(ticket, operand.ok_or(Failure::Input("digest_operand"))?)
        }
        _ => unreachable!("validated fixture method"),
    }
    .map_err(Failure::from)
}
pub fn execute<W: Write>(
    module: Module,
    config: &Configuration,
    path: &Path,
    pins: &Credentials,
    mut report: Report<W>,
) -> io::Result<bool> {
    let mut fixture = Fixture::default();
    let setup = Case::read(path).and_then(|case| {
        fixture.prepare(&module, config, pins, &case)?;
        Ok(case)
    });
    let started = setup.is_ok();
    let body = match &setup {
        Ok(case) => fixture.check(&module, case, &mut report),
        Err(_) => Ok(()),
    };
    let mut cleanup = fixture.cleanup();
    drop(fixture);
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
    if started {
        report.observation(
            Phase::Body,
            "digest_guard_and_cipher_continuation",
            Producer::Fe11Local,
            Observation::Boolean(body.is_ok()),
        )?;
    }
    report.finish(
        if started {
            PhaseResult::Passed
        } else {
            PhaseResult::Failed
        },
        if !started {
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
