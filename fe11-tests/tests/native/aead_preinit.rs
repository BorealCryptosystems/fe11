// SPDX-License-Identifier: Apache-2.0
//! Check public AEAD input boundaries before the first native message Init.
use super::{
    configuration::{select_token, Configuration},
    credentials::Credentials,
    object_owner::Owner,
    outcome::{self, Failure},
    report::{Phase, PhaseResult, Report},
};
use fe11::*;
use std::{
    fs::File,
    io::{self, Read, Write},
    path::Path,
};

struct Case {
    advanced: bool,
    action: String,
}
impl Case {
    fn read(path: &Path) -> std::result::Result<Self, Failure> {
        let mut data = Vec::new();
        File::open(path)
            .map_err(|_| Failure::Input("fixture_open"))?
            .take(129)
            .read_to_end(&mut data)
            .map_err(|_| Failure::Input("fixture_read"))?;
        if data.len() > 128 {
            return Err(Failure::Input("fixture_size"));
        }
        let text = std::str::from_utf8(&data).map_err(|_| Failure::Input("fixture_encoding"))?;
        let f: Vec<_> = text.split_terminator('\n').collect();
        if f.len() != 2
            || !matches!(f[0], "session" | "advanced")
            || !matches!(
                f[1],
                "input_ceiling"
                    | "begin_input_ceiling"
                    | "valid_input_before_init"
                    | "legacy_interface"
                    | "foreign_ticket"
                    | "take_ticket_again"
                    | "recovery_ccm"
                    | "recovery_chacha"
                    | "recovery_salsa"
            )
        {
            return Err(Failure::Input("aead_preinit_fields"));
        }
        Ok(Self {
            advanced: f[0] == "advanced",
            action: f[1].into(),
        })
    }
    fn route(&self) -> MessageRoute {
        if self.action == "begin_input_ceiling" {
            MessageRoute::Multipart
        } else {
            MessageRoute::Single
        }
    }
}

fn begin(owner: &Owner, key: &NativeObjectRef, route: MessageRoute) -> Result<OperationTicket> {
    match owner {
        Owner::Session(s) => s.begin_aead_encrypt_message_stream(
            key,
            MessageAeadMechanism::Gcm,
            route,
            MessageAeadInit::WithoutParameters,
        ),
        Owner::Advanced(s) => s.begin_aead_encrypt_message_stream(
            key,
            MessageAeadMechanism::Gcm,
            route,
            MessageAeadInit::WithoutParameters,
        ),
    }
}
fn negative(
    owner: &Owner,
    ticket: &mut OperationTicket,
    case: &Case,
) -> std::result::Result<(), Failure> {
    if case.action.starts_with("recovery_") {
        let Owner::Advanced(session) = owner else {
            return Err(Failure::Input("recovery_requires_advanced"));
        };
        let before = ticket.aead_message_progress()?;
        let limits = RecordLimits {
            bytes: 1_048_576,
            messages: 1,
            fragments: 1,
        };
        let result = match case.action.as_str() {
            "recovery_ccm" => session.capture_ccm_recovery(ticket, limits).map(|_| ()),
            "recovery_chacha" => session
                .capture_stream_aead_recovery(ticket, limits, StreamAeadAlgorithm::ChaCha20)
                .map(|_| ()),
            "recovery_salsa" => session
                .capture_stream_aead_recovery(ticket, limits, StreamAeadAlgorithm::Salsa20)
                .map(|_| ()),
            _ => return Err(Failure::Input("recovery_kind")),
        };
        match result {
            Err(Error::Rejected(RejectionReason::OperationRecovery(
                OperationRecoveryRejection::RecoveryMechanismDoesNotMatchRequestedApi,
            ))) => (),
            Err(error) => return Err(error.into()),
            Ok(()) => return Err(Failure::Oracle("recovery_wrong_mechanism_accepted")),
        }
        return if ticket.aead_message_progress()? == before {
            Ok(())
        } else {
            Err(Failure::Oracle("recovery_changed_original_ticket"))
        };
    }
    if case.action == "take_ticket_again" {
        let before = ticket.aead_message_progress()?;
        let result = match owner {
            Owner::Session(s) => s.take_aead_message_ticket(),
            Owner::Advanced(s) => s.take_aead_message_ticket(),
        };
        match result {
            Err(Error::Rejected(RejectionReason::AeadMessages(
                AeadMessagesRejection::AeadMessageTicketUnavailable,
            ))) => (),
            Err(error) => return Err(error.into()),
            Ok(_) => return Err(Failure::Oracle("aead_observer_transferred_twice")),
        }
        if ticket.aead_message_progress()? != before {
            return Err(Failure::Oracle("aead_original_ticket_changed"));
        }
        return Ok(());
    }
    let parameters = MessageAeadParameters::Gcm(AeadNonce::Provided([0; 12]));
    let ceiling = case.action == "input_ceiling" || case.action == "begin_input_ceiling";
    let input = MessageAeadInput {
        parameters: &parameters,
        aad: if ceiling { &[0, 1] } else { &[] },
        expected_tag: None,
        output_capacity: 16,
    };
    let limits = InputLimits {
        maximum_parts: 1,
        maximum_total_bytes: 1,
    };
    macro_rules! call {
        ($s:expr) => {
            if case.action == "begin_input_ceiling" {
                $s.begin_aead_message(ticket, input, limits)
            } else {
                $s.submit_aead_message(ticket, input, &[], limits)
            }
        };
    }
    let result = match owner {
        Owner::Session(s) => call!(s),
        Owner::Advanced(s) => call!(s),
    };
    let expected = if ceiling {
        AeadMessagesRejection::AeadInputCeiling
    } else if case.action == "foreign_ticket" {
        AeadMessagesRejection::ForeignOrConsumedAeadStreamTicket
    } else {
        AeadMessagesRejection::AeadStreamIsNotAwaitingInput
    };
    match result {
        Err(Error::Rejected(RejectionReason::AeadMessages(actual))) if actual == expected => Ok(()),
        Err(e) => Err(e.into()),
        Ok(_) => Err(Failure::Oracle("aead_preinit_exact_local_refusal")),
    }
}
fn poll<W: Write>(
    owner: &Owner,
    ticket: &mut OperationTicket,
    report: &mut Report<W>,
) -> std::result::Result<(), Failure> {
    let result = match owner {
        Owner::Session(s) => s.poll_aead(ticket),
        Owner::Advanced(s) => s.poll(ticket),
    };
    match result {
        Err(
            error @ Error::Native {
                function: "C_MessageEncryptInit",
                code,
                ..
            },
        ) if code == fe11_sys::CKR_FUNCTION_NOT_SUPPORTED as u64 => {
            outcome::record(report, Phase::Body, &Failure::Product(error))
                .map_err(|_| Failure::Input("report_write"))
        }
        Err(e) => Err(e.into()),
        Ok(_) => Err(Failure::Oracle("aead_preinit_native_refusal")),
    }
}
pub fn execute<W: Write>(
    module: Module,
    config: &Configuration,
    path: &Path,
    pins: &Credentials,
    mut report: Report<W>,
) -> io::Result<bool> {
    let mut peer = None;
    let mut subject = None;
    let mut foreign = None;
    let mut key = None;
    let mut ticket = None;
    let mut logged = false;
    let setup = (|| -> std::result::Result<Case, Failure> {
        let case = Case::read(path)?;
        let expected_interface = if case.action == "legacy_interface" {
            InterfaceSelection::Legacy240
        } else {
            InterfaceSelection::Standard {
                version: (3, 2),
                required_flags: 0,
            }
        };
        if config.interface != expected_interface {
            return Err(Failure::Input("message_interface_required"));
        }
        let token =
            select_token(&module, &config.label).ok_or(Failure::Input("token_not_unique"))?;
        peer = Some(module.select(&token)?.open_session(true)?);
        peer.as_ref()
            .ok_or(Failure::Input("peer"))?
            .login_as(LoginRole::User, SecretPin::new(pins.user.to_vec()))?;
        logged = true;
        subject = Some(Owner::open(&module, config, case.advanced)?);
        let owner = subject.as_ref().ok_or(Failure::Input("subject"))?;
        key = Some(owner.import_secret(
            &(0u8..16).collect::<Vec<_>>(),
            fe11_sys::CKK_AES,
            [StandardAttribute::ENCRYPT, StandardAttribute::DECRYPT],
        )?);
        let key = key.as_ref().ok_or(Failure::Input("key"))?;
        if case.action == "legacy_interface" {
            return Ok(case);
        }
        ticket = Some(if case.action.starts_with("recovery_") {
            let Owner::Advanced(session) = owner else {
                return Err(Failure::Input("recovery_requires_advanced"));
            };
            // Capture examines the stored mechanism before any message Init.
            // Keep the genuine pre-Init owner; do not fabricate a saved state.
            session.begin_aead_decrypt_message_stream(
                key,
                MessageAeadMechanism::Gcm,
                MessageRoute::Single,
                MessageAeadInit::WithoutParameters,
            )?
        } else {
            begin(owner, key, case.route())?
        });
        if case.action == "foreign_ticket" {
            foreign = Some(Owner::open(&module, config, case.advanced)?);
        }
        Ok(case)
    })();
    let started = setup.is_ok();
    let body = match &setup {
        Err(_) => Ok(()),
        Ok(case) => (|| -> std::result::Result<(), Failure> {
            let owner = subject.as_ref().ok_or(Failure::Input("subject"))?;
            if case.action == "legacy_interface" {
                let key = key.as_ref().ok_or(Failure::Input("key"))?;
                let before = module.call_counts()?;
                match begin(owner, key, MessageRoute::Single) {
                    Err(Error::Rejected(RejectionReason::AeadMessages(
                        AeadMessagesRejection::MessageInterfaceUnavailable,
                    ))) => (),
                    Err(error) => return Err(error.into()),
                    Ok(_) => return Err(Failure::Oracle("legacy_message_owner_created")),
                }
                if module.call_counts()? != before {
                    return Err(Failure::Oracle("legacy_message_native_dispatch"));
                }
                return Ok(());
            }
            let ticket = ticket.as_mut().ok_or(Failure::Input("ticket"))?;
            let before = module.call_counts()?;
            negative(foreign.as_ref().unwrap_or(owner), ticket, case)?;
            if case.action == "take_ticket_again" {
                if module.call_counts()? != before {
                    return Err(Failure::Oracle("aead_ticket_take_dispatched"));
                }
                // The caller still owns the pre-Init ticket. This case closes
                // it without requesting an unsupported native message Init.
                return Ok(());
            }
            // A rejected submission must leave the original Init ticket usable.
            // Its explicit poll is a separately checked native refusal, not success.
            if case.action.starts_with("recovery_") {
                // The kind guard is independent of native message support.
                // Explicit session close below releases this unissued owner.
                Ok(())
            } else {
                poll(owner, ticket, &mut report)
            }
        })(),
    };
    let mut cleanup = Vec::new();
    if let Some(owner) = foreign.as_ref() {
        cleanup.extend(owner.close(None));
    }
    if let Some(owner) = subject.as_ref() {
        cleanup.extend(owner.close(None));
    }
    if let Some(peer) = peer.as_ref() {
        if logged {
            if let Err(e) = peer.logout() {
                cleanup.push(e.into());
            }
        }
        if let Err(e) = peer.close() {
            cleanup.push(e.into());
        }
    }
    drop(ticket);
    drop(key);
    drop(foreign);
    drop(subject);
    drop(peer);
    if let Err(e) = module.close() {
        cleanup.push(e.into());
    }
    if let Err(e) = &setup {
        outcome::record(&mut report, Phase::Setup, e)?;
    }
    if let Err(e) = &body {
        outcome::record(&mut report, Phase::Body, e)?;
    }
    for e in &cleanup {
        outcome::record(&mut report, Phase::Cleanup, e)?;
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
