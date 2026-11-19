// SPDX-License-Identifier: Apache-2.0
//! Invoke the selected public family API with a live digest ticket.
use super::{object_owner::Owner, outcome::Failure};
use fe11::*;

pub fn expected(method: &str) -> std::result::Result<RejectionReason, Failure> {
    Ok(match method {
        "resize_cipher_output" | "resize_aes_output" => {
            OperationOwnershipRejection::CipherTicketRequired.into()
        }
        "prepare_aead_message_output" => {
            OperationOwnershipRejection::AeadMessageTicketRequired.into()
        }
        "resize_recovery_output" => OperationOwnershipRejection::RecoveryTicketRequired.into(),
        "provide_signature_output_capacity" => {
            OperationOwnershipRejection::SignatureTicketRequired.into()
        }
        "cipher_update"
        | "take_cipher_ticket"
        | "cipher_progress"
        | "finish_cipher_stream"
        | "take_cipher_stream_output"
        | "poll_cipher"
        | "poll_aes" => OperationOwnershipRejection::CipherTicketRequired.into(),
        "poll_aead"
        | "take_aead_message_ticket"
        | "aead_message_progress"
        | "submit_aead_message"
        | "begin_aead_message"
        | "update_aead_message"
        | "finish_aead_message"
        | "finish_aead_messages" => OperationOwnershipRejection::AeadMessageTicketRequired.into(),
        "signature_update"
        | "finish_signature_stream"
        | "finish_signature_single"
        | "take_signature_ticket"
        | "signature_progress" => OperationOwnershipRejection::SignatureTicketRequired.into(),
        "poll_recovery" => OperationOwnershipRejection::RecoveryTicketRequired.into(),
        "submit_signature_message"
        | "begin_signature_message"
        | "update_signature_message"
        | "finish_signature_message"
        | "finish_signature_messages" => {
            SignatureMessagesRejection::MessageSignatureTicketRequired.into()
        }
        "take_native_message_ticket"
        | "submit_native_message"
        | "begin_native_message"
        | "update_native_message"
        | "finish_native_message"
        | "finish_native_messages"
        | "poll_native_messages" => NativeMessagesRejection::GenericMessageTicketRequired.into(),
        _ => return Err(Failure::Input("ticket_family_method")),
    })
}

pub fn identity_error(method: &str) -> std::result::Result<RejectionReason, Failure> {
    if let Some(reason) = super::ticket_identity_dispatch::expected(method) {
        return Ok(reason);
    }
    Ok(match method {
        "cipher_update"
        | "finish_cipher_stream"
        | "take_cipher_stream_output"
        | "poll_cipher"
        | "poll_aes" => OperationOwnershipRejection::ForeignOrConsumedCipherTicket.into(),
        "poll_aead" => AeadMessagesRejection::ForeignOrConsumedAeadTicket.into(),
        "submit_aead_message"
        | "begin_aead_message"
        | "update_aead_message"
        | "finish_aead_message"
        | "finish_aead_messages" => AeadMessagesRejection::ForeignOrConsumedAeadStreamTicket.into(),
        "signature_update" | "finish_signature_stream" | "finish_signature_single" => {
            OperationOwnershipRejection::ForeignOrConsumedSignatureTicket.into()
        }
        "submit_signature_message"
        | "begin_signature_message"
        | "update_signature_message"
        | "finish_signature_message"
        | "finish_signature_messages" => {
            SignatureMessagesRejection::ForeignOrConsumedMessageSignatureTicket.into()
        }
        "submit_native_message"
        | "begin_native_message"
        | "update_native_message"
        | "finish_native_message"
        | "finish_native_messages"
        | "poll_native_messages" => {
            NativeMessagesRejection::ForeignOrConsumedGenericMessageTicket.into()
        }
        _ => return Err(Failure::Input("ticket_identity_method")),
    })
}

pub fn invoke(
    owner: &Owner,
    method: &str,
    ticket: &mut OperationTicket,
    identity_check: bool,
) -> std::result::Result<Result<()>, Failure> {
    // Public ticket accessors inspect the real live owner's family. They must
    // neither consume that owner nor dispatch an unrelated native operation.
    match method {
        "cipher_progress" => return Ok(ticket.cipher_progress().map(|_| ())),
        "signature_progress" => return Ok(ticket.signature_progress().map(|_| ())),
        "aead_message_progress" => return Ok(ticket.aead_message_progress().map(|_| ())),
        _ => {}
    }
    // Identity fixtures retain their own capacities. Family fixtures exercise
    // the declared capacity of 32 through the common dispatch below.
    if identity_check && super::ticket_identity_dispatch::expected(method).is_some() {
        return super::ticket_identity_dispatch::invoke(owner, method, ticket);
    }
    let limits = InputLimits {
        maximum_parts: 1,
        maximum_total_bytes: 128,
    };
    let parameters = MessageAeadParameters::Gcm(AeadNonce::Provided([0; 12]));
    let aead = MessageAeadInput {
        parameters: &parameters,
        aad: &[],
        expected_tag: None,
        output_capacity: 16,
    };
    let part = NativeMessagePart {
        data: b"abc",
        parameters: None,
    };
    // The public facades intentionally have different result types. Discarding
    // a successful result here is safe: success is itself an oracle failure.
    macro_rules! common {
        ($session:expr) => {
            match method {
                "resize_cipher_output" => $session.resize_cipher_output(ticket, 32),
                "resize_aes_output" => $session.resize_aes_output(ticket, 32),
                "prepare_aead_message_output" => $session.prepare_aead_message_output(ticket, 32),
                "resize_recovery_output" => $session.resize_recovery_output(ticket, 32),
                "provide_signature_output_capacity" => {
                    $session.provide_signature_output_capacity(ticket, 32)
                }
                "take_cipher_ticket" => $session.take_cipher_ticket().map(|_| ()),
                "take_signature_ticket" => $session.take_signature_ticket().map(|_| ()),
                "take_aead_message_ticket" => $session.take_aead_message_ticket().map(|_| ()),
                "take_native_message_ticket" => $session.take_native_message_ticket().map(|_| ()),
                "cipher_update" => $session.cipher_update(ticket, b"abc", limits).map(|_| ()),
                "finish_cipher_stream" => $session.finish_cipher_stream(ticket).map(|_| ()),
                "take_cipher_stream_output" => {
                    $session.take_cipher_stream_output(ticket).map(|_| ())
                }
                "submit_aead_message" => $session
                    .submit_aead_message(ticket, aead, b"abc", limits)
                    .map(|_| ()),
                "begin_aead_message" => $session
                    .begin_aead_message(ticket, aead, limits)
                    .map(|_| ()),
                "update_aead_message" => $session
                    .update_aead_message(ticket, b"abc", limits)
                    .map(|_| ()),
                "finish_aead_message" => $session
                    .finish_aead_message(ticket, b"abc", None, limits)
                    .map(|_| ()),
                "finish_aead_messages" => $session.finish_aead_messages(ticket).map(|_| ()),
                "signature_update" => $session
                    .signature_update(ticket, b"abc", limits)
                    .map(|_| ()),
                "finish_signature_stream" => {
                    $session.finish_signature_stream(ticket, None).map(|_| ())
                }
                "finish_signature_single" => $session
                    .finish_signature_single(ticket, b"abc", None, limits)
                    .map(|_| ()),
                "submit_signature_message" => $session
                    .submit_signature_message(ticket, b"abc", None, limits)
                    .map(|_| ()),
                "begin_signature_message" => $session.begin_signature_message(ticket).map(|_| ()),
                "update_signature_message" => $session
                    .update_signature_message(ticket, b"abc", limits)
                    .map(|_| ()),
                "finish_signature_message" => $session
                    .finish_signature_message(ticket, b"abc", None, limits)
                    .map(|_| ()),
                "finish_signature_messages" => {
                    $session.finish_signature_messages(ticket).map(|_| ())
                }
                "submit_native_message" => $session
                    .submit_native_message(
                        ticket,
                        part,
                        NativeMessageAction::Sign {
                            output_capacity: 64,
                        },
                        limits,
                    )
                    .map(|_| ()),
                "begin_native_message" => $session
                    .begin_native_message(ticket, None, limits)
                    .map(|_| ()),
                "update_native_message" => $session
                    .update_native_message(ticket, part, limits)
                    .map(|_| ()),
                "finish_native_message" => $session
                    .finish_native_message(
                        ticket,
                        part,
                        NativeMessageAction::Sign {
                            output_capacity: 64,
                        },
                        limits,
                    )
                    .map(|_| ()),
                "finish_native_messages" => $session.finish_native_messages(ticket).map(|_| ()),
                _ => return Err(Failure::Input("ticket_family_method")),
            }
        };
    }
    Ok(match owner {
        Owner::Session(session) => match method {
            "poll_recovery" => session.poll_recovery(ticket).map(|_| ()),
            "poll_cipher" => session.poll_cipher(ticket).map(|_| ()),
            "poll_aes" => session.poll_aes(ticket).map(|_| ()),
            "poll_aead" => session.poll_aead(ticket).map(|_| ()),
            "poll_native_messages" => session.poll_native_messages(ticket).map(|_| ()),
            _ => common!(session),
        },
        Owner::Advanced(session) => common!(session),
    })
}
