// SPDX-License-Identifier: Apache-2.0
//! Identity checks on capacity setters and digest continuations.
use super::{object_owner::Owner, outcome::Failure};
use fe11::*;

pub fn expected(method: &str) -> Option<RejectionReason> {
    Some(match method {
        "provide_digest_output_capacity"
        | "provide_extension_digest_output_capacity"
        | "digest_update"
        | "finish_digest"
        | "finish_native_digest"
        | "finish_extension_digest_stream" => {
            OperationOwnershipRejection::ForeignOrConsumedDigestTicket.into()
        }
        "resize_aes_output" | "resize_cipher_output" => {
            OperationOwnershipRejection::ForeignOrConsumedCipherTicket.into()
        }
        "provide_signature_output_capacity" => {
            OperationOwnershipRejection::ForeignOrConsumedSignatureTicket.into()
        }
        "prepare_aead_message_output" => {
            OperationOwnershipRejection::ForeignOrConsumedAeadMessageTicket.into()
        }
        _ => return None,
    })
}

pub fn invoke(
    owner: &Owner,
    method: &str,
    ticket: &mut OperationTicket,
) -> std::result::Result<Result<()>, Failure> {
    // These actions precede body-family inspection. A real foreign or consumed
    // digest ticket supplies the rejected identity without fabricating a handle.
    macro_rules! call {
        ($session:expr) => {
            match method {
                "provide_digest_output_capacity" => {
                    $session.provide_digest_output_capacity(ticket, 32)
                }
                "provide_extension_digest_output_capacity" => {
                    $session.provide_extension_digest_output_capacity(ticket, 32)
                }
                "resize_aes_output" => $session.resize_aes_output(ticket, 32),
                "resize_cipher_output" => $session.resize_cipher_output(ticket, 32),
                "provide_signature_output_capacity" => {
                    $session.provide_signature_output_capacity(ticket, 256)
                }
                "prepare_aead_message_output" => $session.prepare_aead_message_output(ticket, 16),
                "digest_update" => $session.digest_update(
                    ticket,
                    b"d",
                    InputLimits {
                        maximum_parts: 1,
                        maximum_total_bytes: 1,
                    },
                ),
                "finish_digest" => $session.finish_digest(ticket).map(|_| ()),
                "finish_native_digest" => $session.finish_native_digest(ticket).map(|_| ()),
                "finish_extension_digest_stream" => {
                    $session.finish_extension_digest_stream(ticket).map(|_| ())
                }
                _ => return Err(Failure::Input("ticket_identity_method")),
            }
        };
    }
    Ok(match owner {
        Owner::Session(s) => call!(s),
        Owner::Advanced(s) => call!(s),
    })
}
