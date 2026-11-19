// SPDX-License-Identifier: Apache-2.0
//! Public ticket consumers receive a real foreign or already consumed owner.
use super::{object_owner::Owner, outcome::Failure};
use fe11::*;

pub fn invoke(
    receiver: &Owner,
    method: &str,
    ticket: &mut OperationTicket,
    pin: &[u8],
) -> std::result::Result<(), Failure> {
    let limits = RecordLimits {
        bytes: 1_048_576,
        messages: 1,
        fragments: 1,
    };
    let result = match (receiver, method) {
        (Owner::Session(s), "authenticate_context") => s.authenticate_context(
            ticket,
            ContextAuthentication::login(SecretPin::new(pin.to_vec())),
        ),
        (Owner::Session(s), "poll_signature") => s.poll_signature(ticket).map(|_| ()),
        (Owner::Session(s), "poll_recovery") => s.poll_recovery(ticket).map(|_| ()),
        (Owner::Session(s), "resize_recovery_output") => s.resize_recovery_output(ticket, 256),
        (Owner::Advanced(s), "authenticate_context") => s.authenticate_context(
            ticket,
            ContextAuthentication::login(SecretPin::new(pin.to_vec())),
        ),
        (Owner::Advanced(s), "login_context") => {
            s.login_context(ticket, SecretPin::new(pin.to_vec()))
        }
        (Owner::Advanced(s), "login_context_user") => {
            s.login_context_user(ticket, SecretPin::new(pin.to_vec()), b"user".to_vec())
        }
        (Owner::Advanced(s), "next_native_function") => s.next_native_function(ticket).map(|_| ()),
        (Owner::Advanced(s), "poll" | "poll_published_eager" | "poll_published_cooperative") => {
            s.poll(ticket).map(|_| ())
        }
        (Owner::Advanced(s), "poll_signature") => s.poll_signature(ticket).map(|_| ()),
        (Owner::Advanced(s), "start_state_capture") => {
            s.start_state_capture(ticket, 1_048_576).map(|_| ())
        }
        (Owner::Advanced(s), "poll_state_capture") => s.poll_state_capture(ticket).map(|_| ()),
        (Owner::Advanced(s), "start_detachment") => {
            s.start_detachment(ticket, 1_048_576).map(|_| ())
        }
        (Owner::Advanced(s), "poll_detachment") => s.poll_detachment(ticket).map(|_| ()),
        (Owner::Advanced(s), "capture_gcm_recovery") => {
            s.capture_gcm_recovery(ticket, limits).map(|_| ())
        }
        (Owner::Advanced(s), "capture_dual_gcm_recovery") => {
            s.capture_dual_gcm_recovery(ticket, limits).map(|_| ())
        }
        (Owner::Advanced(s), "capture_ccm_recovery") => {
            s.capture_ccm_recovery(ticket, limits).map(|_| ())
        }
        (Owner::Advanced(s), "capture_stream_aead_recovery") => s
            .capture_stream_aead_recovery(ticket, limits, StreamAeadAlgorithm::ChaCha20)
            .map(|_| ()),
        (Owner::Advanced(s), "capture_stream_aead_recovery_salsa") => s
            .capture_stream_aead_recovery(ticket, limits, StreamAeadAlgorithm::Salsa20)
            .map(|_| ()),
        (Owner::Advanced(s), "resize_recovery_output") => s.resize_recovery_output(ticket, 256),
        // The bounded fixture parser admits only the pairs listed above. This
        // branch remains a harness error, never a synthesized product refusal.
        _ => return Err(Failure::Input("ticket_method_receiver")),
    };
    result.map_err(Failure::from)
}

pub fn begin(owner: &Owner) -> Result<OperationTicket> {
    match owner {
        Owner::Session(s) => s.begin_digest(HashAlgorithm::Sha256),
        Owner::Advanced(s) => s.begin_digest(HashAlgorithm::Sha256),
    }
}

pub fn begin_queued(owner: &Owner) -> std::result::Result<OperationTicket, Failure> {
    let Owner::Advanced(session) = owner else {
        return Err(Failure::Input("publication_advanced_owner"));
    };
    Ok(session.digest(
        HashAlgorithm::Sha256,
        &[b"a", b"b", b"c"],
        InputLimits {
            maximum_parts: 3,
            maximum_total_bytes: 3,
        },
    )?)
}

pub fn finish_queued(
    owner: &Owner,
    ticket: &mut OperationTicket,
) -> std::result::Result<PreparedDigest, Failure> {
    let Owner::Advanced(session) = owner else {
        return Err(Failure::Input("publication_advanced_owner"));
    };
    // The selected synchronous module needs at most Init, three Updates,
    // Final and publication. Pending cannot silently turn this into a retry
    // loop: the exact native-call sequence is checked by the observer.
    for _ in 0..6 {
        match session.poll(ticket)? {
            OperationProgress::Ready | OperationProgress::Pending => (),
            OperationProgress::Digest(value) => return Ok(value),
            _ => return Err(Failure::Oracle("publication_digest_result")),
        }
    }
    Err(Failure::Oracle("publication_digest_not_completed"))
}

pub fn finish(
    owner: &Owner,
    ticket: &mut OperationTicket,
) -> std::result::Result<PreparedDigest, Failure> {
    let limits = InputLimits {
        maximum_parts: 1,
        maximum_total_bytes: 3,
    };
    match owner {
        Owner::Session(s) => {
            s.digest_update(ticket, b"abc", limits)?;
            Ok(s.finish_digest(ticket)?)
        }
        Owner::Advanced(s) => {
            s.digest_update(ticket, b"abc", limits)?;
            match s.finish_digest(ticket)? {
                OperationProgress::Digest(value) => Ok(value),
                _ => Err(Failure::Oracle("ticket_producer_digest_result")),
            }
        }
    }
}
