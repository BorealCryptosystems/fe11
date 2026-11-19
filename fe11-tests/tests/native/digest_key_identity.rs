// SPDX-License-Identifier: Apache-2.0
//! A valid receiver key must not make a foreign or consumed digest ticket usable.
use super::digest_key_value::ValueCase;
use super::{
    arguments::hex, configuration::Configuration, module_controls, object_owner::Owner,
    outcome::Failure, report::Report, ticket_identity_action as digest,
};
use fe11::*;
use std::{
    fs::File,
    io::{self, Read, Write},
    path::Path,
};

fn read(path: &Path) -> std::result::Result<(bool, bool, Option<ValueCase>), Failure> {
    let mut bytes = Vec::new();
    File::open(path)
        .map_err(|_| Failure::Input("digest_key_identity_open"))?
        .take(65)
        .read_to_end(&mut bytes)
        .map_err(|_| Failure::Input("digest_key_identity_read"))?;
    match bytes.as_slice() {
        b"Session\nforeign\n" => Ok((false, false, None)),
        b"Session\nconsumed\n" => Ok((false, true, None)),
        b"AdvancedSession\nforeign\n" => Ok((true, false, None)),
        b"AdvancedSession\nconsumed\n" => Ok((true, true, None)),
        b"Session\nvalue\n" => Ok((false, false, Some(ValueCase::Sha256))),
        b"AdvancedSession\nvalue\n" => Ok((true, false, Some(ValueCase::Sha256))),
        b"Session\nmd5\n" => Ok((false, false, Some(ValueCase::Md5))),
        b"AdvancedSession\nmd5\n" => Ok((true, false, Some(ValueCase::Md5))),
        b"Session\nsensitive_md5\n" => Ok((false, false, Some(ValueCase::SensitiveMd5))),
        b"AdvancedSession\nsensitive_md5\n" => Ok((true, false, Some(ValueCase::SensitiveMd5))),
        b"Session\nsensitive_sha256\n" => Ok((false, false, Some(ValueCase::SensitiveSha256))),
        b"AdvancedSession\nsensitive_sha256\n" => {
            Ok((true, false, Some(ValueCase::SensitiveSha256)))
        }
        _ => Err(Failure::Input("digest_key_identity_fields")),
    }
}

pub fn execute<W: Write>(
    module: Module,
    config: &Configuration,
    path: &Path,
    report: Report<W>,
) -> io::Result<bool> {
    let parsed = read(path);
    if let Ok((advanced, _, Some(case))) = &parsed {
        return super::digest_key_value::execute(module, config, *advanced, *case, report);
    }
    let mut origin = None;
    let mut other = None;
    let mut key = None;
    let mut ticket = None;
    let mut published = None;
    let mut consumed = false;
    let setup = (|| -> std::result::Result<Vec<u8>, Failure> {
        let (advanced, finished, _) = parsed?;
        consumed = finished;
        origin = Some(Owner::open(&module, config, advanced)?);
        if !consumed {
            other = Some(Owner::open(&module, config, advanced)?);
        }
        let receiver = if consumed { &origin } else { &other };
        let receiver = receiver
            .as_ref()
            .ok_or(Failure::Input("digest_key_receiver"))?;
        // Import the exact real key before starting either digest. Only the
        // ticket identity is invalid at the tested public entry point.
        key = Some(receiver.import_secret(
            &[0; 16],
            fe11_sys::CKK_AES,
            [StandardAttribute::ENCRYPT, StandardAttribute::DECRYPT],
        )?);
        let producer = origin.as_ref().ok_or(Failure::Input("digest_key_origin"))?;
        ticket = Some(digest::begin(producer)?);
        let expected = hex(
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad",
            32,
        )
        .map_err(Failure::Input)?;
        if consumed {
            let value = digest::finish(
                producer,
                ticket.as_mut().ok_or(Failure::Input("digest_key_ticket"))?,
            )?;
            if value.as_bytes() != expected {
                return Err(Failure::Oracle("digest_key_producer_value"));
            }
            published = Some(value);
        }
        Ok(expected)
    })();
    let body = (|| -> std::result::Result<(), Failure> {
        let Ok(expected) = &setup else { return Ok(()) };
        let receiver = if consumed { &origin } else { &other };
        let receiver = receiver
            .as_ref()
            .ok_or(Failure::Input("digest_key_receiver"))?;
        let ticket = ticket.as_mut().ok_or(Failure::Input("digest_key_ticket"))?;
        let key = key.as_ref().ok_or(Failure::Input("digest_key_object"))?;
        let before = module.call_counts()?;
        let result = match receiver {
            Owner::Session(s) => s.digest_key(ticket, key),
            Owner::Advanced(s) => s.digest_key(ticket, key),
        };
        match result {
            Err(Error::Rejected(RejectionReason::OperationOwnership(
                OperationOwnershipRejection::ForeignOrConsumedDigestTicket,
            ))) => (),
            Err(error) => return Err(error.into()),
            Ok(()) => return Err(Failure::Oracle("digest_key_ticket_accepted")),
        }
        if module.call_counts()? != before {
            return Err(Failure::Oracle("digest_key_guard_dispatched"));
        }
        if !consumed {
            let producer = origin.as_ref().ok_or(Failure::Input("digest_key_origin"))?;
            let value = digest::finish(producer, ticket)?;
            if value.as_bytes() != expected {
                return Err(Failure::Oracle("digest_key_original_changed"));
            }
            published = Some(value);
            // The foreign-ticket receiver remains independently usable.
            let mut control = digest::begin(receiver)?;
            if digest::finish(receiver, &mut control)?.as_bytes() != expected {
                return Err(Failure::Oracle("digest_key_receiver_changed"));
            }
        }
        Ok(())
    })();
    let mut cleanup = Vec::new();
    let receiver = if consumed { &origin } else { &other };
    if let Some(receiver) = receiver {
        cleanup.extend(receiver.close(key.as_ref()));
    }
    if !consumed {
        if let Some(producer) = &origin {
            cleanup.extend(producer.close(None));
        }
    }
    drop(key);
    drop(ticket);
    drop(other);
    drop(origin);
    if let Err(error) = module.close() {
        cleanup.push(error.into());
    }
    if let (Ok(expected), Some(value)) = (&setup, &published) {
        if value.as_bytes() != expected {
            cleanup.push(Failure::Oracle("digest_key_published_changed"));
        }
    }
    module_controls::finish(report, setup.map(|_| ()), body, cleanup)
}
