// SPDX-License-Identifier: Apache-2.0
//! Compare managed and native HMAC routes using the same imported object.
use super::{
    arguments::hex, configuration::Configuration, module_controls, object_owner::Owner,
    outcome::Failure, report::Report, selection_symmetric,
};
use fe11::*;
use std::{
    fs::File,
    io::{self, Read, Write},
    path::Path,
};

struct Vector {
    key: Vec<u8>,
    message: Vec<u8>,
    tag: Vec<u8>,
}

fn read(path: &Path) -> std::result::Result<Vector, Failure> {
    let mut text = String::new();
    File::open(path)
        .map_err(|_| Failure::Input("mac_equivalence_open"))?
        .take(2049)
        .read_to_string(&mut text)
        .map_err(|_| Failure::Input("mac_equivalence_read"))?;
    let fields: Vec<_> = text.split_terminator('\n').collect();
    if text.len() > 2048 || fields.len() != 3 {
        return Err(Failure::Input("mac_equivalence_dimensions"));
    }
    let result = Vector {
        key: hex(fields[0], 131).map_err(Failure::Input)?,
        message: hex(fields[1], 54).map_err(Failure::Input)?,
        tag: hex(fields[2], 32).map_err(Failure::Input)?,
    };
    if result.key.len() != 131 || result.message.len() != 54 || result.tag.len() != 32 {
        return Err(Failure::Input("mac_equivalence_vector_width"));
    }
    Ok(result)
}

fn check(
    session: &Session,
    key: &IntroducedSymmetricKey,
    vector: &Vector,
) -> std::result::Result<(), Failure> {
    let native = key.managed().native_object();
    let parts = [
        &vector.message[..1],
        &vector.message[1..1],
        &vector.message[1..],
    ];
    let limits = InputLimits {
        maximum_parts: 3,
        maximum_total_bytes: vector.message.len(),
    };
    for route in [MessageRoute::Single, MessageRoute::Multipart] {
        let whole = [vector.message.as_slice()];
        let input = if route == MessageRoute::Single {
            whole.as_slice()
        } else {
            parts.as_slice()
        };
        let managed = if route == MessageRoute::Single {
            session.compute_introduced_mac(key, &vector.message, limits)?
        } else {
            session.compute_introduced_mac_multipart(key, input, limits)?
        };
        let raw = session.compute_native_mac(
            &native,
            NativeMacParameters::Full(NativeMacAlgorithm::SHA256_HMAC),
            route,
            input,
            limits,
            32,
            None,
        )?;
        // Neither implementation is the other's oracle: each must match RFC4231.
        if managed.as_bytes() != vector.tag || raw.as_bytes() != vector.tag {
            return Err(Failure::Oracle("mac_equivalence_published_tag"));
        }
        let verified = if route == MessageRoute::Single {
            session.verify_introduced_mac(key, &vector.message, &vector.tag, limits)?
        } else {
            session.verify_introduced_mac_multipart(key, input, &vector.tag, limits)?
        };
        if verified != Verification::Valid {
            return Err(Failure::Oracle("mac_equivalence_managed_verification"));
        }
        session.verify_native_mac(
            &native,
            NativeMacParameters::Full(NativeMacAlgorithm::SHA256_HMAC),
            route,
            input,
            &vector.tag,
            limits,
            None,
        )?;
    }
    Ok(())
}

pub fn execute<W: Write>(
    module: Module,
    config: &Configuration,
    path: &Path,
    report: Report<W>,
) -> io::Result<bool> {
    let mut owner = None;
    let mut objects = None;
    let setup = (|| -> std::result::Result<(Vector, IntroducedSymmetricKey), Failure> {
        let vector = read(path)?;
        owner = Some(Owner::open(&module, config, false)?);
        let Some(Owner::Session(session)) = &owner else {
            return Err(Failure::Input("mac_equivalence_owner"));
        };
        let mut spec = selection_symmetric::introduced();
        spec.key.algorithm = SymmetricAlgorithm::HmacSha256 {
            key_length: vector.key.len(),
        };
        spec.key.hmac_key_type = Some(HmacKeyType::Generic);
        spec.key.usages = KeyUsageRequest {
            sign: Some(true),
            verify: Some(true),
            ..KeyUsageRequest::omitted()
        };
        let mut material = SecretBytes::new(vector.key.len())?;
        material.as_mut_slice().copy_from_slice(&vector.key);
        let created = session.import_symmetric_key(spec, material)?;
        // Preserve destruction rights before inspecting a fallible observation.
        objects = Some(created.objects);
        if created.remainder.is_some() || objects.as_ref().map_or(0, |o| o.as_slice().len()) != 1 {
            return Err(Failure::Oracle("mac_equivalence_import_count"));
        }
        Ok((vector, created.observation?))
    })();
    let body = match (&setup, &owner) {
        (Ok((vector, key)), Some(Owner::Session(session))) => check(session, key, vector),
        _ => Ok(()),
    };
    let mut cleanup = Vec::new();
    if let (Some(Owner::Session(session)), Some(objects)) = (&owner, &objects) {
        for object in objects.as_slice() {
            if let Err(e) = session.destroy_native_object(object) {
                cleanup.push(e.into());
            }
        }
    }
    if let Some(owner) = &owner {
        cleanup.extend(owner.close(None));
    }
    drop(owner);
    if let Err(e) = module.close() {
        cleanup.push(e.into());
    }
    module_controls::finish(report, setup.map(|_| ()), body, cleanup)
}
