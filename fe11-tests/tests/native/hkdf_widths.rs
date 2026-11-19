// SPDX-License-Identifier: Apache-2.0
//! Exercise hash selectors through the typed HKDF facades with a real managed base.
use crate::{
    arguments::Arguments, generation_transition_spec::{history, key}, key_wrap_fixture,
    module_controls, object_owner::Owner, outcome::{self, Failure},
    report::{Phase, Report}, selection_additional::{self, Selected},
};
use fe11::*;
use std::{fs::File, io::{self, Read, Write}};

pub(super) fn execute<W: Write>(module: Module, args: &Arguments, mut report: Report<W>)
    -> io::Result<bool> {
    let mut owner = None;
    let mut objects = Vec::new();
    let mut sets = Vec::new();
    let setup = (|| -> std::result::Result<(String, Vec<u64>, HkdfKey), Failure> {
        let mut text = String::new();
        File::open(&args.vector).and_then(|f| f.take(160).read_to_string(&mut text))
            .map_err(|_| Failure::Input("hkdf_width_fixture"))?;
        let mut lines = text.lines();
        let route = lines.next().ok_or(Failure::Input("hkdf_width_route"))?;
        if !matches!(route, "derive" | "extract" | "expand") {
            return Err(Failure::Input("hkdf_width_route"));
        }
        let mut values = Vec::new();
        for field in lines {
            let value = field.parse::<u64>().map_err(|_| Failure::Input("hkdf_hash_width"))?;
            if ![0, 1, u32::MAX as u64, u32::MAX as u64 + 1, u64::MAX].contains(&value)
                || values.contains(&value) {
                return Err(Failure::Input("hkdf_width_partition"));
            }
            values.push(value);
        }
        if values.is_empty() { return Err(Failure::Input("empty_hkdf_widths")); }
        owner = Some(Owner::open(&module, &args.config, false)?);
        let Some(o @ Owner::Session(session)) = &owner else { return Err(Failure::Input("hkdf_width_session")); };
        if !selection_additional::prepare(session, "hkdf", &mut sets, &mut objects, &mut None)? {
            return Err(Failure::Input("hkdf_width_base"));
        }
        let Selected::Hkdf(base) = selection_additional::find(o, "hkdf", None)? else {
            return Err(Failure::Input("hkdf_width_selection"));
        };
        Ok((route.to_owned(), values, base))
    })();
    let body = (|| -> std::result::Result<(), Failure> {
        let (Ok((route, values, base)), Some(Owner::Session(session))) = (&setup, &owner) else { return Ok(()); };
        for &hash in values {
            // Creation can remain uncertain after a refusal. Give every hash
            // its own destination, so an earlier result cannot mask dispatch.
            let label = format!("hkdf-{route}-{hash}");
            let observation = DerivationObservationPlan { parent: history(), child: history() };
            let mut target = key(&label);
            target.persistent = false;
            let result = match route.as_str() {
                "derive" => session.derive_hkdf_with_hash(base, hash, HkdfSalt::Null,
                    b"width", target, observation).map(|v| v.objects),
                "expand" => session.expand_hkdf_with_hash(base, hash, b"width",
                    target, observation).map(|v| v.objects),
                _ => {
                    let mut extracted = selection_additional::hkdf();
                    extracted.id = label.as_bytes().to_vec();
                    extracted.label = label;
                    session.extract_hkdf_with_hash(base, hash, HkdfSalt::Null, extracted,
                        CurrentKeyProtection { sensitive: false, extractable: true }, observation)
                        .map(|v| v.objects)
                }
            };
            match result {
                Err(error @ Error::Native { function: "C_DeriveKey", code: 112, .. }) => {
                    outcome::record(&mut report, Phase::Body, &Failure::Product(error))
                        .map_err(|_| Failure::Input("hkdf_width_observation_write"))?;
                }
                Err(error) => return Err(error.into()),
                Ok(created) => {
                    sets.push(created);
                    return Err(Failure::Oracle("unexpected_hkdf_width_success"));
                }
            }
        }
        Ok(())
    })();
    let setup = setup.map(|_| ());
    let mut cleanup = Vec::new();
    if let Some(o) = &owner {
        for object in sets.iter().flat_map(|set| set.as_slice()).chain(objects.iter()).rev() {
            if let Err(e) = key_wrap_fixture::destroy(o, object) { cleanup.push(e.into()); }
        }
        cleanup.extend(o.close(None));
    }
    drop(sets);
    drop(objects);
    drop(owner);
    if let Err(e) = module.close() { cleanup.push(e.into()); }
    module_controls::finish(report, setup, body, cleanup)
}
