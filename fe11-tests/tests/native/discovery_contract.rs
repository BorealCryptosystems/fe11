// SPDX-License-Identifier: Apache-2.0
//! Public discovery calls checked against a pinned recipe and exact native errors.
use super::{
    configuration::{Budgets, Configuration},
    module_controls,
    outcome::Failure,
    report::{Observation, Phase, Producer, Report},
};
use fe11::*;
use std::{
    collections::{BTreeMap, BTreeSet},
    fs::File,
    io::{self, Read, Write},
    path::Path,
};

struct Case {
    action: String,
    catalogue: BTreeMap<u64, (u64, u64, u64)>,
}

fn read(path: &Path) -> std::result::Result<Case, Failure> {
    let mut data = String::new();
    File::open(path)
        .map_err(|_| Failure::Input("discovery_fixture_open"))?
        .take(65537)
        .read_to_string(&mut data)
        .map_err(|_| Failure::Input("discovery_fixture_read"))?;
    if data.len() > 65536 {
        return Err(Failure::Input("discovery_fixture_size"));
    }
    let mut lines = data.lines();
    let action = lines
        .next()
        .ok_or(Failure::Input("discovery_fixture_action"))?;
    if !matches!(
        action,
        "identifier_widths" | "slots" | "metadata" | "catalogue" | "unknown_slot" | "unknown_mechanism" | "poll" | "wait"
    ) {
        return Err(Failure::Input("discovery_fixture_action"));
    }
    let mut catalogue = BTreeMap::new();
    for line in lines {
        let fields = line
            .split('\t')
            .map(str::parse::<u64>)
            .collect::<std::result::Result<Vec<_>, _>>()
            .map_err(|_| Failure::Input("discovery_fixture_number"))?;
        if fields.len() != 4
            || fields[1] > fields[2]
            || catalogue.len() >= 512
            || catalogue
                .insert(fields[0], (fields[1], fields[2], fields[3]))
                .is_some()
        {
            return Err(Failure::Input("discovery_fixture_catalogue"));
        }
    }
    if matches!(action, "catalogue" | "identifier_widths") == catalogue.is_empty() {
        return Err(Failure::Input("discovery_fixture_payload"));
    }
    Ok(Case {
        action: action.into(),
        catalogue,
    })
}

fn require(condition: bool, name: &'static str) -> std::result::Result<(), Failure> {
    if condition {
        Ok(())
    } else {
        Err(Failure::Oracle(name))
    }
}

fn native_error<T>(
    result: fe11::Result<T>,
    function: &'static str,
    code: u64,
) -> std::result::Result<(), Failure> {
    match result {
        Err(Error::Native {
            function: actual,
            code: actual_code,
            ..
        }) if actual == function && actual_code == code => Ok(()),
        Err(error) => Err(error.into()),
        Ok(_) => Err(Failure::Oracle("discovery_negative_accepted")),
    }
}

/// Numeric selectors have two independent domains: a slot may exist while a
/// mechanism with the same number is unknown, and vice versa.
fn identifier_widths(
    module: &Module,
    selected: u64,
    present: &[u64],
    catalogue: &BTreeMap<u64, (u64, u64, u64)>,
) -> std::result::Result<(), Failure> {
    let slots = module.slot_ids(false)?;
    let sha = fe11_sys::CKM_SHA256 as u64;
    let expected_sha = catalogue.get(&sha).ok_or(Failure::Input("sha256_in_catalogue"))?;
    for value in [0, 1, u32::MAX as u64, u32::MAX as u64 + 1, u64::MAX] {
        let exists = slots.contains(&value);
        // The separate unknown-slot scenario already exercises u32::MAX.
        if value != u32::MAX as u64 {
            let info = module.slot_info(value);
            if exists {
                require((info?.flags & fe11_sys::CKF_TOKEN_PRESENT as u64 != 0)
                    == present.contains(&value), "width_slot_presence")?;
            } else {
                native_error(info, "C_GetSlotInfo", fe11_sys::CKR_SLOT_ID_INVALID as u64)?;
            }
        }
        let token = module.token_info(value);
        if present.contains(&value) {
            let flags = token?.flags;
            require((flags & fe11_sys::CKF_TOKEN_INITIALIZED as u64 != 0) == (value == selected),
                "width_token_identity")?;
        } else {
            let rv = if exists { fe11_sys::CKR_TOKEN_NOT_PRESENT } else { fe11_sys::CKR_SLOT_ID_INVALID };
            native_error(token, "C_GetTokenInfo", rv as u64)?;
        }
        let list = module.mechanism_ids(value);
        let slot_info = module.mechanism_info(value, sha);
        if exists {
            let ids: BTreeSet<_> = list?.into_iter().collect();
            require(ids == catalogue.keys().copied().collect(), "width_slot_mechanisms")?;
            let info = slot_info?;
            require((info.minimum, info.maximum, info.flags) == *expected_sha, "width_slot_sha256")?;
        } else {
            native_error(list, "C_GetMechanismList", fe11_sys::CKR_SLOT_ID_INVALID as u64)?;
            native_error(slot_info, "C_GetMechanismInfo", fe11_sys::CKR_SLOT_ID_INVALID as u64)?;
        }
        let mechanism_info = module.mechanism_info(selected, value);
        match catalogue.get(&value) {
            Some(expected) => {
                let actual = mechanism_info?;
                require((actual.minimum, actual.maximum, actual.flags) == *expected,
                    "width_numeric_mechanism")?;
            }
            None => native_error(mechanism_info, "C_GetMechanismInfo",
                fe11_sys::CKR_MECHANISM_INVALID as u64)?,
        }
    }
    Ok(())
}

fn check<W: Write>(
    module: &Module,
    slot: u64,
    slots: &[u64],
    config: &Configuration,
    case: &Case,
    report: &mut Report<W>,
) -> std::result::Result<(), Failure> {
    match case.action.as_str() {
        "slots" => {
            let all = module.slot_ids(false)?;
            let present = module.slot_ids(true)?;
            let unique: BTreeSet<_> = all.iter().copied().collect();
            require(
                all.len() == unique.len() && present.iter().all(|s| unique.contains(s)),
                "discovery_token_subset",
            )?;
            require(
                present.iter().copied().collect::<BTreeSet<_>>() == slots.iter().copied().collect(),
                "discovery_stable_slots",
            )?;
            // This recipe includes an uninitialized token; it cannot produce
            // an empty native slot list. Record its actual nonempty result.
            require(!present.is_empty(), "discovery_nonempty_recipe")?;
        }
        "metadata" => {
            for slot in slots {
                require(
                    module.slot_info(*slot)? == module.slot_info(*slot)?,
                    "discovery_fixed_slot_metadata",
                )?;
            }
            let token = module.token_info(slot)?;
            let mut label = [b' '; 32];
            if config.label.len() > label.len() {
                return Err(Failure::Input("discovery_label"));
            }
            label[..config.label.len()].copy_from_slice(config.label.as_bytes());
            require(
                token.label == label && token.flags & fe11_sys::CKF_TOKEN_INITIALIZED as u64 != 0,
                "discovery_exact_label_and_initialized",
            )?;
        }
        "identifier_widths" => {
            identifier_widths(module, slot, slots, &case.catalogue)?;
        }
        "catalogue" => {
            let ids = module.mechanism_ids(slot)?;
            let unique: BTreeSet<_> = ids.iter().copied().collect();
            require(
                ids.len() == unique.len() && unique == case.catalogue.keys().copied().collect(),
                "discovery_complete_catalogue",
            )?;
            for (id, &(minimum, maximum, flags)) in &case.catalogue {
                let actual = module.mechanism_info(slot, *id)?;
                require(
                    actual.minimum == minimum && actual.maximum == maximum && actual.flags == flags,
                    "discovery_exact_mechanism_metadata",
                )?;
            }
            report
                .observation(
                    Phase::Body,
                    "discovery_mechanisms_checked",
                    Producer::TestOracle,
                    Observation::Number(ids.len() as u64),
                )
                .map_err(|_| Failure::Input("report_write"))?;
        }
        "unknown_slot" => {
            require(
                !module.slot_ids(false)?.contains(&0xffff_ffff),
                "unknown_slot_fixture_membership",
            )?;
            native_error(
                module.slot_info(0xffff_ffff),
                "C_GetSlotInfo",
                fe11_sys::CKR_SLOT_ID_INVALID as u64,
            )?;
        }
        "unknown_mechanism" => {
            let ids = module.mechanism_ids(slot)?;
            let mechanism = fe11_sys::CKM_RC2_ECB as u64;
            require(
                !ids.contains(&mechanism),
                "unknown_mechanism_fixture_membership",
            )?;
            native_error(
                module.mechanism_info(slot, mechanism),
                "C_GetMechanismInfo",
                fe11_sys::CKR_MECHANISM_INVALID as u64,
            )?;
        }
        "poll" => require(
            matches!(module.poll_slot_event()?, SlotEvent::NoEvent),
            "discovery_no_event",
        )?,
        "wait" => native_error(
            module.wait_slot_event(),
            "C_WaitForSlotEvent",
            fe11_sys::CKR_FUNCTION_NOT_SUPPORTED as u64,
        )?,
        _ => return Err(Failure::Input("discovery_action")),
    }
    Ok(())
}

pub fn execute<W: Write>(
    config: &Configuration,
    path: &Path,
    mut report: Report<W>,
) -> io::Result<bool> {
    let mut module = None;
    let setup = (|| -> std::result::Result<(Case, u64, Vec<u64>), Failure> {
        let case = read(path)?;
        module = Some(
            config
                .builder(&Budgets::ordinary())
                .discovery(DiscoverySelection::Deferred)
                .open()?,
        );
        let owner = module.as_ref().ok_or(Failure::Input("discovery_owner"))?;
        let slots = owner.slot_ids(true)?;
        let mut selected = None;
        for slot in &slots {
            let token = owner.token_info(*slot)?;
            let length = token
                .label
                .iter()
                .rposition(|b| *b != b' ')
                .map_or(0, |n| n + 1);
            if &token.label[..length] == config.label.as_bytes() {
                if selected.replace(*slot).is_some() {
                    return Err(Failure::Input("discovery_duplicate_token"));
                }
            }
        }
        Ok((
            case,
            selected.ok_or(Failure::Input("discovery_token"))?,
            slots,
        ))
    })();
    let body = match (&module, &setup) {
        (Some(module), Ok((case, slot, slots))) => {
            check(module, *slot, slots, config, case, &mut report)
        }
        (_, Err(_)) => Ok(()),
        _ => Err(Failure::Input("discovery_owner")),
    };
    let mut cleanup = Vec::new();
    if let Some(module) = module {
        if let Err(error) = module.close() {
            cleanup.push(error.into());
        }
    }
    module_controls::finish(report, setup.map(|_| ()), body, cleanup)
}
