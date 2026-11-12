// SPDX-License-Identifier: Apache-2.0
//! Discover selected slots, token information and mechanism observations.
//! Each native result belongs to its retained frame and the current slot context.

use super::*;

// Classify before returning the original native error, including initial
// discovery before a State exists. Token retirement uses captured observations.
pub(crate) fn check_discovery(native: &Native, rv: CK_RV, function: &'static str) -> Result<()> {
    native.observe_runtime_return(rv);
    let scope = crate::native_return::slot_scope(function, rv);
    if scope == crate::native_return::FailureScope::Module {
        native.mark_uncertain();
    }
    check(
        rv,
        function,
        matches!(
            scope,
            crate::native_return::FailureScope::Token | crate::native_return::FailureScope::Module
        ),
    )
}

pub(super) fn list<T: Copy + Default>(
    native: &Native,
    name: &'static str,
    limit: usize,
    attempts: usize,
    mut call: impl FnMut(*mut T, *mut CK_ULONG) -> CK_RV,
) -> Result<Vec<T>> {
    // The caller bounds sizing/fill attempts. Initialized output storage is
    // never read beyond the provider's checked final length.
    for attempt in 0..attempts {
        let mut frame = crate::native::frame::NativeFrame::new(DiscoveryListFrame {
            count: 0,
            values: Vec::<T>::new(),
        })?;

        native.record(name)?;
        let rv = call(std::ptr::null_mut(), &mut frame.count);
        frame.retain_if_pending(rv, native);
        check_discovery(native, rv, name)?;
        if frame.count == CK_UNAVAILABLE_INFORMATION {
            return Err(Error::Rejected(crate::RejectionReason::ModuleLifecycle(
                crate::ModuleLifecycleRejection::UnavailableDiscoveryCount,
            )));
        }
        let n = usize::try_from(frame.count).map_err(|_| {
            Error::Rejected(crate::RejectionReason::ModuleLifecycle(
                crate::ModuleLifecycleRejection::DiscoveryLengthConversion,
            ))
        })?;
        if n > limit {
            return Err(Error::Rejected(crate::RejectionReason::ModuleLifecycle(
                crate::ModuleLifecycleRejection::DiscoveryItemBudgetAfterSizing,
            )));
        }
        if n == 0 {
            // A successful sizing call already observed an empty list.
            // A second null-pointer call would be another sizing query,
            // not a fill whose returned count can be checked against zero.
            return Ok(Vec::new());
        }
        n.checked_mul(std::mem::size_of::<T>())
            .filter(|bytes| *bytes <= isize::MAX as usize)
            .ok_or(Error::Rejected(crate::RejectionReason::ModuleLifecycle(
                crate::ModuleLifecycleRejection::DiscoveryAllocationRepresentation,
            )))?;
        frame.values.try_reserve_exact(n).map_err(|_| {
            Error::Rejected(crate::RejectionReason::ModuleLifecycle(
                crate::ModuleLifecycleRejection::DiscoveryAllocation,
            ))
        })?;
        frame.values.resize(n, T::default());
        native.record(name)?;
        let body = &mut *frame;
        let rv = call(body.values.as_mut_ptr(), &mut body.count);
        frame.retain_if_pending(rv, native);
        if rv == CKR_BUFFER_TOO_SMALL && attempt + 1 < attempts {
            continue;
        }
        check_discovery(native, rv, name)?;
        let final_n = bounds::final_length(frame.count, n).map_err(|error| {
            frame.quarantine(native);
            error
        })?;
        frame.values.truncate(final_n);
        return Ok(std::mem::take(&mut frame.values));
    }
    Err(Error::Rejected(crate::RejectionReason::ModuleLifecycle(
        crate::ModuleLifecycleRejection::DiscoveryAttemptBudgetExhausted,
    )))
}

pub(crate) fn discover_selected(
    native: &Native,
    limits: Limits,
    selection: DiscoverySelection,
    observe: &impl Fn(CK_SLOT_ID, &Error),
) -> Result<DiscoveryReport> {
    let slots = match &selection {
        DiscoverySelection::Deferred => Vec::new(),
        DiscoverySelection::Slots(selected) => {
            if selected.len() > limits.slots {
                return Err(Error::Rejected(crate::RejectionReason::ModuleLifecycle(
                    crate::ModuleLifecycleRejection::SelectedSlotBudget,
                )));
            }
            let mut slots = Vec::new();
            slots.try_reserve_exact(selected.len()).map_err(|_| {
                Error::Rejected(crate::RejectionReason::ModuleLifecycle(
                    crate::ModuleLifecycleRejection::SelectedSlotAllocation,
                ))
            })?;
            for selected in selected {
                slots.push(CK_SLOT_ID::try_from(*selected).map_err(|_| {
                    Error::Rejected(crate::RejectionReason::ModuleLifecycle(
                        crate::ModuleLifecycleRejection::SlotIdentifierConversion,
                    ))
                })?);
            }
            slots
        }
        DiscoverySelection::AllPresentSlots => {
            let get_slots =
                crate::native::functions::resolve(native.table.C_GetSlotList, "C_GetSlotList")?;
            list(
                native,
                "C_GetSlotList",
                limits.slots,
                limits.discovery_attempts,
                |p, n| {
                    // SAFETY: list supplies null sizing or stable initialized bounded storage.
                    unsafe { get_slots(CK_TRUE, p, n) }
                },
            )?
        }
    };
    for (index, slot) in slots.iter().enumerate() {
        if slots[..index].contains(slot) {
            return Err(Error::Rejected(crate::RejectionReason::ModuleLifecycle(
                crate::ModuleLifecycleRejection::DuplicateSlot,
            )));
        }
    }
    let mut out = Vec::new();
    out.try_reserve_exact(slots.len()).map_err(|_| {
        Error::Rejected(crate::RejectionReason::ModuleLifecycle(
            crate::ModuleLifecycleRejection::DiscoverySnapshotAllocation,
        ))
    })?;
    let mut failures = Vec::new();
    failures.try_reserve_exact(slots.len()).map_err(|_| {
        Error::Rejected(crate::RejectionReason::ModuleLifecycle(
            crate::ModuleLifecycleRejection::DiscoveryFailureAllocation,
        ))
    })?;
    for slot in slots {
        match discover_slot(native, limits, slot, observe) {
            Ok(capabilities) => out.push(capabilities),
            Err(error) => {
                if native.is_uncertain() {
                    return Err(error);
                }
                failures.push(SlotDiscoveryFailure {
                    slot: slot as u64,
                    error,
                });
            }
        }
    }
    Ok(DiscoveryReport {
        selection,
        tokens: out,
        failures,
    })
}

pub(crate) fn discover_slot(
    native: &Native,
    limits: Limits,
    slot: CK_SLOT_ID,
    observe: &impl Fn(CK_SLOT_ID, &Error),
) -> Result<Capabilities> {
    discover_slot_inner(native, limits, slot).map_err(|error| {
        observe(slot, &error);
        error
    })
}

pub(super) fn discover_slot_inner(
    native: &Native,
    limits: Limits,
    slot: CK_SLOT_ID,
) -> Result<Capabilities> {
    struct SlotFrame {
        slot: CK_SLOT_INFO,
        token: CK_TOKEN_INFO,
        mechanism: CK_MECHANISM_INFO,
    }
    let mut frame = crate::native::frame::NativeFrame::new(SlotFrame {
        slot: crate::native::output::slot_info(),
        token: crate::native::output::token_info(),
        mechanism: crate::native::output::mechanism_info(),
    })?;

    let get_slot_info =
        crate::native::functions::resolve(native.table.C_GetSlotInfo, "C_GetSlotInfo")?;
    native.record("C_GetSlotInfo")?;
    // SAFETY: aligned initialized output structures of the selected ABI.
    let rv = unsafe { get_slot_info(slot, &mut frame.slot) };
    frame.retain_if_pending(rv, native);
    check_discovery(native, rv, "C_GetSlotInfo")?;

    let get_token_info =
        crate::native::functions::resolve(native.table.C_GetTokenInfo, "C_GetTokenInfo")?;
    native.record("C_GetTokenInfo")?;
    // SAFETY: ti lives through the serialized native call.
    let rv = unsafe { get_token_info(slot, &mut frame.token) };
    frame.retain_if_pending(rv, native);
    check_discovery(native, rv, "C_GetTokenInfo")?;
    // Administrative snapshots include uninitialized tokens; crypto selection
    // still requires CKF_TOKEN_INITIALIZED. No mechanism call on a blank token.
    let mut map = crate::MechanismCatalog::default();
    let mechanisms = if frame.token.flags & CKF_TOKEN_INITIALIZED as CK_FLAGS == 0 {
        Vec::new()
    } else {
        let listed = crate::native::functions::resolve(
            native.table.C_GetMechanismList,
            "C_GetMechanismList",
        )
        .and_then(|get_mechanisms| {
            list(
                native,
                "C_GetMechanismList",
                limits.mechanisms,
                limits.discovery_attempts,
                |p, n| {
                    // SAFETY: same bounded list contract, and token slot came from discovery.
                    unsafe { get_mechanisms(slot, p, n) }
                },
            )
        });
        match listed {
            Ok(mechanisms) => {
                map.set_discovery(crate::MechanismDiscovery::Complete);
                mechanisms
            }
            Err(error) => {
                let scope = match &error {
                    Error::Native { code, .. } => {
                        crate::native_return::diagnostic_context_scope(*code)
                    }
                    _ => crate::native_return::FailureScope::None,
                };
                if native.is_uncertain() || scope != crate::native_return::FailureScope::None {
                    return Err(error);
                }
                map.set_discovery(crate::MechanismDiscovery::Unavailable(error));
                Vec::new()
            }
        }
    };
    for mechanism in mechanisms {
        // Absence is an unavailable observation here, not an operation failure.
        let Some(get_mechanism_info) = native.table.C_GetMechanismInfo else {
            map.insert(mechanism as u64, crate::MechanismObservation::Unavailable)?;
            continue;
        };
        frame.mechanism = crate::native::output::mechanism_info();

        native.record("C_GetMechanismInfo")?;
        // SAFETY: valid output allocation and discovered mechanism/slot values.
        let rv = unsafe { get_mechanism_info(slot, mechanism, &mut frame.mechanism) };
        frame.retain_if_pending(rv, native);
        if rv != CKR_OK
            && crate::native_return::slot_scope("C_GetMechanismInfo", rv)
                == crate::native_return::FailureScope::None
        {
            map.insert(
                mechanism as u64,
                crate::MechanismObservation::Refused { code: rv as u64 },
            )?;
            continue;
        }
        check_discovery(native, rv, "C_GetMechanismInfo")?;
        let mi = &frame.mechanism;
        insert_mechanism(
            &mut map,
            mechanism as u64,
            MechanismInfo {
                minimum: mi.ulMinKeySize as u64,
                maximum: mi.ulMaxKeySize as u64,
                flags: mi.flags as u64,
            },
        )?;
    }
    let ti = &frame.token;
    let si = &frame.slot;
    Ok(Capabilities {
        identity: TokenIdentity {
            slot: slot as u64,
            manufacturer: ti.manufacturerID,
            model: ti.model,
            serial: ti.serialNumber,
        },
        label: ti.label,
        flags: ti.flags as u64,
        minimum_pin_length: ti.ulMinPinLen as u64,
        maximum_pin_length: ti.ulMaxPinLen as u64,
        maximum_sessions: ti.ulMaxSessionCount as u64,
        maximum_read_write_sessions: ti.ulMaxRwSessionCount as u64,
        slot_description: si.slotDescription,
        mechanisms: map,
        observed_at: SystemTime::now(),
    })
}

// Repeated identifiers are harmless only when every observed property agrees.
// The native list is bounded before this reduction; conflicts never overwrite
// an earlier observation or publish a partially discovered token snapshot.
pub(super) fn insert_mechanism(
    map: &mut crate::MechanismCatalog,
    mechanism: u64,
    info: MechanismInfo,
) -> Result<()> {
    map.insert(mechanism, crate::MechanismObservation::Available(info))
}
