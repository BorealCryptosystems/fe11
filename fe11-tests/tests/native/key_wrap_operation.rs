// SPDX-License-Identifier: Apache-2.0
//! Exact wrap bytes, recovered key values, and independent cleanup outcomes.
use super::{
    key_wrap_fixture as fixture,
    object_owner::Owner,
    outcome::{self, Failure},
    report::{Observation, Phase, Producer, Report},
};
use fe11::*;
use std::io::Write;

#[path = "key_wrap_attributes.rs"]
mod attributes;

pub fn check<W: Write>(
    owner: &Owner,
    kek: &NativeObjectRef,
    target: Option<&NativeObjectRef>,
    vector: &fixture::Vector,
    controlled: bool,
    report: &mut Report<W>,
    cleanup: &mut Vec<Failure>,
) -> std::result::Result<(), Failure> {
    if controlled {
        return controlled_unwrap(owner, kek, target, vector, report, cleanup);
    }
    if let Some(check) = vector
        .check
        .as_ref()
        .filter(|check| check.as_str() != "attributes")
    {
        if check == "kwp-absent" {
            return absent_kwp(owner, kek, target, vector, cleanup);
        }
        return check_wrap_contract(
            owner,
            kek,
            target.ok_or(Failure::Input("wrap_contract_target"))?,
            vector,
            check,
        );
    }
    // NULL IV and the explicit RFC 3394 default must have identical semantics.
    // They are two requests, never a retry following an error.
    // Attribute-contract cases use the accepted NULL-IV tuple only. Optional
    // explicit-IV support belongs to the separate wrapping vector scenarios.
    let iv_forms = &[false, true][..if vector.check.as_deref() == Some("attributes") {
        1
    } else {
        2
    }];
    for &explicit in iv_forms {
        if vector.unwrap {
            unwrap(owner, kek, vector, explicit, report, cleanup)?;
        } else {
            let target = target.ok_or(Failure::Input("wrap_target"))?;
            let parameters = fixture::parameters(explicit);
            let wrapped = match owner {
                Owner::Session(session) => {
                    session.wrap_native_key(kek, target, parameters, vector.ciphertext.len())
                }
                Owner::Advanced(session) => {
                    session.wrap_native_key(kek, target, parameters, vector.ciphertext.len())
                }
            }?;
            if wrapped.as_bytes() != vector.ciphertext {
                return Err(Failure::Oracle("wrapped_key_bytes"));
            }
        }
    }
    Ok(())
}

fn absent_kwp(
    owner: &Owner,
    kek: &NativeObjectRef,
    target: Option<&NativeObjectRef>,
    vector: &fixture::Vector,
    cleanup: &mut Vec<Failure>,
) -> std::result::Result<(), Failure> {
    let target = target.ok_or(Failure::Input("kwp_target"))?;
    let parameters = || NativeTransportParameters::Fixed {
        mechanism: NativeTransportMechanism::AES_KEY_WRAP_KWP,
        bytes: None,
    };
    let wrapped = match owner {
        Owner::Session(s) => s.wrap_native_key(kek, target, parameters(), 64),
        Owner::Advanced(s) => s.wrap_native_key(kek, target, parameters(), 64),
    };
    match wrapped {
        Err(Error::Native {
            function: "C_WrapKey",
            code,
            may_have_effect: false,
        }) if code == fe11_sys::CKR_MECHANISM_INVALID as u64 => (),
        Err(error) => return Err(error.into()),
        Ok(_) => return Err(Failure::Oracle("absent_kwp_wrap_accepted")),
    }
    let attributes = fixture::template();
    let template = GenerationTemplate {
        attributes: &attributes,
        limits: fixture::limits(attributes.len(), 0),
        observation: None,
        destination: DestinationPlan {
            search: DestinationSearchPlan::NotRequested,
            user: DestinationUserObservation::NotRequested,
        },
    };
    let unwrapped = match owner {
        Owner::Session(s) => s.unwrap_native_key(
            kek,
            &vector.ciphertext,
            parameters(),
            ManagedClass::SecretKey,
            template,
        ),
        Owner::Advanced(s) => s.unwrap_native_key(
            kek,
            &vector.ciphertext,
            parameters(),
            ManagedClass::SecretKey,
            template,
        ),
    };
    match unwrapped {
        Err(Error::Native {
            function: "C_UnwrapKey",
            code,
            may_have_effect: true,
        }) if code == fe11_sys::CKR_MECHANISM_INVALID as u64 => Ok(()),
        Err(error) => Err(error.into()),
        Ok(created) => {
            // Unexpected creation still owns objects: clean them independently
            // of the failed oracle and never discard a publication failure.
            for object in created.objects.as_slice() {
                if let Err(error) = fixture::destroy(owner, object) {
                    cleanup.push(error.into());
                }
            }
            Err(Failure::Oracle("absent_kwp_unwrap_accepted"))
        }
    }
}

fn check_wrap_contract(
    owner: &Owner,
    kek: &NativeObjectRef,
    target: &NativeObjectRef,
    vector: &fixture::Vector,
    check: &str,
) -> std::result::Result<(), Failure> {
    let wrap = |capacity| match owner {
        Owner::Session(s) => s.wrap_native_key(kek, target, fixture::parameters(false), capacity),
        Owner::Advanced(s) => s.wrap_native_key(kek, target, fixture::parameters(false), capacity),
    };
    if check == "capacity" {
        let length = vector.ciphertext.len();
        let short = length
            .checked_sub(1)
            .ok_or(Failure::Input("wrap_contract_length"))?;
        let large = length
            .checked_add(1)
            .ok_or(Failure::Input("wrap_contract_length"))?;
        for capacity in [0, short, length, large] {
            match wrap(capacity) {
                Err(Error::OutputBufferTooSmall {
                    function: "C_WrapKey",
                    code: 0x150,
                    required,
                    capacity: supplied,
                }) if capacity < length && required == length && supplied == capacity => (),
                Ok(value) if capacity >= length && value.as_bytes() == vector.ciphertext => (),
                Err(error) => return Err(error.into()),
                Ok(_) => return Err(Failure::Oracle("wrap_capacity_exact_bytes")),
            }
        }
    } else {
        let expected = match check {
            "nonextractable" => fe11_sys::CKR_KEY_UNEXTRACTABLE as u64,
            "untrusted" => fe11_sys::CKR_KEY_NOT_WRAPPABLE as u64,
            _ => return Err(Failure::Input("wrap_contract_selector")),
        };
        match wrap(vector.ciphertext.len()) {
            Err(Error::Native {
                function: "C_WrapKey",
                code,
                may_have_effect: false,
            }) if code == expected => (),
            Err(error) => return Err(error.into()),
            Ok(_) => return Err(Failure::Oracle("wrap_policy_not_enforced")),
        }
    }
    Ok(())
}

fn controlled_unwrap<W: Write>(
    owner: &Owner,
    kek: &NativeObjectRef,
    target: Option<&NativeObjectRef>,
    vector: &fixture::Vector,
    report: &mut Report<W>,
    cleanup: &mut Vec<Failure>,
) -> std::result::Result<(), Failure> {
    let target = target.ok_or(Failure::Input("positive_wrap_target"))?;
    let wrapped = match owner {
        Owner::Session(session) => {
            session.wrap_native_key(kek, target, fixture::parameters(false), 24)
        }
        Owner::Advanced(session) => {
            session.wrap_native_key(kek, target, fixture::parameters(false), 24)
        }
    }?;
    if wrapped.as_bytes().len() != 24 {
        return Err(Failure::Oracle("positive_wrapped_key_length"));
    }
    let control = fixture::Vector {
        advanced: vector.advanced,
        unwrap: true,
        valid: true,
        kek: vector.kek.clone(),
        plaintext: vec![0x5a; 16],
        ciphertext: wrapped.as_bytes().to_vec(),
        check: None,
    };
    // This control proves native use of the exact same KEK and template. It is
    // a roundtrip witness, not an independent AES known-answer verification.
    unwrap(owner, kek, &control, false, report, cleanup)?;
    let negative = unwrap(owner, kek, vector, false, report, cleanup);
    match &negative {
        Ok(())
        | Err(Failure::Product(Error::Native {
            function: "C_UnwrapKey",
            ..
        })) => (),
        _ => return negative,
    }
    // A diagnostic mismatch remains a failure. Do not hide it by accepting the
    // subsequent control or by repeating the negative with different parameters.
    // GENERAL_ERROR leaves an unknown creation at this destination. A second
    // creation cannot be used as a control until that uncertainty is resolved.
    // Wrap the existing target instead: it uses the same KEK without requesting
    // another object, and the deterministic RFC 3394 bytes must be unchanged.
    let after = (|| -> std::result::Result<(), Failure> {
        let result = match owner {
            Owner::Session(session) => {
                session.wrap_native_key(kek, target, fixture::parameters(false), 24)
            }
            Owner::Advanced(session) => {
                session.wrap_native_key(kek, target, fixture::parameters(false), 24)
            }
        }?;
        if result.as_bytes() != control.ciphertext {
            return Err(Failure::Oracle("positive_wrap_after_negative_bytes"));
        }
        Ok(())
    })();
    if let Err(error) = &negative {
        if after.is_err() {
            outcome::record(report, Phase::Body, error)
                .map_err(|_| Failure::Input("report_write"))?;
        }
    }
    after?;
    report
        .observation(
            Phase::Body,
            "same_kek_positive_controls_complete",
            Producer::TestOracle,
            Observation::Boolean(true),
        )
        .map_err(|_| Failure::Input("report_write"))?;
    negative
}

fn unwrap<W: Write>(
    owner: &Owner,
    kek: &NativeObjectRef,
    vector: &fixture::Vector,
    explicit: bool,
    report: &mut Report<W>,
    cleanup: &mut Vec<Failure>,
) -> std::result::Result<(), Failure> {
    let attributes = fixture::template();
    let template = GenerationTemplate {
        attributes: &attributes,
        limits: fixture::limits(attributes.len(), 0),
        observation: None,
        destination: DestinationPlan {
            search: DestinationSearchPlan::NotRequested,
            user: DestinationUserObservation::NotRequested,
        },
    };
    let parameters = fixture::parameters(explicit);
    let result = match owner {
        Owner::Session(session) => session.unwrap_native_key(
            kek,
            &vector.ciphertext,
            parameters,
            ManagedClass::SecretKey,
            template,
        ),
        Owner::Advanced(session) => session.unwrap_native_key(
            kek,
            &vector.ciphertext,
            parameters,
            ManagedClass::SecretKey,
            template,
        ),
    };
    match result {
        Ok(created) => {
            // Retain cleanup references even if the optional publication failed.
            // A negative that unexpectedly creates a key is still cleaned up.
            let checked = (|| -> std::result::Result<(), Failure> {
                if !vector.valid {
                    return Err(Failure::Oracle("invalid_wrapped_key_accepted"));
                }
                if created.objects.as_slice().len() != 1 || created.remainder.is_some() {
                    return Err(Failure::Oracle("unwrap_creation_count"));
                }
                let observed = created
                    .observation
                    .as_ref()
                    .map_err(|error| Failure::Product(error.clone()))?;
                if vector.check.as_deref() == Some("attributes") {
                    attributes::check(owner, observed.object.native())?;
                }
                let plan = FlatAttributeReadPlan::Buffer {
                    capacity: vector.plaintext.len(),
                };
                let value = match owner {
                    Owner::Session(session) => session.read_flat_attribute(
                        observed.object.native(),
                        StandardAttribute::VALUE,
                        plan,
                    ),
                    Owner::Advanced(session) => session.read_flat_attribute(
                        observed.object.native(),
                        StandardAttribute::VALUE,
                        plan,
                    ),
                }?;
                if value.calls != (AttributeReadCalls::Direct { code: 0 }) {
                    return Err(Failure::Oracle("unwrapped_value_native_code"));
                }
                match value.value {
                    FlatAttributeValue::Available(bytes)
                        if bytes.as_bytes() == vector.plaintext =>
                    {
                        Ok(())
                    }
                    _ => Err(Failure::Oracle("unwrapped_key_bytes")),
                }
            })();
            for object in created.objects.as_slice() {
                if let Err(error) = fixture::destroy(owner, object) {
                    cleanup.push(error.into());
                }
            }
            checked
        }
        Err(
            error @ Error::Native {
                function: "C_UnwrapKey",
                code,
                may_have_effect: true,
                ..
            },
        ) if !vector.valid
            && (code == fe11_sys::CKR_WRAPPED_KEY_INVALID as u64
                || code == fe11_sys::CKR_WRAPPED_KEY_LEN_RANGE as u64) =>
        {
            // Native rejection and lack of a proven cleanup target are separate
            // facts. The result must retain conservative creation uncertainty.
            outcome::record(report, Phase::Body, &Failure::Product(error))
                .map_err(|_| Failure::Input("report_write"))?;
            Ok(())
        }
        Err(error) => Err(error.into()),
    }
}
