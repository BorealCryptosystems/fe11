// SPDX-License-Identifier: Apache-2.0
//! Observe token initialization refusal while an owned idle session remains open.
use super::{
    configuration::{select_token, Configuration},
    credentials::Credentials,
    outcome::{self, Failure},
    report::{Phase, Report},
};
use fe11::*;
use std::io::Write;

pub(super) fn check<W: Write>(
    module: &Module,
    config: &Configuration,
    pins: &Credentials,
    session: &mut Option<Session>,
    report: &mut Report<W>,
) -> std::result::Result<(), Failure> {
    let identity =
        select_token(module, &config.label).ok_or(Failure::Input("administration_open_token"))?;
    let targets = module.administration_targets()?;
    let target = targets
        .iter()
        .find(|target| target.capabilities().identity == identity)
        .ok_or(Failure::Input("administration_open_target"))?;
    *session = Some(module.select(&identity)?.open_session(true)?);
    let owner = session
        .as_ref()
        .ok_or(Failure::Input("administration_open_session"))?;
    let before = owner.info()?;
    let token = module.token_info(identity.slot)?;
    let result =
        module.reinitialize_token(target, SecretPin::new(pins.officer.to_vec()), "Test Token");
    // Check preservation even when the error producer differs from the oracle.
    // Otherwise a local admission error would hide damage to the live owner.
    let after = owner.info()?;
    let current = module.token_info(identity.slot)?;
    if after.slot != before.slot
        || after.state != before.state
        || after.flags != before.flags
        || current.label != token.label
        || current.serial != token.serial
    {
        return Err(Failure::Oracle("administration_open_session_changed"));
    }
    match result {
        Err(
            error @ Error::Native {
                function: "C_InitToken",
                code,
                ..
            },
        ) if code == fe11_sys::CKR_SESSION_EXISTS as u64 => {
            outcome::record(report, Phase::Body, &Failure::Product(error))
                .map_err(|_| Failure::Input("administration_open_report"))
        }
        Err(error) => Err(error.into()),
        Ok(()) => Err(Failure::Oracle("administration_open_session_reset")),
    }
}

// The caller's per-case store is isolated and removed by the supervisor even
// when the body fails. A successful reset destroys the token-object control.
const RESET_LABEL: &str = "Initialization control";
const CONTROL_VALUE: &[u8] = b"public initialization control";

fn assertion(value: bool, name: &'static str) -> std::result::Result<(), Failure> {
    if value {
        Ok(())
    } else {
        Err(Failure::Oracle(name))
    }
}

fn reset(
    module: &Module,
    target: &TokenAdministrationTarget,
    pin: SecretPin,
    bytes: bool,
) -> Result<()> {
    if bytes {
        let mut label = [b' '; 32];
        label[..RESET_LABEL.len()].copy_from_slice(RESET_LABEL.as_bytes());
        module.reinitialize_token_bytes(target, pin, label)
    } else {
        module.reinitialize_token(target, pin, RESET_LABEL)
    }
}

fn create_control(session: &Session, label: &[u8], token: bool) -> Result<NativeObjectRef> {
    let attribute = |attribute: StandardAttribute, value| AttributeInput {
        attribute: attribute.into(),
        value,
    };
    let template = [
        attribute(
            StandardAttribute::CLASS,
            AttributeInputValue::Unsigned(fe11_sys::CKO_DATA as u64),
        ),
        attribute(
            StandardAttribute::TOKEN,
            AttributeInputValue::Boolean(token),
        ),
        attribute(
            StandardAttribute::PRIVATE,
            AttributeInputValue::Boolean(false),
        ),
        attribute(StandardAttribute::LABEL, AttributeInputValue::Bytes(label)),
        attribute(
            StandardAttribute::VALUE,
            AttributeInputValue::Bytes(CONTROL_VALUE),
        ),
    ];
    session.create_native_object(
        &template,
        AttributeTemplateLimits {
            maximum_depth: 0,
            maximum_attributes: template.len(),
            maximum_value_bytes: std::mem::size_of::<fe11_sys::CK_ULONG>()
                + 2
                + label.len()
                + CONTROL_VALUE.len(),
        },
    )
}

fn read_control(session: &Session, object: &NativeObjectRef) -> std::result::Result<(), Failure> {
    let batch = session.read_flat_attributes(
        object,
        &[FlatAttributeRequest {
            attribute: StandardAttribute::VALUE.into(),
            plan: FlatAttributeReadPlan::Buffer {
                capacity: CONTROL_VALUE.len(),
            },
        }],
        CONTROL_VALUE.len(),
    )?;
    assertion(
        batch.calls()
            == AttributeBatchCalls::One(AttributeBatchCall {
                code: 0,
                attribute_count: 1,
            })
            && batch.len() == 1,
        "initialization_control_attribute_call",
    )?;
    let observation = batch
        .iter()
        .next()
        .ok_or(Failure::Input("initialization_control_attribute"))?;
    assertion(
        matches!(&observation.value, FlatAttributeValue::Available(value)
        if value.as_bytes() == CONTROL_VALUE),
        "initialization_control_value",
    )
}

fn close_control(session: &mut Option<Session>) -> std::result::Result<(), Failure> {
    session
        .as_ref()
        .ok_or(Failure::Input("initialization_control_session"))?
        .close()?;
    *session = None;
    Ok(())
}

pub(super) fn check_preservation<W: Write>(
    module: &Module,
    config: &Configuration,
    pins: &Credentials,
    action: &str,
    session: &mut Option<Session>,
    report: &mut Report<W>,
) -> std::result::Result<(), Failure> {
    let (wrong_pin, bytes) = match action {
        "preserve_open_string" => (false, false),
        "preserve_open_bytes" => (false, true),
        "preserve_pin_string" => (true, false),
        "preserve_pin_bytes" => (true, true),
        _ => return Err(Failure::Input("initialization_preservation_action")),
    };
    assertion(config.label != RESET_LABEL, "initialization_distinct_label")?;
    let identity = select_token(module, &config.label)
        .ok_or(Failure::Input("initialization_preservation_token"))?;
    let targets = module.administration_targets()?;
    let target = targets
        .iter()
        .find(|target| target.capabilities().identity == identity)
        .ok_or(Failure::Input("initialization_preservation_target"))?;
    let before = module.token_info(identity.slot)?;
    *session = Some(module.select(&identity)?.open_session(true)?);
    let owner = session
        .as_ref()
        .ok_or(Failure::Input("initialization_control_session"))?;
    let state = owner.info()?;
    let object = create_control(owner, config.label.as_bytes(), wrong_pin)?;
    if wrong_pin {
        // A valid-length one-byte mutation reaches authentication, not the
        // module's length precheck. Zeroizing retains this temporary PIN copy.
        let mut incorrect = zeroize::Zeroizing::new(pins.officer.to_vec());
        assertion(
            !incorrect.is_empty()
                && incorrect.len() as u64 >= target.capabilities().minimum_pin_length
                && incorrect.len() as u64 <= target.capabilities().maximum_pin_length,
            "initialization_wrong_pin_valid_length",
        )?;
        incorrect[0] = if incorrect[0] == b'0' { b'1' } else { b'0' };
        close_control(session)?;
        match reset(module, target, SecretPin::new(incorrect.to_vec()), bytes) {
            Err(
                error @ Error::Native {
                    function: "C_InitToken",
                    code,
                    may_have_effect: true,
                },
            ) if code == fe11_sys::CKR_PIN_INCORRECT as u64 => {
                outcome::record(report, Phase::Body, &Failure::Product(error))
                    .map_err(|_| Failure::Input("initialization_report"))?;
            }
            Err(error) => return Err(error.into()),
            Ok(()) => return Err(Failure::Oracle("initialization_wrong_pin_accepted")),
        }
        *session = Some(module.select(&identity)?.open_session(true)?);
        let owner = session
            .as_ref()
            .ok_or(Failure::Input("initialization_control_session"))?;
        let controls = super::object_transition_fixture::find(owner, config.label.as_bytes())?;
        assertion(
            controls.len() == 1,
            "initialization_pin_preserves_token_object",
        )?;
        read_control(owner, &controls[0])?;
    } else {
        match reset(module, target, SecretPin::new(pins.officer.to_vec()), bytes) {
            Err(
                error @ Error::Native {
                    function: "C_InitToken",
                    code,
                    may_have_effect: false,
                },
            ) if code == fe11_sys::CKR_SESSION_EXISTS as u64 => {
                outcome::record(report, Phase::Body, &Failure::Product(error))
                    .map_err(|_| Failure::Input("initialization_report"))?;
            }
            Err(error) => return Err(error.into()),
            Ok(()) => return Err(Failure::Oracle("initialization_open_session_reset")),
        }
        let after = owner.info()?;
        assertion(
            after.slot == state.slot && after.state == state.state && after.flags == state.flags,
            "initialization_session_preserved",
        )?;
        read_control(owner, &object)?;
    }
    let after = module.token_info(identity.slot)?;
    assertion(
        after.label == before.label && after.serial == before.serial,
        "initialization_refusal_identity_preserved",
    )?;
    close_control(session)?;
    drop(object);
    // The exact same target is reused, without refresh after the refusal.
    reset(module, target, SecretPin::new(pins.officer.to_vec()), bytes)?;
    let counts = module.call_counts()?;
    let result = reset(module, target, SecretPin::new(pins.officer.to_vec()), bytes);
    assertion(
        matches!(
            result,
            Err(Error::Rejected(RejectionReason::ModuleLifecycle(
                ModuleLifecycleRejection::TokenContextStale
            )))
        ) && module.call_counts()? == counts,
        "initialization_success_retires_old_target",
    )?;
    module.refresh_tokens()?;
    let targets = module.administration_targets()?;
    let mut label = [b' '; 32];
    label[..RESET_LABEL.len()].copy_from_slice(RESET_LABEL.as_bytes());
    let current: Vec<_> = targets
        .iter()
        .filter(|target| target.capabilities().label == label)
        .collect();
    assertion(current.len() == 1, "initialization_success_target_unique")?;
    let identity = &current[0].capabilities().identity;
    let info = module.token_info(identity.slot)?;
    assertion(
        info.label == label
            && info.flags & fe11_sys::CKF_TOKEN_INITIALIZED as u64 != 0
            && info.flags & fe11_sys::CKF_USER_PIN_INITIALIZED as u64 == 0,
        "initialization_success_state",
    )?;
    *session = Some(module.select(identity)?.open_session(true)?);
    if wrong_pin {
        let controls = super::object_transition_fixture::find(
            session
                .as_ref()
                .ok_or(Failure::Input("initialization_control_session"))?,
            config.label.as_bytes(),
        )?;
        assertion(
            controls.is_empty(),
            "initialization_success_destroys_token_control",
        )?;
    }
    report
        .observation(
            Phase::Body,
            "initialization_preservation_and_retirement",
            super::report::Producer::TestOracle,
            super::report::Observation::Boolean(true),
        )
        .map_err(|_| Failure::Input("initialization_report"))
}
