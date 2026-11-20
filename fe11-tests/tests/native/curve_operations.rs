// SPDX-License-Identifier: Apache-2.0
//! Generated curve keys, imported identities and two-sided native agreement.
//! Agreement equality is not an independent known-answer result. Published
//! agreement fixtures supply that separate evidence where a reference exists.
use super::super::{
    arguments::hex,
    configuration::{select_token, Configuration},
    derived_value,
    outcome::{self, Failure},
    report::{Observation, Phase, PhaseResult, Producer, Report},
};
use fe11::*;
use std::{
    fs::File,
    io::{self, Read, Write},
    path::Path,
};

pub(super) fn selected(path: &Path) -> bool {
    let mut prefix = [0; b"curve-ops-v1\n".len()];
    File::open(path)
        .and_then(|mut f| f.read_exact(&mut prefix))
        .is_ok()
        && &prefix == b"curve-ops-v1\n"
}

// Public point-shape observations for curves with intermittent native refusals.
const OBSERVED_CURVES: &[&[u8]] = &[
    &[6, 5, 43, 129, 4, 0, 3],             // sect239k1
    &[6, 5, 43, 129, 4, 0, 9],             // secp160k1
    &[6, 8, 42, 134, 72, 206, 61, 3, 1, 2], // prime192v2
    &[6, 8, 42, 134, 72, 206, 61, 3, 0, 12], // c2tnb239v2
];

struct Case {
    oid: Vec<u8>,
    width: usize,
    unknown: bool,
}
impl Case {
    fn read(path: &Path) -> std::result::Result<Self, Failure> {
        let mut bytes = Vec::new();
        File::open(path)
            .map_err(|_| Failure::Input("curve_fixture_open"))?
            .take(257)
            .read_to_end(&mut bytes)
            .map_err(|_| Failure::Input("curve_fixture_read"))?;
        if bytes.len() > 256 {
            return Err(Failure::Input("curve_fixture_bound"));
        }
        let text =
            std::str::from_utf8(&bytes).map_err(|_| Failure::Input("curve_fixture_encoding"))?;
        let f: Vec<_> = text.split_terminator('\n').collect();
        if f.len() != 4 || f[0] != "curve-ops-v1" || !matches!(f[3], "named" | "unknown") {
            return Err(Failure::Input("curve_fixture_fields"));
        }
        let oid = hex(f[1], 32).map_err(Failure::Input)?;
        let width = f[2]
            .parse()
            .map_err(|_| Failure::Input("curve_field_width"))?;
        if oid.len() < 3
            || oid[0] != 6
            || oid[1] as usize + 2 != oid.len()
            || !(14..=72).contains(&width)
        {
            return Err(Failure::Input("curve_fixture_dimensions"));
        }
        let unknown = f[3] == "unknown";
        if unknown && oid != [6, 9, 43, 6, 1, 4, 1, 134, 141, 31, 1] {
            return Err(Failure::Input("curve_unknown_oid"));
        }
        Ok(Self {
            oid,
            width,
            unknown,
        })
    }
}

fn attr(attribute: StandardAttribute, value: AttributeInputValue<'_>) -> AttributeInput<'_> {
    AttributeInput {
        attribute: attribute.into(),
        value,
    }
}
fn template<'a>(attributes: &'a [AttributeInput<'a>]) -> GenerationTemplate<'a> {
    GenerationTemplate {
        attributes,
        limits: AttributeTemplateLimits {
            maximum_depth: 0,
            maximum_attributes: attributes.len(),
            maximum_value_bytes: 512,
        },
        observation: None,
        destination: DestinationPlan {
            search: DestinationSearchPlan::NotRequested,
            user: DestinationUserObservation::NotRequested,
        },
    }
}
fn public_template(oid: &[u8]) -> Vec<AttributeInput<'_>> {
    vec![
        attr(
            StandardAttribute::CLASS,
            AttributeInputValue::Unsigned(fe11_sys::CKO_PUBLIC_KEY as u64),
        ),
        attr(
            StandardAttribute::KEY_TYPE,
            AttributeInputValue::Unsigned(fe11_sys::CKK_EC as u64),
        ),
        attr(
            StandardAttribute::TOKEN,
            AttributeInputValue::Boolean(false),
        ),
        attr(
            StandardAttribute::PRIVATE,
            AttributeInputValue::Boolean(false),
        ),
        attr(
            StandardAttribute::VERIFY,
            AttributeInputValue::Boolean(true),
        ),
        attr(
            StandardAttribute::EC_PARAMS,
            AttributeInputValue::Bytes(oid),
        ),
    ]
}
fn private_template(oid: &[u8]) -> Vec<AttributeInput<'_>> {
    vec![
        attr(
            StandardAttribute::CLASS,
            AttributeInputValue::Unsigned(fe11_sys::CKO_PRIVATE_KEY as u64),
        ),
        attr(
            StandardAttribute::KEY_TYPE,
            AttributeInputValue::Unsigned(fe11_sys::CKK_EC as u64),
        ),
        attr(
            StandardAttribute::TOKEN,
            AttributeInputValue::Boolean(false),
        ),
        attr(
            StandardAttribute::PRIVATE,
            AttributeInputValue::Boolean(false),
        ),
        attr(StandardAttribute::SIGN, AttributeInputValue::Boolean(true)),
        attr(
            StandardAttribute::DERIVE,
            AttributeInputValue::Boolean(true),
        ),
        attr(
            StandardAttribute::SENSITIVE,
            AttributeInputValue::Boolean(false),
        ),
        attr(
            StandardAttribute::EXTRACTABLE,
            AttributeInputValue::Boolean(true),
        ),
        attr(
            StandardAttribute::EC_PARAMS,
            AttributeInputValue::Bytes(oid),
        ),
    ]
}
fn read(
    session: &Session,
    key: &NativeObjectRef,
    attribute: StandardAttribute,
    capacity: usize,
) -> std::result::Result<Vec<u8>, Failure> {
    let read =
        session.read_flat_attribute(key, attribute, FlatAttributeReadPlan::Buffer { capacity })?;
    if read.calls != (AttributeReadCalls::Direct { code: 0 }) {
        return Err(Failure::Oracle("curve_attribute_native_status"));
    }
    match read.value {
        FlatAttributeValue::Available(value) => Ok(value.as_bytes().to_vec()),
        _ => Err(Failure::Oracle("curve_attribute_unavailable")),
    }
}
fn raw_point(encoded: &[u8], width: usize) -> std::result::Result<&[u8], Failure> {
    // CKA_EC_POINT is DER OCTET STRING. The length forms below are sufficient
    // for the closed14..72-byte field widths; no permissive ASN.1 fallback.
    let raw = if encoded.len() >= 2
        && encoded[0] == 4
        && encoded[1] < 128
        && encoded[1] as usize + 2 == encoded.len()
    {
        &encoded[2..]
    } else if encoded.len() >= 3
        && encoded[0..2] == [4, 129]
        && encoded[2] >= 128
        && encoded[2] as usize + 3 == encoded.len()
    {
        &encoded[3..]
    } else {
        return Err(Failure::Oracle("curve_public_der_point"));
    };
    if raw.len() != 1 + 2 * width || raw[0] != 4 {
        return Err(Failure::Oracle("curve_public_point_width"));
    }
    Ok(raw)
}

#[derive(Default)]
struct Owners {
    sets: Vec<CreatedObjectSet>,
    imports: Vec<NativeObjectRef>,
}
fn body<W: Write>(
    session: &Session,
    case: &Case,
    owners: &mut Owners,
    report: &mut Report<W>,
) -> std::result::Result<(), Failure> {
    let public = public_template(&case.oid);
    let mut private = private_template(&case.oid);
    // Generation takes EC_PARAMS from the public template; private import
    // requires its own explicit curve parameters later in this scenario.
    private.retain(|a| a.attribute != StandardAttribute::EC_PARAMS);
    for _ in 0..if case.unknown { 1 } else { 2 } {
        let result = session.generate_native_key_pair(
            KeyPairGenerator::EC_KEY_PAIR_GEN,
            template(&public),
            template(&private),
        );
        let created = match result {
            Err(
                error @ Error::Native {
                    function: "C_GenerateKeyPair",
                    code,
                    may_have_effect: true,
                },
            ) if case.unknown && code == fe11_sys::CKR_GENERAL_ERROR as u64 => {
                outcome::record(report, Phase::Body, &Failure::Product(error))
                    .map_err(|_| Failure::Input("report_write"))?;
                return Ok(());
            }
            other => other?,
        };
        owners.sets.push(created.objects);
        created.observation?;
        if created.remainder.is_some() || owners.sets.last().map(|s| s.as_slice().len()) != Some(2)
        {
            return Err(Failure::Oracle("curve_pair_outputs"));
        }
        if case.unknown {
            return Err(Failure::Oracle("unknown_curve_created"));
        }
    }
    let mut points = Vec::new();
    for set in &owners.sets {
        for key in set.as_slice() {
            if read(session, key, StandardAttribute::EC_PARAMS, 32)? != case.oid {
                return Err(Failure::Oracle("curve_parameters_changed"));
            }
        }
        let point = read(
            session,
            &set.as_slice()[0],
            StandardAttribute::EC_POINT,
            148,
        )?;
        raw_point(&point, case.width)?;
        points.push(point);
    }
    let scalar = read(
        session,
        &owners.sets[0].as_slice()[1],
        StandardAttribute::VALUE,
        case.width + 1,
    )?;
    if scalar.is_empty() || scalar.len() > case.width + 1 {
        return Err(Failure::Oracle("curve_private_scalar_width"));
    }
    let mut imported_public = public_template(&case.oid);
    imported_public.push(attr(
        StandardAttribute::EC_POINT,
        AttributeInputValue::Bytes(&points[0]),
    ));
    owners.imports.push(session.create_native_object(
        &imported_public,
        AttributeTemplateLimits {
            maximum_depth: 0,
            maximum_attributes: imported_public.len(),
            maximum_value_bytes: 512,
        },
    )?);
    let mut imported_private = private_template(&case.oid);
    imported_private.push(attr(
        StandardAttribute::VALUE,
        AttributeInputValue::Bytes(&scalar),
    ));
    owners.imports.push(session.create_native_object(
        &imported_private,
        AttributeTemplateLimits {
            maximum_depth: 0,
            maximum_attributes: imported_private.len(),
            maximum_value_bytes: 512,
        },
    )?);
    if read(
        session,
        &owners.imports[0],
        StandardAttribute::EC_POINT,
        148,
    )? != points[0]
    {
        return Err(Failure::Oracle("curve_imported_public_changed"));
    }
    let digest = [0x5a; 32];
    let parameters = || NativeSignatureParameters::Parameterless(NativeSignatureAlgorithm::ECDSA);
    let limits = InputLimits {
        maximum_parts: 1,
        maximum_total_bytes: digest.len(),
    };
    // Both generated and reimported private owners sign; the matching public
    // owners verify. These native round trips are not independent math proofs.
    for (private, public) in [
        (&owners.sets[0].as_slice()[1], &owners.imports[0]),
        (&owners.imports[1], &owners.sets[0].as_slice()[0]),
    ] {
        // The subgroup order and field widths can differ (for example some
        // 160-bit fields have a161-bit order). Do not equate their dimensions.
        let signature_capacity = 2 * (case.width + 1);
        let signature = session.sign_native(
            private,
            parameters(),
            MessageRoute::Single,
            &[&digest],
            limits,
            signature_capacity,
            None,
        )?;
        if signature.as_bytes().is_empty()
            || signature.as_bytes().len() % 2 != 0
            || signature.as_bytes().len() > signature_capacity
        {
            return Err(Failure::Oracle("curve_signature_width"));
        }
        session.verify_native(
            public,
            parameters(),
            MessageRoute::Single,
            &[&digest],
            signature.as_bytes(),
            limits,
            None,
        )?;
    }
    let mut secrets = Vec::new();
    for index in 0..2 {
        let attributes = derived_value::template_attributes(case.width);
        let peer = raw_point(&points[1 - index], case.width)?;
        // The first coordinate of a valid uncompressed point
        // can also look like the short-form length of a DER OCTET STRING.
        // Record the shape of the actual input before dispatch, including
        // when derivation fails. Neither coordinates nor secret bytes are logged.
        if OBSERVED_CURVES.contains(&case.oid.as_slice()) {
            report
                .observation(
                    Phase::Body,
                    "ecdh_sec1_point_bytes",
                    Producer::TestOracle,
                    Observation::Number(peer.len() as u64),
                )
                .map_err(|_| Failure::Input("report_write"))?;
            report
                .observation(
                    Phase::Body,
                    "ecdh_sec1_matches_der_header",
                    Producer::TestOracle,
                    Observation::Boolean(usize::from(peer[1]) + 2 == peer.len()),
                )
                .map_err(|_| Failure::Input("report_write"))?;
        }
        let created = session.derive_native_key(
            &owners.sets[index].as_slice()[1],
            NativeKeyDerivation::Ecdh {
                kdf: fe11_sys::CKD_NULL as u64,
                cofactor: false,
                peer_public: peer,
                shared_data: None,
            },
            template(&attributes),
        )?;
        owners.sets.push(created.objects);
        created.observation?;
        let set = owners
            .sets
            .last()
            .ok_or(Failure::Input("curve_derived_owner"))?;
        if created.remainder.is_some() || set.as_slice().len() != 1 {
            return Err(Failure::Oracle("curve_derived_outputs"));
        }
        let value = read(
            session,
            &set.as_slice()[0],
            StandardAttribute::VALUE,
            case.width,
        )?;
        if value.len() != case.width {
            return Err(Failure::Oracle("curve_shared_secret_width"));
        }
        secrets.push(value);
    }
    if secrets[0] != secrets[1] {
        return Err(Failure::Oracle("curve_shared_secret_mismatch"));
    }
    Ok(())
}

pub(super) fn execute<W: Write>(
    module: Module,
    config: &Configuration,
    path: &Path,
    mut report: Report<W>,
) -> io::Result<bool> {
    let mut session = None;
    let mut owners = Owners::default();
    let setup = (|| -> std::result::Result<Case, Failure> {
        let case = Case::read(path)?;
        let token = select_token(&module, &config.label).ok_or(Failure::Input("curve_token"))?;
        session = Some(module.select(&token)?.open_session(true)?);
        Ok(case)
    })();
    let started = setup.is_ok();
    let (setup, result) = match setup {
        Err(error) => (Err(error), Ok(())),
        Ok(case) => (
            Ok(()),
            body(
                session.as_ref().expect("assigned during setup"),
                &case,
                &mut owners,
                &mut report,
            ),
        ),
    };
    let created_pairs = owners
        .sets
        .iter()
        .filter(|set| set.as_slice().len() == 2)
        .count() as u64;
    let owned_objects = owners.imports.len()
        + owners
            .sets
            .iter()
            .map(|set| set.as_slice().len())
            .sum::<usize>();
    let mut cleanup = Vec::new();
    if let Some(session) = &session {
        for key in owners
            .imports
            .iter()
            .chain(owners.sets.iter().flat_map(|set| set.as_slice()))
        {
            if let Err(error) = session.destroy_native_object(key) {
                cleanup.push(error.into());
            }
        }
        if let Err(error) = session.close() {
            cleanup.push(error.into());
        }
    }
    drop(owners);
    drop(session);
    if let Err(error) = module.close() {
        cleanup.push(error.into());
    }
    if let Err(error) = &setup {
        outcome::record(&mut report, Phase::Setup, error)?;
    }
    if let Err(error) = &result {
        outcome::record(&mut report, Phase::Body, error)?;
    }
    for error in &cleanup {
        outcome::record(&mut report, Phase::Cleanup, error)?;
    }
    if started {
        report.observation(
            Phase::Body,
            "curve_created_pairs",
            Producer::Native,
            Observation::Number(created_pairs),
        )?;
        report.observation(
            Phase::Body,
            "curve_owned_objects",
            Producer::Native,
            Observation::Number(owned_objects as u64),
        )?;
        report.observation(
            Phase::Body,
            "curve_generation_import_signature_agreement",
            Producer::TestOracle,
            Observation::Boolean(result.is_ok()),
        )?;
    }
    report.finish(
        if setup.is_ok() {
            PhaseResult::Passed
        } else {
            PhaseResult::Failed
        },
        if !started {
            PhaseResult::NotExecuted
        } else if result.is_ok() {
            PhaseResult::Passed
        } else {
            PhaseResult::Failed
        },
        if cleanup.is_empty() {
            PhaseResult::Passed
        } else {
            PhaseResult::Failed
        },
    )
}
