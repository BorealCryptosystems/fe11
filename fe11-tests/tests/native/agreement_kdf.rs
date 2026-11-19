// SPDX-License-Identifier: Apache-2.0
//! Typed ECDH KDF requests use a real admitted base and an exact public peer.
use super::super::{
    generation_transition_spec::history,
    outcome::{self, Failure},
    report::{Phase, Report},
    selection_symmetric,
};
use fe11::*;
use std::io::Write;

pub(super) fn target() -> SymmetricKeySpec {
    let mut target = selection_symmetric::key(false);
    target.algorithm = SymmetricAlgorithm::HmacSha256 { key_length: 32 };
    target.hmac_key_type = Some(HmacKeyType::Generic);
    target.usages = KeyUsageRequest {
        sign: Some(true),
        verify: Some(true),
        ..KeyUsageRequest::omitted()
    };
    target.admission.observation.encrypt = false;
    target.admission.observation.decrypt = false;
    target.admission.observation.sign = true;
    target.admission.observation.verify = true;
    target
}

pub(super) fn refused<W: Write>(
    session: &Session,
    key: &AgreementKey,
    spki: &[u8],
    action: &str,
    retained: &mut Vec<CreatedObjectSet>,
    report: &mut Report<W>,
) -> std::result::Result<(), Failure> {
    let kdf = match action {
        "kdf-x963" => EcdhKdf::X963Sha256,
        "kdf-concat" => EcdhKdf::ConcatSha256,
        "kdf-native" => EcdhKdf::Native(fe11_sys::CKD_SHA256_KDF as u64),
        _ => return Err(Failure::Input("typed_ecdh_kdf_action")),
    };
    let peer = AgreementPeer::from_spki(AgreementCurve::P256, spki)?;
    match session.derive_ecdh(
        key,
        &peer,
        kdf,
        &[],
        target(),
        DerivationObservationPlan {
            parent: history(),
            child: history(),
        },
    ) {
        Err(
            error @ Error::Native {
                function: "C_DeriveKey",
                code,
                ..
            },
        ) if code == fe11_sys::CKR_MECHANISM_PARAM_INVALID as u64 => {
            outcome::record(report, Phase::Body, &Failure::Product(error))
                .map_err(|_| Failure::Input("report_write"))
        }
        Err(error) => Err(error.into()),
        Ok(created) => {
            // Even unexpected successful creation must preserve cleanup rights.
            retained.push(created.objects);
            Err(Failure::Oracle("typed_ecdh_hash_kdf_accepted"))
        }
    }
}
