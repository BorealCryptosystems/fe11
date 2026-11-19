// SPDX-License-Identifier: Apache-2.0
//! OAEP cannot restore an asymmetric agreement key; the real KEK survives refusal.
use super::{
    configuration::{select_token, Configuration},
    credentials::Credentials,
    generation_transition_spec::history,
    module_controls,
    outcome::Failure,
    report::Report,
    selection_asymmetric, selection_rsa, selection_symmetric,
};
use fe11::*;
use std::io::{self, Write};

pub fn execute<W: Write>(
    module: Module,
    config: &Configuration,
    pins: &Credentials,
    report: Report<W>,
) -> io::Result<bool> {
    let mut session = None;
    let mut retained = None;
    let mut unexpected = None;
    let mut logged = false;
    let setup = (|| -> std::result::Result<RsaKeyEncryptionPair, Failure> {
        let token =
            select_token(&module, &config.label).ok_or(Failure::Input("oaep_destination_token"))?;
        session = Some(module.select(&token)?.open_session(true)?);
        let owner = session
            .as_ref()
            .ok_or(Failure::Input("oaep_destination_owner"))?;
        owner.login_as(LoginRole::User, SecretPin::new(pins.user.to_vec()))?;
        logged = true;
        let result = owner.generate_rsa_key_encryption_pair(
            selection_rsa::transport(),
            MechanismObservationPlan::NotRequested,
            MechanismObservationPlan::NotRequested,
        )?;
        retained = Some(result.objects);
        if result.remainder.is_some() || retained.as_ref().map_or(0, |v| v.as_slice().len()) != 2 {
            return Err(Failure::Oracle("oaep_destination_key_count"));
        }
        Ok(result.observation?)
    })();
    let body = (|| -> std::result::Result<(), Failure> {
        let Ok(pair) = &setup else {
            return Ok(());
        };
        let owner = session
            .as_ref()
            .ok_or(Failure::Input("oaep_destination_owner"))?;
        let before = module.call_counts()?;
        // The envelope has the RSA modulus width. The destination class is the
        // sole invalid parameter; no ciphertext is submitted to the module.
        let result = owner.unwrap_agreement_key(
            &pair.private().unwrapping(),
            UnwrapParameters::RsaOaep {
                hash: fe11_sys::CKM_SHA256 as u64,
                mgf: fe11_sys::CKG_MGF1_SHA256 as u64,
                label: &[],
            },
            &[0; 256],
            AgreementIntroductionSpec {
                native_protection: CurrentKeyProtection {
                    sensitive: false,
                    extractable: true,
                },
                history_observation: history(),
                key: selection_asymmetric::agreement(),
            },
        );
        match result {
            Err(Error::Rejected(RejectionReason::KeyDerivation(
                KeyDerivationRejection::OaepRequiresASecretKeyDestination,
            ))) => (),
            Err(error) => return Err(error.into()),
            Ok(created) => {
                unexpected = Some(created.objects);
                return Err(Failure::Oracle("oaep_agreement_destination_accepted"));
            }
        }
        if module.call_counts()? != before {
            return Err(Failure::Oracle("oaep_destination_dispatched"));
        }
        for (object, class) in [
            (pair.public().managed(), fe11_sys::CKO_PUBLIC_KEY),
            (pair.private().managed(), fe11_sys::CKO_PRIVATE_KEY),
        ] {
            let values = owner.managed_attributes(
                object,
                &[Attribute::Class],
                selection_symmetric::key(false).admission.metadata,
            )?;
            if !matches!(values.as_slice(), [AttributeValue::Available(value)]
                if value.as_slice() == class.to_ne_bytes())
            {
                return Err(Failure::Oracle("oaep_destination_surviving_class"));
            }
        }
        Ok(())
    })();
    let setup = setup.map(|_| ());
    let mut cleanup = Vec::new();
    if let Some(owner) = &session {
        for objects in unexpected.iter().chain(retained.iter()) {
            for object in objects.as_slice() {
                if let Err(error) = owner.destroy_native_object(object) {
                    cleanup.push(error.into());
                }
            }
        }
        if logged {
            if let Err(error) = owner.logout() {
                cleanup.push(error.into());
            }
        }
        if let Err(error) = owner.close() {
            cleanup.push(error.into());
        }
    }
    drop(unexpected);
    drop(retained);
    drop(session);
    if let Err(error) = module.close() {
        cleanup.push(error.into());
    }
    module_controls::finish(report, setup, body, cleanup)
}
