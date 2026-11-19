// SPDX-License-Identifier: Apache-2.0
//! RSA object references keep their original session and public/private class.
use super::{
    configuration::{select_token, Configuration},
    credentials::Credentials,
    module_controls,
    outcome::Failure,
    report::Report,
    selection_symmetric,
};
use fe11::*;
use std::{
    fs::File,
    io::{self, Read, Write},
    path::Path,
};

pub fn execute<W: Write>(
    module: Module,
    config: &Configuration,
    path: &Path,
    pins: &Credentials,
    report: Report<W>,
) -> io::Result<bool> {
    let mut source = None;
    let mut peer = None;
    let mut objects = None;
    let mut logged = false;
    let setup = (|| -> std::result::Result<(bool, KeyPair), Failure> {
        let mut text = String::new();
        File::open(path)
            .map_err(|_| Failure::Input("oaep_reference_fixture"))?
            .take(16)
            .read_to_string(&mut text)
            .map_err(|_| Failure::Input("oaep_reference_read"))?;
        let foreign = match text.as_str() {
            "foreign\n" => true,
            "private\n" => false,
            _ => return Err(Failure::Input("oaep_reference_action")),
        };
        let token =
            select_token(&module, &config.label).ok_or(Failure::Input("oaep_reference_token"))?;
        let context = module.select(&token)?;
        source = Some(context.open_session(true)?);
        let session = source
            .as_ref()
            .ok_or(Failure::Input("oaep_reference_source"))?;
        session.login_as(LoginRole::User, SecretPin::new(pins.user.to_vec()))?;
        logged = true;
        let key = selection_symmetric::key(false);
        let created = session.generate_rsa_oaep_key_pair(OaepKeySpec {
            public_visibility: ObjectVisibility::Public,
            private_visibility: ObjectVisibility::Private,
            private_protection: key.protection_request,
            public_usages: KeyUsageRequest {
                encrypt: Some(true),
                ..KeyUsageRequest::omitted()
            },
            private_usages: KeyUsageRequest {
                decrypt: Some(true),
                ..KeyUsageRequest::omitted()
            },
            public_admission: key.admission,
            private_admission: selection_symmetric::key(false).admission,
            bits: 2048,
            exponent: 65537,
            id: vec![1, 2, 3, 4],
            label: config.label.clone(),
            persistent: false,
        })?;
        objects = Some(created.objects);
        if created.remainder.is_some() || objects.as_ref().map_or(0, |o| o.as_slice().len()) != 2 {
            return Err(Failure::Oracle("oaep_reference_generation_count"));
        }
        let pair = created.observation?;
        if foreign {
            peer = Some(context.open_session(true)?);
        }
        Ok((foreign, pair))
    })();
    let body = (|| -> std::result::Result<(), Failure> {
        let Ok((foreign, pair)) = &setup else {
            return Ok(());
        };
        let session = if *foreign {
            peer.as_ref()
        } else {
            source.as_ref()
        }
        .ok_or(Failure::Input("oaep_reference_receiver"))?;
        let key = if *foreign {
            &pair.public
        } else {
            &pair.private
        };
        let mut plaintext = SecretPlaintext::new(3)?;
        plaintext.as_mut_slice().copy_from_slice(b"abc");
        let before = module.call_counts()?;
        let expected = if *foreign {
            ObjectObservationRejection::ForeignOrStaleObject
        } else {
            ObjectObservationRejection::ObjectContextOrClass
        };
        match session.encrypt_oaep(
            key,
            plaintext,
            OaepParams {
                hash: fe11_sys::CKM_SHA256 as u64,
                mgf: fe11_sys::CKG_MGF1_SHA256 as u64,
                label: &[],
            },
        ) {
            Err(Error::Rejected(RejectionReason::ObjectObservation(reason)))
                if reason == expected =>
            {
                ()
            }
            Err(error) => return Err(error.into()),
            Ok(_) => return Err(Failure::Oracle("oaep_reference_guard_accepted")),
        }
        if module.call_counts()? != before {
            return Err(Failure::Oracle("oaep_reference_guard_dispatched"));
        }
        // Native observation by the real source owner verifies the foreign-call
        // refusal did not destroy or revoke either generated object.
        let owner = source
            .as_ref()
            .ok_or(Failure::Input("oaep_reference_source"))?;
        for (object, class) in [
            (&pair.public, fe11_sys::CKO_PUBLIC_KEY),
            (&pair.private, fe11_sys::CKO_PRIVATE_KEY),
        ] {
            let values = owner.attributes(
                object,
                &[Attribute::Class],
                selection_symmetric::key(false).admission.metadata,
            )?;
            if !matches!(values.as_slice(), [AttributeValue::Available(value)] if value.as_slice() == class.to_ne_bytes())
            {
                return Err(Failure::Oracle("oaep_reference_surviving_class"));
            }
        }
        Ok(())
    })();
    let setup = setup.map(|_| ());
    let mut cleanup = Vec::new();
    if let (Some(session), Some(objects)) = (&source, &objects) {
        for key in objects.as_slice() {
            if let Err(error) = session.destroy_native_object(key) {
                cleanup.push(error.into());
            }
        }
    }
    drop(objects);
    if let Some(session) = &peer {
        if let Err(error) = session.close() {
            cleanup.push(error.into());
        }
    }
    drop(peer);
    if let Some(session) = &source {
        if logged {
            if let Err(error) = session.logout() {
                cleanup.push(error.into());
            }
        }
        if let Err(error) = session.close() {
            cleanup.push(error.into());
        }
    }
    drop(source);
    if let Err(error) = module.close() {
        cleanup.push(error.into());
    }
    module_controls::finish(report, setup, body, cleanup)
}
