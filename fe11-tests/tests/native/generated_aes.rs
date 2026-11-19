// SPDX-License-Identifier: Apache-2.0
//! Exercise a generated session key across successive operations on the same session.
use super::{
    configuration::{select_token, Configuration},
    credentials::Credentials,
    module_controls,
    outcome::{self, Failure},
    report::{Phase, Report},
};
use fe11::*;
use std::{
    fs::File,
    io::{self, Read, Write},
    num::NonZeroUsize,
    path::Path,
    sync::Arc,
};

type Check<T> = std::result::Result<T, Failure>;

enum Operation {
    AuthenticatedRoundTrip,
    SearchById,
}

impl Operation {
    fn read(path: &Path) -> Check<Self> {
        let mut input = Vec::new();
        File::open(path)
            .and_then(|file| file.take(33).read_to_end(&mut input))
            .map_err(|_| Failure::Input("generated_aes_vector"))?;
        match input.as_slice() {
            b"authenticated-round-trip\n" => Ok(Self::AuthenticatedRoundTrip),
            b"search-by-id\n" => Ok(Self::SearchById),
            _ => Err(Failure::Input("generated_aes_action")),
        }
    }
}

// Establish ownership before inspecting admission metadata, so an observation
// failure still leaves the generated objects available for cleanup.
fn retain<T>(created: CreatedObjects<T>, owned: &mut Option<CreatedObjectSet>) -> Check<T> {
    let count = created.objects.as_slice().len();
    *owned = Some(created.objects);
    if count != 1 {
        return Err(Failure::Oracle("generated_aes_single_owner"));
    }
    if created.remainder.is_some() {
        return Err(Failure::Oracle("generated_aes_incomplete_creation"));
    }
    Ok(created.observation?)
}

fn round_trip<W: Write>(
    session: &Session,
    owned: &mut Option<CreatedObjectSet>,
    report: &mut Report<W>,
) -> Check<()> {
    let key = retain(session.generate_aes_key(aes_spec())?, owned)?;
    let key = key.managed().native_object();
    let random = session.generate_random(12)?;
    let nonce: &[u8; 12] = random
        .as_slice()
        .try_into()
        .map_err(|_| Failure::Oracle("gcm_nonce_length"))?;
    let parameters = || ClassicAeadParameters::Gcm {
        iv: nonce,
        aad: b"public associated data",
        tag_bits: 128,
    };
    let plaintext = b"public authenticated plaintext";
    let envelope = session.encrypt_classic_aead(
        &key,
        parameters(),
        MessageRoute::Single,
        &[plaintext],
        limits(),
    )?;
    if envelope.as_bytes().len() != plaintext.len() + 16 {
        return Err(Failure::Oracle("gcm_envelope_length"));
    }
    let decrypt = |bytes: &[u8]| {
        session.decrypt_classic_aead(&key, parameters(), MessageRoute::Single, &[bytes], limits())
    };
    if decrypt(envelope.as_bytes())?.as_bytes() != plaintext {
        return Err(Failure::Oracle("gcm_plaintext"));
    }
    let mut damaged = envelope.as_bytes().to_vec();
    *damaged
        .last_mut()
        .ok_or(Failure::Oracle("gcm_missing_tag"))? ^= 1;
    match decrypt(&damaged) {
        Err(
            error @ Error::Native {
                function: "C_Decrypt",
                code,
                ..
            },
        ) if code == fe11_sys::CKR_ENCRYPTED_DATA_INVALID as u64 => {
            outcome::record(report, Phase::Body, &Failure::Product(error))
                .map_err(|_| Failure::Input("report_write"))?;
        }
        Err(error) => return Err(error.into()),
        Ok(_) => return Err(Failure::Oracle("gcm_damaged_tag_accepted")),
    }
    if decrypt(envelope.as_bytes())?.as_bytes() != plaintext {
        return Err(Failure::Oracle("gcm_plaintext_after_refusal"));
    }
    Ok(())
}

fn search(session: &Session, id: &[u8], owned: &mut Option<CreatedObjectSet>) -> Check<()> {
    use AttributeInputValue::{Boolean, Bytes, Unsigned};
    let attr = |name: StandardAttribute, value| AttributeInput {
        attribute: name.into(),
        value,
    };
    let attributes = [
        attr(StandardAttribute::TOKEN, Boolean(false)),
        attr(StandardAttribute::PRIVATE, Boolean(true)),
        attr(StandardAttribute::VALUE_LEN, Unsigned(16)),
        attr(StandardAttribute::ID, Bytes(id)),
    ];
    let key = retain(
        session.generate_native_key(KeyGenerator::AES_KEY_GEN, generation(&attributes))?,
        owned,
    )?;
    let query = [attr(StandardAttribute::ID, Bytes(id))];
    let lookup = || session.find_native_objects(&query, template_limits(), search_plan());
    if lookup()?.as_slice().len() != 1 {
        return Err(Failure::Oracle("session_key_unique_by_id"));
    }
    session.destroy_native_object(key.native())?;
    *owned = None;
    if !lookup()?.as_slice().is_empty() {
        return Err(Failure::Oracle("destroyed_session_key_found"));
    }
    Ok(())
}

pub fn execute<W: Write>(
    module: Module,
    config: &Configuration,
    path: &Path,
    pins: &Credentials,
    mut report: Report<W>,
) -> io::Result<bool> {
    let mut session = None;
    let mut logged_in = false;
    let mut owned = None;
    let setup = (|| -> Check<Operation> {
        let action = Operation::read(path)?;
        let token =
            select_token(&module, &config.label).ok_or(Failure::Input("token_not_unique"))?;
        let opened = session.insert(module.select(&token)?.open_session(true)?);
        opened.login_as(LoginRole::User, SecretPin::new(pins.user.to_vec()))?;
        logged_in = true;
        Ok(action)
    })();
    let body = match (&setup, &session) {
        (Ok(Operation::AuthenticatedRoundTrip), Some(opened)) => {
            round_trip(opened, &mut owned, &mut report)
        }
        (Ok(Operation::SearchById), Some(opened)) => {
            search(opened, config.label.as_bytes(), &mut owned)
        }
        (Ok(_), None) => Err(Failure::Input("generated_aes_session")),
        (Err(_), _) => Ok(()),
    };
    let mut cleanup = Vec::new();
    if let Some(opened) = session {
        if let Some(set) = owned {
            for object in set.as_slice() {
                if let Err(error) = opened.destroy_native_object(object) {
                    cleanup.push(error.into());
                }
            }
        }
        if logged_in {
            if let Err(error) = opened.logout() {
                cleanup.push(error.into());
            }
        }
        if let Err(error) = opened.close() {
            cleanup.push(error.into());
        }
    }
    if let Err(error) = module.close() {
        cleanup.push(error.into());
    }
    module_controls::finish(report, setup.map(|_| ()), body, cleanup)
}

fn limits() -> InputLimits {
    InputLimits {
        maximum_parts: 8,
        maximum_total_bytes: 4096,
    }
}
fn search_plan() -> SearchPlan {
    SearchPlan {
        maximum_objects: Some(16),
        batch_size: NonZeroUsize::new(16).expect("nonzero batch"),
    }
}
fn template_limits() -> AttributeTemplateLimits {
    AttributeTemplateLimits {
        maximum_depth: 0,
        maximum_attributes: 16,
        maximum_value_bytes: 1024,
    }
}
fn destination() -> DestinationPlan {
    DestinationPlan {
        search: DestinationSearchPlan::NotRequested,
        user: DestinationUserObservation::NotRequested,
    }
}
fn generation<'a>(attributes: &'a [AttributeInput<'a>]) -> GenerationTemplate<'a> {
    GenerationTemplate {
        attributes,
        limits: template_limits(),
        observation: None,
        destination: destination(),
    }
}

fn aes_spec() -> SymmetricKeySpec {
    let observation = ObjectObservationPlan {
        private: true,
        token: true,
        modifiable: false,
        copyable: false,
        destroyable: false,
        encrypt: false,
        decrypt: false,
        sign: false,
        verify: false,
        sign_recover: false,
        verify_recover: false,
        wrap: false,
        unwrap: false,
        derive: false,
        sensitive: false,
        extractable: false,
        local: false,
        always_sensitive: false,
        never_extractable: false,
        always_authenticate: false,
        trusted: false,
        encapsulate: false,
        decapsulate: false,
        wrap_with_trusted: false,
        maximum_bytes: 4096,
    };
    SymmetricKeySpec {
        usages: KeyUsageRequest {
            encrypt: Some(true),
            decrypt: Some(true),
            ..KeyUsageRequest::omitted()
        },
        visibility: ObjectVisibility::Private,
        admission: ObjectAdmission {
            public_attributes: Arc::new(Vec::new()),
            search: search_plan(),
            selection: ObjectSearchSelection { index: 0 },
            destination: destination(),
            metadata: AttributeReadPlan {
                maximum_bytes: 4096,
                clarification: AttributeClarification::BatchOnly,
            },
            observation,
        },
        protection_request: CurrentKeyProtection {
            sensitive: true,
            extractable: false,
        },
        history: HistoryObservationPlan {
            sensitive: true,
            extractable: true,
            always_sensitive: false,
            never_extractable: false,
            local: false,
            generation: false,
            maximum_bytes: 64,
        },
        mechanisms: MechanismObservationPlan::NotRequested,
        algorithm: SymmetricAlgorithm::Aes128,
        hmac_key_type: None,
        id: b"public-ci-aes".to_vec(),
        label: "public-ci-aes".into(),
        persistent: false,
    }
}
