// SPDX-License-Identifier: Apache-2.0
//! Application-selected budgets and ownership for one small public scenario.
//! Cleanup keeps its own verdict, even when the operation or an observation fails.
use crate::{
    environment::Environment,
    report::{require, Cause, Failure, Outcome},
};
use fe11::*;
use std::{num::NonZeroUsize, sync::Arc};

pub struct Fixture {
    module: Option<Module>,
    session: Option<Session>,
    pub environment: Option<Environment>,
    pub objects: Vec<NativeObjectRef>,
    logged_in: bool,
}

impl Fixture {
    pub fn new() -> Self {
        Self {
            module: None,
            session: None,
            environment: None,
            objects: Vec::new(),
            logged_in: false,
        }
    }
    pub fn open(&mut self, environment: Environment) -> Outcome {
        let config = ModuleConfig {
            path: environment.module.clone(),
            integrity: ModuleIntegrity::Sha256 {
                expected: environment.digest,
                on_mismatch: ModuleDigestMismatch::Refuse,
            },
            limits: Limits {
                slots: 64,
                mechanisms: 512,
                discovery_attempts: 4,
                sessions: 4,
            },
        };
        let options = ModuleOptions {
            discovery: DiscoverySelection::AllPresentSlots,
            initialization: InitializationOptions {
                cannot_create_os_threads: false,
                concurrency: NativeConcurrency::Concurrent,
            },
            interface_discovery: InterfaceDiscoveryLimits {
                interfaces: 16,
                attempts: 4,
            },
            interface: InterfaceSelection::ProviderDefault,
            object_limits: ObjectLimits {
                object_references: None,
                managed_references: None,
                destination_reservations: None,
            },
            crypto_options: CryptoOptions {
                limits: CryptoLimits {
                    maximum_parts: 8,
                    maximum_total_bytes: 4096,
                },
                edwards: EdwardsOptions {
                    parameter_encoding: EdwardsParameterEncoding::Oid,
                    point_encoding: EdwardsPointEncoding::Raw,
                    key_size_units: EdwardsKeySizeUnits::FieldBits,
                },
            },
            session_policy: SessionPolicy {
                module_read_write: 4,
                default_token: SessionLimit {
                    total: 4,
                    read_write: 4,
                },
                tokens: Vec::new(),
                announced_limits: AnnouncedSessionLimits::Ignore,
            },
            symmetric_limits: SymmetricLimits {
                maximum_buffer_bytes: 8 * 1024 * 1024,
            },
            chacha_nonce_length_encoding: ChaChaNonceLengthEncoding::Bits,
        };
        self.module = Some(Module::builder(config, options).open()?);
        self.environment = Some(environment);
        let module = self.module.as_ref().ok_or(Failure::new(Cause::Setup))?;
        let expected = self
            .environment
            .as_ref()
            .ok_or(Failure::new(Cause::Setup))?
            .label
            .as_bytes();
        let matches: Vec<_> = module
            .tokens()
            .iter()
            .filter(|token| {
                token
                    .label
                    .iter()
                    .rposition(|b| *b != b' ')
                    .map(|last| &token.label[..=last] == expected)
                    .unwrap_or(false)
            })
            .collect();
        require(matches.len() == 1)?;
        let token = matches[0];
        // Missing capabilities fail prerequisites; they never become skipped tests.
        for (mechanism, flags) in [
            (fe11_sys::CKM_SHA256, fe11_sys::CKF_DIGEST),
            (
                fe11_sys::CKM_RSA_PKCS_KEY_PAIR_GEN,
                fe11_sys::CKF_GENERATE_KEY_PAIR,
            ),
            (
                fe11_sys::CKM_SHA256_RSA_PKCS,
                fe11_sys::CKF_SIGN | fe11_sys::CKF_VERIFY,
            ),
            (fe11_sys::CKM_AES_KEY_GEN, fe11_sys::CKF_GENERATE),
            (
                fe11_sys::CKM_AES_GCM,
                fe11_sys::CKF_ENCRYPT | fe11_sys::CKF_DECRYPT,
            ),
        ] {
            let info = token
                .mechanisms
                .get(&(mechanism as u64))
                .ok_or(Failure::new(Cause::Prerequisite))?;
            if info.flags & flags as u64 != flags as u64 {
                return Err(Failure::new(Cause::Prerequisite));
            }
        }
        self.session = Some(module.select(&token.identity)?.open_session(true)?);
        Ok(())
    }
    pub fn session(&self) -> &Session {
        self.session
            .as_ref()
            .expect("session established before scenario")
    }
    pub fn login(&mut self) -> Outcome {
        let pin = self
            .environment
            .as_ref()
            .ok_or(Failure::new(Cause::Setup))?
            .user_pin
            .clone();
        self.session()
            .login_as(LoginRole::User, SecretPin::new(pin))?;
        self.logged_in = true;
        Ok(())
    }
    pub fn logout(&mut self) -> Outcome {
        self.session().logout()?;
        self.logged_in = false;
        Ok(())
    }
    pub fn retain<T>(&mut self, created: CreatedObjects<T>) -> std::result::Result<T, Failure> {
        self.objects
            .extend(created.objects.as_slice().iter().cloned());
        created.observation.map_err(Failure::from)
    }
    pub fn destroy(&mut self, object: &NativeObjectRef) -> Outcome {
        self.session().destroy_native_object(object)?;
        // This helper is used only by the one-object search scenario.
        require(self.objects.len() == 1)?;
        self.objects.clear();
        Ok(())
    }
    pub fn cleanup(&mut self) -> Outcome {
        let mut first = None;
        if let Some(session) = &self.session {
            for object in self.objects.drain(..).rev() {
                if let Err(error) = session.destroy_native_object(&object) {
                    first.get_or_insert(Failure::from(error));
                }
            }
            if self.logged_in {
                if let Err(error) = session.logout() {
                    first.get_or_insert(Failure::from(error));
                }
            }
            if let Err(error) = session.close() {
                first.get_or_insert(Failure::from(error));
            }
        }
        self.session = None;
        if let Some(module) = &self.module {
            if let Err(error) = module.close() {
                first.get_or_insert(Failure::from(error));
            }
        }
        self.module = None;
        first.map_or(Ok(()), Err)
    }
}

pub fn limits() -> InputLimits {
    InputLimits {
        maximum_parts: 8,
        maximum_total_bytes: 4096,
    }
}
pub fn search_plan() -> SearchPlan {
    SearchPlan {
        maximum_objects: Some(16),
        batch_size: NonZeroUsize::new(16).expect("nonzero batch"),
    }
}
pub fn template_limits() -> AttributeTemplateLimits {
    AttributeTemplateLimits {
        maximum_depth: 0,
        maximum_attributes: 16,
        maximum_value_bytes: 1024,
    }
}
pub fn destination() -> DestinationPlan {
    DestinationPlan {
        search: DestinationSearchPlan::NotRequested,
        user: DestinationUserObservation::NotRequested,
    }
}
pub fn generation<'a>(attributes: &'a [AttributeInput<'a>]) -> GenerationTemplate<'a> {
    GenerationTemplate {
        attributes,
        limits: template_limits(),
        observation: None,
        destination: destination(),
    }
}

pub fn aes_spec() -> SymmetricKeySpec {
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
