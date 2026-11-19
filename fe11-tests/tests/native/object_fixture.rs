// SPDX-License-Identifier: Apache-2.0
//! Public session objects owned by one case, including failed descriptive reads.
use super::{
    configuration::{select_token, Configuration},
    outcome::Failure,
};
use fe11::*;
use std::{num::NonZeroUsize, sync::Arc};

pub struct Fixture {
    pub session: Session,
    objects: Vec<CreatedObjectSet>,
}

impl Fixture {
    pub fn open(module: &Module, config: &Configuration) -> std::result::Result<Self, Failure> {
        let token =
            select_token(module, &config.label).ok_or(Failure::Input("token_not_unique"))?;
        Ok(Self {
            session: module.select(&token)?.open_session(true)?,
            objects: Vec::new(),
        })
    }

    /// Keep native ownership even when the descriptive view could not be returned.
    pub fn retain_public_key(
        &mut self,
        created: CreatedObjects<VerificationKey>,
    ) -> std::result::Result<VerificationKey, Failure> {
        self.objects.push(created.objects);
        if created.remainder.is_some() {
            return Err(Failure::Oracle("unexpected_public_import_auxiliary_output"));
        }
        created.observation.map_err(Failure::from)
    }

    pub fn close(&mut self) -> Vec<Failure> {
        let mut failures = Vec::new();
        // Only the exact references returned to this case authorize destruction.
        // No search, label or identifier is used to select objects for cleanup.
        for set in &self.objects {
            for object in set.as_slice() {
                if let Err(error) = self.session.destroy_native_object(object) {
                    failures.push(error.into());
                }
            }
        }
        self.objects.clear();
        if let Err(error) = self.session.close() {
            failures.push(error.into());
        }
        failures
    }
}

pub fn public_key_options(label: &[u8]) -> PublicKeyImportOptions {
    PublicKeyImportOptions {
        metadata: PublicImportMetadata::Exact {
            id: label.to_vec(),
            label: label.to_vec(),
        },
        usages: KeyUsageRequest {
            verify: Some(true),
            ..KeyUsageRequest::omitted()
        },
        persistent: false,
        destroyable: true,
        visibility: ObjectVisibility::Public,
        modifiable: false,
        copyable: false,
        admission: ObjectAdmission {
            public_attributes: Arc::new(Vec::new()),
            search: SearchPlan {
                maximum_objects: Some(8),
                batch_size: NonZeroUsize::new(4).unwrap(),
            },
            selection: ObjectSearchSelection { index: 0 },
            destination: DestinationPlan {
                search: DestinationSearchPlan::NotRequested,
                user: DestinationUserObservation::NotRequested,
            },
            // Bounds the small named-curve SPKI and explicitly selected metadata.
            metadata: AttributeReadPlan {
                maximum_bytes: 4096,
                clarification: AttributeClarification::BatchOnly,
            },
            observation: ObjectObservationPlan {
                private: true,
                token: true,
                verify: true,
                modifiable: false,
                copyable: false,
                destroyable: false,
                encrypt: false,
                decrypt: false,
                sign: false,
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
                maximum_bytes: 3,
            },
        },
    }
}
