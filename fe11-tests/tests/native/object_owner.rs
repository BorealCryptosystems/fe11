// SPDX-License-Identifier: Apache-2.0
//! Synchronous session ownership and exact object templates for native cases.
use super::{
    configuration::{select_token, Configuration},
    outcome::Failure,
};
use fe11::*;

pub enum Owner {
    Session(Session),
    Advanced(AdvancedSession),
}

impl Owner {
    pub fn open(
        module: &Module,
        config: &Configuration,
        advanced: bool,
    ) -> std::result::Result<Self, Failure> {
        let token =
            select_token(module, &config.label).ok_or(Failure::Input("token_not_unique"))?;
        let session = module.select(&token)?.open_session(true)?;
        Ok(if advanced {
            Self::Advanced(session.into_advanced()?)
        } else {
            Self::Session(session)
        })
    }

    pub fn import_secret(
        &self,
        bytes: &[u8],
        key_type: fe11_sys::CK_KEY_TYPE,
        usage: [StandardAttribute; 2],
    ) -> Result<NativeObjectRef> {
        self.import_secret_usages(bytes, key_type, [(usage[0], true), (usage[1], true)])
    }

    pub fn import_secret_usages(
        &self,
        bytes: &[u8],
        key_type: fe11_sys::CK_KEY_TYPE,
        usage: [(StandardAttribute, bool); 2],
    ) -> Result<NativeObjectRef> {
        let attr = |attribute: StandardAttribute, value| AttributeInput {
            attribute: attribute.into(),
            value,
        };
        // Public known-answer keys are session objects. The requested usages
        // are explicit; these fixtures require neither login nor persistent keys.
        let template = [
            attr(
                StandardAttribute::CLASS,
                AttributeInputValue::Unsigned(fe11_sys::CKO_SECRET_KEY as u64),
            ),
            attr(
                StandardAttribute::KEY_TYPE,
                AttributeInputValue::Unsigned(key_type as u64),
            ),
            attr(
                StandardAttribute::TOKEN,
                AttributeInputValue::Boolean(false),
            ),
            attr(
                StandardAttribute::PRIVATE,
                AttributeInputValue::Boolean(false),
            ),
            attr(usage[0].0, AttributeInputValue::Boolean(usage[0].1)),
            attr(usage[1].0, AttributeInputValue::Boolean(usage[1].1)),
            attr(StandardAttribute::VALUE, AttributeInputValue::Bytes(bytes)),
        ];
        let limits = AttributeTemplateLimits {
            maximum_depth: 0,
            maximum_attributes: template.len(),
            maximum_value_bytes: bytes.len() + 20,
        };
        self.create(&template, limits)
    }

    pub fn create(
        &self,
        template: &[AttributeInput<'_>],
        limits: AttributeTemplateLimits,
    ) -> Result<NativeObjectRef> {
        match self {
            Self::Session(session) => session.create_native_object(template, limits),
            Self::Advanced(session) => session.create_native_object(template, limits),
        }
    }

    pub fn close(&self, key: Option<&NativeObjectRef>) -> Vec<Failure> {
        let mut failures = Vec::new();
        if let Some(key) = key {
            let result = match self {
                Self::Session(session) => session.destroy_native_object(key),
                Self::Advanced(session) => session.destroy_native_object(key),
            };
            if let Err(error) = result {
                failures.push(error.into());
            }
        }
        let result = match self {
            Self::Session(session) => session.close().map_err(Failure::from),
            Self::Advanced(session) => match session.close() {
                Ok(AdvancedCloseStatus::Complete) => Ok(()),
                Ok(AdvancedCloseStatus::Pending) => Err(Failure::Oracle("cleanup_pending")),
                Err(error) => Err(error.into()),
            },
        };
        if let Err(error) = result {
            failures.push(error);
        }
        failures
    }
}
