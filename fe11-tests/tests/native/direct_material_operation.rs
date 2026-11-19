// SPDX-License-Identifier: Apache-2.0
//! Native results remain owned before descriptive reads or assertions can fail.
use super::{
    direct_material_fixture::Case, key_wrap_fixture, object_owner::Owner, outcome::Failure,
};
use fe11::*;

pub struct Fixture {
    pub owner: Option<Owner>,
    pub key: Option<NativeObjectRef>,
    pub denied_key: Option<NativeObjectRef>,
    pub target: Option<NativeObjectRef>,
    pub created: Vec<CreatedObjectSet>,
    pub values: Vec<Vec<u8>>,
    pub wrapped: Vec<ExtensionResult>,
    pub closed: bool,
    pub logged: bool,
}
impl Fixture {
    pub fn owner(&self) -> std::result::Result<&Owner, Failure> {
        self.owner.as_ref().ok_or(Failure::Input("material_owner"))
    }
    pub fn session(&self) -> std::result::Result<&Session, Failure> {
        match self.owner()? {
            Owner::Session(session) => Ok(session),
            _ => Err(Failure::Input("material_session")),
        }
    }
    pub fn invoke(&mut self, c: &Case, invalid: bool) -> std::result::Result<(), Failure> {
        let key = if invalid && c.route == "wrap" {
            &self.denied_key
        } else {
            &self.key
        }
        .as_ref()
        .ok_or(Failure::Input("material_key"))?;
        if c.route == "wrap" {
            let target = self.target.as_ref().ok_or(Failure::Input("wrap_target"))?;
            let value = self.session()?.wrap_native_key(
                key,
                target,
                key_wrap_fixture::parameters(false),
                c.expected.len(),
            )?;
            if value.as_bytes() != c.expected {
                return Err(Failure::Oracle("published_wrap_bytes"));
            }
            self.values.push(value.as_bytes().to_vec());
            self.wrapped.push(value);
            return Ok(());
        }
        let mut attributes = Vec::from(key_wrap_fixture::template());
        if c.route == "derive" {
            attributes.push(AttributeInput {
                attribute: StandardAttribute::VALUE_LEN.into(),
                value: AttributeInputValue::Unsigned(c.expected.len() as u64),
            });
        }
        // A single missing required attribute supplies the terminal negative.
        // The envelope/base and all remaining attributes are the positive tuple.
        if invalid {
            attributes.remove(0);
        }
        let template = GenerationTemplate {
            attributes: &attributes,
            limits: key_wrap_fixture::limits(attributes.len(), 0),
            observation: None,
            destination: DestinationPlan {
                search: DestinationSearchPlan::NotRequested,
                user: DestinationUserObservation::NotRequested,
            },
        };
        let (objects, remainder_present, observation) = if c.route == "unwrap" {
            let result = self.session()?.unwrap_native_key(
                key,
                &c.input,
                key_wrap_fixture::parameters(false),
                ManagedClass::SecretKey,
                template,
            )?;
            (
                result.objects,
                result.remainder.is_some(),
                result.observation.map(|_| ()),
            )
        } else {
            let result = self.session()?.derive_native_key(
                key,
                NativeKeyDerivation::EncryptData(NativeEncryptData::AesEcb(&c.input)),
                template,
            )?;
            (
                result.objects,
                result.remainder.is_some(),
                result.observation.map(|_| ()),
            )
        };
        self.created.push(objects);
        observation?;
        let objects = self
            .created
            .last()
            .ok_or(Failure::Input("material_result"))?
            .as_slice();
        if objects.len() != 1 || remainder_present {
            return Err(Failure::Oracle("material_creation_count"));
        }
        let read = self.session()?.read_flat_attribute(
            &objects[0],
            StandardAttribute::VALUE,
            FlatAttributeReadPlan::Buffer {
                capacity: c.expected.len(),
            },
        )?;
        if read.calls != (AttributeReadCalls::Direct { code: 0 }) {
            return Err(Failure::Oracle("material_read_status"));
        }
        match read.value {
            FlatAttributeValue::Available(value) if value.as_bytes() == c.expected => {
                self.values.push(value.as_bytes().to_vec());
                Ok(())
            }
            _ => Err(Failure::Oracle("published_material_bytes")),
        }
    }
    pub fn snapshot(&self) -> Vec<(Option<usize>, ObjectCreatorProvenance, Observation<bool>)> {
        self.created
            .iter()
            .flat_map(|set| set.as_slice())
            .map(|object| {
                (
                    object.output_slot(),
                    object.creator_provenance(),
                    object.visibility_observation(),
                )
            })
            .collect()
    }
    pub fn close(&mut self) -> std::result::Result<(), Failure> {
        self.session()?.close()?;
        self.closed = true;
        Ok(())
    }
    pub fn cleanup(&mut self) -> Vec<Failure> {
        let mut errors = Vec::new();
        if self.closed {
            return errors;
        }
        if let Ok(session) = self.session() {
            for object in self
                .created
                .iter()
                .flat_map(|set| set.as_slice())
                .chain(self.target.iter())
                .chain(self.denied_key.iter())
                .chain(self.key.iter())
            {
                if let Err(error) = session.destroy_native_object(object) {
                    errors.push(error.into());
                }
            }
            if self.logged {
                if let Err(error) = session.logout() {
                    errors.push(error.into());
                }
            }
            if let Err(error) = session.close() {
                errors.push(error.into());
            } else {
                self.closed = true;
            }
        }
        errors
    }
}
