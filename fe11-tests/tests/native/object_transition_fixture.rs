// SPDX-License-Identifier: Apache-2.0
//! Real creator and independently selected peer references for object lifetimes.
use super::{
    arguments::hex,
    configuration::{select_token, Configuration},
    credentials::Credentials,
    outcome::Failure,
};
use fe11::*;
use std::{fs::File, io::Read, num::NonZeroUsize, path::Path};

pub struct Case {
    pub private: bool,
    pub token: bool,
    pub state: String,
    pub action: String,
    pub expected_mac: Vec<u8>,
}
impl Case {
    pub fn read(path: &Path) -> std::result::Result<Self, Failure> {
        let mut data = Vec::new();
        File::open(path)
            .map_err(|_| Failure::Input("fixture_open"))?
            .take(257)
            .read_to_end(&mut data)
            .map_err(|_| Failure::Input("fixture_read"))?;
        if data.len() > 256 {
            return Err(Failure::Input("fixture_size"));
        }
        let text = std::str::from_utf8(&data).map_err(|_| Failure::Input("fixture_encoding"))?;
        let fields: Vec<_> = text.split_terminator('\n').collect();
        if fields.len() != 5
            || !matches!(fields[0], "true" | "false")
            || !matches!(fields[1], "true" | "false")
            || !matches!(
                fields[2],
                "LIVE"
                    | "DESTROYED"
                    | "CREATOR_CLOSED"
                    | "LOGGED_OUT"
                    | "PERSISTENT_HIDDEN"
                    | "RUNTIME_RETIRED"
            )
            || !matches!(
                fields[3],
                "read"
                    | "search"
                    | "copy"
                    | "mutate"
                    | "destroy"
                    | "use"
                    | "mutate_label"
                    | "destroy_again"
                    | "logout"
                    | "close_last"
                    | "shared_login"
            )
        {
            return Err(Failure::Input("object_transition_fields"));
        }
        let expected_mac = hex(fields[4], 32).map_err(Failure::Input)?;
        if expected_mac.len() != 32 {
            return Err(Failure::Input("object_mac_width"));
        }
        Ok(Self {
            private: fields[0] == "true",
            token: fields[1] == "true",
            state: fields[2].into(),
            action: fields[3].into(),
            expected_mac,
        })
    }
}
pub fn limits(count: usize, bytes: usize) -> AttributeTemplateLimits {
    AttributeTemplateLimits {
        maximum_depth: 0,
        maximum_attributes: count,
        maximum_value_bytes: bytes,
    }
}
pub fn label_template(label: &[u8]) -> [AttributeInput<'_>; 1] {
    [AttributeInput {
        attribute: StandardAttribute::LABEL.into(),
        value: AttributeInputValue::Bytes(label),
    }]
}
pub fn find(session: &Session, label: &[u8]) -> std::result::Result<Vec<NativeObjectRef>, Failure> {
    let template = label_template(label);
    let mut iterator = session.iter_native_objects(
        &template,
        limits(1, label.len()),
        NonZeroUsize::new(2).unwrap(),
    )?;
    let mut objects = Vec::new();
    while let Some(object) = iterator.next() {
        objects.push(object?);
        // A case creates at most an original and a separately labelled copy.
        if objects.len() > 1 {
            iterator.finish()?;
            return Err(Failure::Oracle("object_search_duplicate_label"));
        }
    }
    iterator.finish()?;
    Ok(objects)
}
pub fn read(
    session: &Session,
    object: &NativeObjectRef,
    label: &[u8],
) -> Result<FlatAttributeBatch> {
    let requests = [
        (StandardAttribute::LABEL, label.len()),
        (StandardAttribute::VALUE, 32),
        (
            StandardAttribute::CLASS,
            std::mem::size_of::<fe11_sys::CK_ULONG>(),
        ),
        (
            StandardAttribute::KEY_TYPE,
            std::mem::size_of::<fe11_sys::CK_ULONG>(),
        ),
    ]
    .map(|(attribute, capacity)| FlatAttributeRequest {
        attribute: attribute.into(),
        plan: FlatAttributeReadPlan::Buffer { capacity },
    });
    session.read_flat_attributes(
        object,
        &requests,
        label.len() + 32 + 2 * std::mem::size_of::<fe11_sys::CK_ULONG>(),
    )
}
pub fn check(batch: &FlatAttributeBatch, label: &[u8]) -> std::result::Result<(), Failure> {
    if batch.calls()
        != AttributeBatchCalls::One(AttributeBatchCall {
            code: 0,
            attribute_count: 4,
        })
        || batch.len() != 4
    {
        return Err(Failure::Oracle("object_attribute_calls"));
    }
    let observations: Vec<_> = batch.iter().collect();
    for (observation, expected) in [(observations[0], label), (observations[1], &[0xaa; 32][..])] {
        match &observation.value {
            FlatAttributeValue::Available(value) if value.as_bytes() == expected => (),
            _ => return Err(Failure::Oracle("object_attribute_bytes")),
        }
    }
    if observations[2].unsigned()? != fe11_sys::CKO_SECRET_KEY as u64
        || observations[3].unsigned()? != fe11_sys::CKK_GENERIC_SECRET as u64
    {
        return Err(Failure::Oracle("object_class_type"));
    }
    Ok(())
}
pub struct Fixture {
    pub creator: Option<Session>,
    pub peer: Option<Session>,
    pub original: Option<NativeObjectRef>,
    pub selected: Option<NativeObjectRef>,
    pub copied: Option<NativeObjectRef>,
    pub creator_closed: bool,
    pub peer_closed: bool,
    pub module_closed: bool,
    pub logged: bool,
    pub label: Vec<u8>,
    pub changed: Vec<u8>,
    pub copy_label: Vec<u8>,
}
impl Fixture {
    pub fn empty(label: &[u8]) -> Self {
        Self {
            creator: None,
            peer: None,
            original: None,
            selected: None,
            copied: None,
            creator_closed: false,
            peer_closed: false,
            module_closed: false,
            logged: false,
            label: label.to_vec(),
            changed: [label, b".changed"].concat(),
            copy_label: [label, b".copy"].concat(),
        }
    }
    pub fn peer(&self) -> std::result::Result<&Session, Failure> {
        self.peer.as_ref().ok_or(Failure::Input("object_peer"))
    }
    pub fn object(&self) -> std::result::Result<&NativeObjectRef, Failure> {
        self.selected
            .as_ref()
            .ok_or(Failure::Input("object_peer_reference"))
    }
    pub fn login(&mut self, pins: &Credentials) -> std::result::Result<(), Failure> {
        self.peer()?
            .login_as(LoginRole::User, SecretPin::new(pins.user.to_vec()))?;
        self.logged = true;
        Ok(())
    }
    pub fn prepare(
        &mut self,
        module: &Module,
        config: &Configuration,
        pins: &Credentials,
        case: &Case,
    ) -> std::result::Result<(), Failure> {
        let token =
            select_token(module, &config.label).ok_or(Failure::Input("token_not_unique"))?;
        let selected = module.select(&token)?;
        self.creator = Some(selected.open_session(true)?);
        self.peer = Some(selected.open_session(true)?);
        self.login(pins)?;
        let attr = |attribute: StandardAttribute, value| AttributeInput {
            attribute: attribute.into(),
            value,
        };
        let template = [
            attr(
                StandardAttribute::CLASS,
                AttributeInputValue::Unsigned(fe11_sys::CKO_SECRET_KEY as u64),
            ),
            attr(
                StandardAttribute::KEY_TYPE,
                AttributeInputValue::Unsigned(fe11_sys::CKK_GENERIC_SECRET as u64),
            ),
            attr(
                StandardAttribute::TOKEN,
                AttributeInputValue::Boolean(case.token),
            ),
            attr(
                StandardAttribute::PRIVATE,
                AttributeInputValue::Boolean(case.private),
            ),
            attr(StandardAttribute::SIGN, AttributeInputValue::Boolean(true)),
            attr(
                StandardAttribute::VERIFY,
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
                StandardAttribute::COPYABLE,
                AttributeInputValue::Boolean(true),
            ),
            attr(
                StandardAttribute::MODIFIABLE,
                AttributeInputValue::Boolean(true),
            ),
            attr(
                StandardAttribute::DESTROYABLE,
                AttributeInputValue::Boolean(true),
            ),
            attr(
                StandardAttribute::LABEL,
                AttributeInputValue::Bytes(&self.label),
            ),
            attr(
                StandardAttribute::VALUE,
                AttributeInputValue::Bytes(&[0xaa; 32]),
            ),
        ];
        self.original = Some(
            self.creator
                .as_ref()
                .ok_or(Failure::Input("object_creator"))?
                .create_native_object(
                    &template,
                    limits(
                        template.len(),
                        self.label.len() + 32 + 2 * std::mem::size_of::<fe11_sys::CK_ULONG>() + 9,
                    ),
                )?,
        );
        let mut found = find(self.peer()?, &self.label)?;
        if found.len() != 1 {
            return Err(Failure::Oracle("object_initial_peer_search"));
        }
        self.selected = found.pop();
        check(
            &read(self.peer()?, self.object()?, &self.label)?,
            &self.label,
        )?;
        if case.state == "CREATOR_CLOSED" {
            // A raw search result does not infer CKA_TOKEN from the creation
            // template. Establish the lifetime used by this particular scenario
            // through the public observation API before closing its creator.
            let mut admission = super::object_fixture::public_key_options(&self.label).admission;
            admission.observation.verify = false;
            admission.observation.maximum_bytes = 2;
            let _view = self.peer()?.observe_native_object(
                self.object()?,
                ManagedClass::SecretKey,
                admission,
                ContentObservation::NotRequested,
            )?;
            let provenance = if case.token {
                ObjectCreatorProvenance::TokenObject
            } else {
                ObjectCreatorProvenance::KnownCreationSession
            };
            if self.object()?.creator_provenance() != provenance
                || self.object()?.visibility_observation() != Observation::Observed(case.private)
            {
                return Err(Failure::Oracle("object_creator_observation_prerequisite"));
            }
        }
        match case.state.as_str() {
            "DESTROYED" => self.peer()?.destroy_native_object(self.object()?)?,
            "CREATOR_CLOSED" => {
                self.creator
                    .as_ref()
                    .ok_or(Failure::Input("object_creator"))?
                    .close()?;
                self.creator_closed = true;
            }
            "LOGGED_OUT" | "PERSISTENT_HIDDEN" => {
                self.peer()?.logout()?;
                self.logged = false;
            }
            "RUNTIME_RETIRED" => {
                self.creator
                    .as_ref()
                    .ok_or(Failure::Input("object_creator"))?
                    .close()?;
                self.creator_closed = true;
                self.peer()?.close()?;
                self.peer_closed = true;
                self.logged = false;
                module.close()?;
                self.module_closed = true;
            }
            "LIVE" => (),
            _ => return Err(Failure::Input("object_state")),
        }
        Ok(())
    }
    pub fn cleanup(&mut self, pins: &Credentials) -> Vec<Failure> {
        let mut errors = Vec::new();
        if self.module_closed {
            return errors;
        }
        if self.peer.is_some() && !self.peer_closed {
            if !self.logged {
                if let Err(error) = self.login(pins) {
                    errors.push(error);
                }
            }
            // Reselect after Logout: private token objects have new native
            // references; private session objects may have ceased to exist.
            for label in [&self.label, &self.changed, &self.copy_label] {
                match find(self.peer.as_ref().unwrap(), label) {
                    Ok(objects) => {
                        for object in objects {
                            if let Err(error) =
                                self.peer.as_ref().unwrap().destroy_native_object(&object)
                            {
                                errors.push(error.into());
                            }
                        }
                    }
                    Err(error) => errors.push(error),
                }
            }
        }
        if let Some(creator) = &self.creator {
            if !self.creator_closed {
                match creator.close() {
                    Ok(()) => self.creator_closed = true,
                    Err(error) => errors.push(error.into()),
                }
            }
        }
        if let Some(peer) = &self.peer {
            if !self.peer_closed {
                if self.logged {
                    match peer.logout() {
                        Ok(()) => self.logged = false,
                        Err(error) => errors.push(error.into()),
                    }
                }
                match peer.close() {
                    Ok(()) => self.peer_closed = true,
                    Err(error) => errors.push(error.into()),
                }
            }
        }
        errors
    }
}
