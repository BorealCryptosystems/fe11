// SPDX-License-Identifier: Apache-2.0
//! Known RSA envelopes establish a usable unwrapping key before one mutation.
use super::{
    arguments::hex,
    configuration::Configuration,
    credentials::Credentials,
    key_wrap_fixture, module_controls,
    object_owner::Owner,
    outcome::{self, Failure},
    report::{Phase, Report},
};
use fe11::*;
use std::{
    fs::File,
    io::{self, Read, Write},
    path::Path,
};

pub(super) struct Case {
    pub(super) algorithm: String,
    pub(super) label_owner: Option<bool>,
    pub(super) secret_class: bool,
    pub(super) private_target: Option<Vec<Vec<u8>>>,
    usage: bool,
    private_unwrap_bits: Option<u64>,
    pub(super) key: Vec<Vec<u8>>,
    pub(super) envelope: Vec<u8>,
    pub(super) plain: Vec<u8>,
}
impl Case {
    pub(super) fn read(path: &Path) -> std::result::Result<Self, Failure> {
        Self::read_inner(path, false, false)
    }
    pub(super) fn read_wrapping(path: &Path) -> std::result::Result<Self, Failure> {
        Self::read_inner(path, true, false)
    }
    pub(super) fn read_private_transport(path: &Path) -> std::result::Result<Self, Failure> {
        Self::read_inner(path, false, true)
    }
    fn read_inner(
        path: &Path,
        wrapping: bool,
        private_transport: bool,
    ) -> std::result::Result<Self, Failure> {
        let mut bytes = Vec::new();
        File::open(path)
            .map_err(|_| Failure::Input("unwrap_fixture_open"))?
            .take(32769)
            .read_to_end(&mut bytes)
            .map_err(|_| Failure::Input("unwrap_fixture_read"))?;
        if bytes.len() > 32768 {
            return Err(Failure::Input("unwrap_fixture_size"));
        }
        let text =
            std::str::from_utf8(&bytes).map_err(|_| Failure::Input("unwrap_fixture_encoding"))?;
        let fields: Vec<_> = text.split_terminator('\n').collect();
        // A class-only refusal needs the public wrapping key and a separate,
        // extractable target. It never consumes ciphertext or plaintext.
        if wrapping && fields.get(1) == Some(&"distinct-private-target") {
            if fields.len() != 12 || !matches!(fields[0], "pkcs" | "oaep") {
                return Err(Failure::Input("wrap_private_class_fields"));
            }
            let components = fields[2..]
                .iter()
                .map(|value| hex(value, 1024).map_err(Failure::Input))
                .collect::<std::result::Result<Vec<_>, _>>()?;
            if components.iter().any(Vec::is_empty) || components[0] == components[2] {
                return Err(Failure::Input("wrap_distinct_rsa_keys"));
            }
            let mut key = components;
            let target = key.split_off(2);
            return Ok(Self {
                algorithm: fields[0].into(),
                label_owner: None,
                secret_class: false,
                private_target: Some(target),
                usage: false,
                private_unwrap_bits: None,
                key,
                envelope: Vec::new(),
                plain: Vec::new(),
            });
        }
        let private_unwrap_bits = if private_transport && fields.first() == Some(&"rsa_aes") {
            match fields.get(1) {
                Some(&"private-128") => Some(128),
                Some(&"private-192") => Some(192),
                Some(&"private-256") => Some(256),
                _ => None,
            }
        } else {
            None
        };
        if private_transport != private_unwrap_bits.is_some()
            || fields.len() != 12
            || !matches!(fields[0], "pkcs" | "oaep" | "rsa_aes")
            || !(private_unwrap_bits.is_some()
                || matches!(fields[1], "usage" | "template")
                || (wrapping
                    && fields[1] == "private-target"
                    && matches!(fields[0], "pkcs" | "oaep"))
                || (wrapping && fields[1] == "generic-secret" && matches!(fields[0], "pkcs" | "oaep"))
                || (wrapping
                    && fields[0] == "oaep"
                    && matches!(fields[1], "label-session" | "label-advanced")))
        {
            return Err(Failure::Input("unwrap_fixture_fields"));
        }
        let key = fields[2..10]
            .iter()
            .map(|v| hex(v, 1024).map_err(Failure::Input))
            .collect::<std::result::Result<Vec<_>, _>>()?;
        if key.iter().any(Vec::is_empty) {
            return Err(Failure::Input("unwrap_key_components"));
        }
        let envelope = hex(fields[10], 2048).map_err(Failure::Input)?;
        let plain = hex(fields[11], 1024).map_err(Failure::Input)?;
        if plain.is_empty()
            || (fields[0] != "rsa_aes" && envelope.len() != key[0].len())
            || (fields[0] == "rsa_aes"
                && private_unwrap_bits.is_none()
                && envelope.len() != key[0].len() + 32)
            || (private_unwrap_bits.is_some()
                && (plain.len() != 256 || envelope.len() <= key[0].len() + 8))
        {
            return Err(Failure::Input("unwrap_fixture_lengths"));
        }
        Ok(Self {
            algorithm: fields[0].into(),
            secret_class: fields[1] == "generic-secret",
            label_owner: match fields[1] {
                "generic-secret" | "label-session" => Some(false),
                "label-advanced" => Some(true),
                _ => None,
            },
            private_target: (fields[1] == "private-target").then(|| key.clone()),
            usage: fields[1] == "usage",
            private_unwrap_bits,
            key,
            envelope,
            plain,
        })
    }
    pub(super) fn parameters(&self) -> NativeTransportParameters<'_> {
        let oaep = NativeOaepParameters {
            hash: fe11_sys::CKM_SHA256 as u64,
            mgf: fe11_sys::CKG_MGF1_SHA256 as u64,
            source: fe11_sys::CKZ_DATA_SPECIFIED as u64,
            data: None,
        };
        match self.algorithm.as_str() {
            "pkcs" => NativeTransportParameters::Fixed {
                mechanism: NativeTransportMechanism::RSA_PKCS,
                bytes: None,
            },
            "oaep" => NativeTransportParameters::RsaOaep(oaep),
            _ => NativeTransportParameters::RsaAes {
                aes_key_bits: self.private_unwrap_bits.unwrap_or(192),
                oaep,
            },
        }
    }
}

fn unwrap(
    session: &Session,
    key: &NativeObjectRef,
    case: &Case,
    incomplete: bool,
    retained: &mut Option<CreatedObjectSet>,
) -> std::result::Result<(), Failure> {
    let complete = key_wrap_fixture::template();
    let attributes = if incomplete {
        &complete[1..]
    } else {
        &complete[..]
    };
    let template = GenerationTemplate {
        attributes,
        limits: key_wrap_fixture::limits(attributes.len(), 0),
        observation: None,
        destination: DestinationPlan {
            search: DestinationSearchPlan::NotRequested,
            user: DestinationUserObservation::NotRequested,
        },
    };
    let result = session.unwrap_native_key(
        key,
        &case.envelope,
        case.parameters(),
        ManagedClass::SecretKey,
        template,
    )?;
    *retained = Some(result.objects);
    result.observation?;
    if result.remainder.is_some() {
        return Err(Failure::Oracle("unwrap_unexpected_remainder"));
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
    let mut owner = None;
    let mut key = None;
    let mut denied = None;
    let mut control = None;
    let mut created = None;
    let setup = (|| -> std::result::Result<Case, Failure> {
        let case = Case::read(path)?;
        owner = Some(Owner::open(&module, config, false)?);
        let o = owner.as_ref().ok_or(Failure::Input("unwrap_owner"))?;
        if case.algorithm == "rsa_aes" {
            // RSA-AES unwrapping can create a private intermediate AES key.
            // Establish user authentication before the unchanged control and
            // negative operation; keep the requested key attributes identical.
            let Owner::Session(session) = o else {
                return Err(Failure::Input("unwrap_login_owner"));
            };
            session.login_as(LoginRole::User, SecretPin::new(pins.user.to_vec()))?;
        }
        key = Some(o.import_rsa_private(&case.key, StandardAttribute::UNWRAP)?);
        if case.usage {
            denied =
                Some(o.import_rsa_private_usage(&case.key, StandardAttribute::UNWRAP, false)?);
        }
        Ok(case)
    })();
    let body = match &setup {
        Err(_) => Ok(()),
        Ok(case) => (|| -> std::result::Result<(), Failure> {
            let Some(Owner::Session(session)) = &owner else {
                return Err(Failure::Input("unwrap_owner"));
            };
            let key = key.as_ref().ok_or(Failure::Input("unwrap_key"))?;
            unwrap(session, key, case, false, &mut control)?;
            let objects = control
                .as_ref()
                .ok_or(Failure::Input("unwrap_control"))?
                .as_slice();
            if objects.len() != 1 {
                return Err(Failure::Oracle("unwrap_control_count"));
            }
            let value = session.read_flat_attribute(
                &objects[0],
                StandardAttribute::VALUE,
                FlatAttributeReadPlan::Buffer {
                    capacity: case.plain.len(),
                },
            )?;
            if value.calls != (AttributeReadCalls::Direct { code: 0 }) {
                return Err(Failure::Oracle("unwrap_control_value_code"));
            }
            match value.value {
                FlatAttributeValue::Available(v) if v.as_bytes() == case.plain => (),
                _ => return Err(Failure::Oracle("unwrap_control_plaintext")),
            }
            let key = if case.usage {
                denied.as_ref().ok_or(Failure::Input("unwrap_denied_key"))?
            } else {
                key
            };
            let expected = if case.usage {
                fe11_sys::CKR_KEY_FUNCTION_NOT_PERMITTED
            } else {
                fe11_sys::CKR_TEMPLATE_INCOMPLETE
            };
            match unwrap(session, key, case, !case.usage, &mut created) {
                Err(Failure::Product(
                    error @ Error::Native {
                        function: "C_UnwrapKey",
                        code,
                        ..
                    },
                )) if code == expected as u64 => {
                    outcome::record(&mut report, Phase::Body, &Failure::Product(error))
                        .map_err(|_| Failure::Input("report_write"))?;
                    Ok(())
                }
                Err(error) => Err(error),
                Ok(()) => Err(Failure::Oracle("invalid_unwrap_accepted")),
            }
        })(),
    };
    let mut cleanup = Vec::new();
    if let Some(o) = &owner {
        for objects in control.iter().chain(created.iter()) {
            for object in objects.as_slice() {
                if let Err(e) = key_wrap_fixture::destroy(o, object) {
                    cleanup.push(e.into());
                }
            }
        }
        for object in key.iter().chain(denied.iter()) {
            if let Err(e) = key_wrap_fixture::destroy(o, object) {
                cleanup.push(e.into());
            }
        }
    }
    drop(control);
    drop(created);
    drop(key);
    drop(denied);
    if let Some(o) = &owner {
        cleanup.extend(o.close(None));
    }
    drop(owner);
    if let Err(e) = module.close() {
        cleanup.push(e.into());
    }
    module_controls::finish(report, setup.map(|_| ()), body, cleanup)
}
