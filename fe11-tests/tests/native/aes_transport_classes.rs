// SPDX-License-Identifier: Apache-2.0
//! AES wrapping against independently encoded secret and PKCS #8 private keys.
use crate::{
    arguments::{hex, Arguments}, credentials::Credentials, key_wrap_fixture, module_controls,
    object_owner::Owner, outcome::Failure, report::Report,
};
use fe11::*;
use std::{fs::File, io::{self, Read, Write}, path::Path};

enum Target {
    Secret(Vec<u8>),
    Private(Vec<Vec<u8>>),
}

struct Vector {
    mechanism: NativeTransportMechanism,
    iv: Vec<u8>,
    wrapping_key: Vec<u8>,
    target: Target,
    expected_envelope: Vec<u8>,
    expected_witness: Vec<u8>,
}

impl Vector {
    fn read(path: &Path) -> std::result::Result<Self, Failure> {
        let mut text = String::new();
        File::open(path).and_then(|f| f.take(16385).read_to_string(&mut text))
            .map_err(|_| Failure::Input("transport_class_vector"))?;
        let f: Vec<_> = text.lines().collect();
        if text.len() > 16384 || f.len() < 7 {
            return Err(Failure::Input("transport_class_fields"));
        }
        let (mechanism, iv_len) = match f[0] {
            "AES_CBC" => (NativeTransportMechanism::AES_CBC, 16),
            "AES_CBC_PAD" => (NativeTransportMechanism::AES_CBC_PAD, 16),
            "AES_KEY_WRAP" => (NativeTransportMechanism::AES_KEY_WRAP, 0),
            "AES_KEY_WRAP_PAD" => (NativeTransportMechanism::AES_KEY_WRAP_PAD, 0),
            _ => return Err(Failure::Input("transport_class_mechanism")),
        };
        let bytes = |s: &str, max: usize| hex(s, max).map_err(Failure::Input);
        let iv = bytes(f[2], 16)?;
        let wrapping_key = bytes(f[3], 16)?;
        let expected_envelope = bytes(f[4], 2048)?;
        let expected_witness = bytes(f[5], 256)?;
        if iv.len() != iv_len || wrapping_key.len() != 16 || expected_envelope.is_empty() {
            return Err(Failure::Input("transport_class_width"));
        }
        let target = match (f[1], f.len(), expected_witness.len()) {
            ("secret", 7, 16) => Target::Secret(bytes(f[6], 16)?),
            ("private", 14, 256) => Target::Private(f[6..].iter()
                .map(|v| bytes(v, 256)).collect::<std::result::Result<_, _>>()?),
            _ => return Err(Failure::Input("transport_class_target")),
        };
        Ok(Self { mechanism, iv, wrapping_key, target, expected_envelope, expected_witness })
    }

    fn parameters(&self) -> NativeTransportParameters<'_> {
        NativeTransportParameters::Fixed {
            mechanism: self.mechanism,
            bytes: if self.iv.is_empty() { None } else { Some(&self.iv) },
        }
    }

    fn check(
        &self, session: &Session, kek: &NativeObjectRef, target: &NativeObjectRef,
        recovered: &mut Option<CreatedObjectSet>,
    ) -> std::result::Result<(), Failure> {
        // Include room for either common padding interpretation. A difference
        // in the returned bytes must remain visible independently of capacity.
        let output = session.wrap_native_key(kek, target, self.parameters(), 2048)?;
        if output.as_bytes() != self.expected_envelope {
            return Err(Failure::Oracle("transport_class_envelope_mismatch"));
        }
        let (class, attributes) = match self.target {
            Target::Secret(_) => (ManagedClass::SecretKey, Vec::from(key_wrap_fixture::template())),
            Target::Private(_) => (ManagedClass::PrivateKey, Vec::from(super::rsa_private_transport::private_template())),
        };
        let created = session.unwrap_native_key(kek, &self.expected_envelope, self.parameters(), class,
            GenerationTemplate {
                attributes: &attributes, limits: key_wrap_fixture::limits(attributes.len(), 0),
                observation: None,
                destination: DestinationPlan { search: DestinationSearchPlan::NotRequested,
                    user: DestinationUserObservation::NotRequested },
            })?;
        *recovered = Some(created.objects);
        created.observation?;
        let [key] = recovered.as_ref().ok_or(Failure::Input("transport_class_owner"))?.as_slice()
            else { return Err(Failure::Oracle("transport_class_count")); };
        if created.remainder.is_some() { return Err(Failure::Oracle("transport_class_remainder")); }
        let parts = [b"abc".as_slice()];
        let limits = InputLimits { maximum_parts: 1, maximum_total_bytes: 3 };
        let matched = match self.target {
            Target::Private(_) => session.sign_native(key,
                NativeSignatureParameters::Parameterless(NativeSignatureAlgorithm::SHA256_RSA_PKCS),
                MessageRoute::Single, &parts, limits, 256, None)?.as_bytes() == self.expected_witness,
            Target::Secret(_) => session.compute_native_mac(key,
                NativeMacParameters::Full(NativeMacAlgorithm::MD5_HMAC),
                MessageRoute::Single, &parts, limits, 16, None)?.as_bytes() == self.expected_witness,
        };
        if !matched { return Err(Failure::Oracle("unwrapped_key_known_answer")); }
        Ok(())
    }
}

pub(super) fn execute<W: Write>(
    module: Module, args: &Arguments, pins: &Credentials, report: Report<W>,
) -> io::Result<bool> {
    let mut owner = None;
    let mut keys = Vec::new();
    let mut recovered = None;
    let setup = (|| -> std::result::Result<Vector, Failure> {
        let v = Vector::read(&args.vector)?;
        owner = Some(Owner::open(&module, &args.config, false)?);
        let Some(o @ Owner::Session(session)) = &owner else { return Err(Failure::Input("session_required")); };
        session.login_as(LoginRole::User, SecretPin::new(pins.user.to_vec()))?;
        keys.push(o.import_secret(&v.wrapping_key, fe11_sys::CKK_AES,
            [StandardAttribute::WRAP, StandardAttribute::UNWRAP])?);
        keys.push(match &v.target {
            Target::Secret(bytes) => key_wrap_fixture::import_target(o, bytes)?,
            Target::Private(components) => o.import_rsa_private(components, StandardAttribute::EXTRACTABLE)?,
        });
        Ok(v)
    })();
    let body = match (&setup, &owner, keys.as_slice()) {
        (Ok(v), Some(Owner::Session(session)), [kek, target]) => v.check(session, kek, target, &mut recovered),
        (Err(_), _, _) => Ok(()),
        _ => Err(Failure::Input("transport_class_ownership")),
    };
    let mut cleanup = Vec::new();
    if let Some(o) = &owner {
        for key in recovered.iter().flat_map(|set| set.as_slice()).chain(keys.iter().rev()) {
            if let Err(e) = key_wrap_fixture::destroy(o, key) { cleanup.push(e.into()); }
        }
        cleanup.extend(o.close(None));
    }
    drop(recovered); drop(keys); drop(owner);
    if let Err(e) = module.close() { cleanup.push(e.into()); }
    module_controls::finish(report, setup.map(|_| ()), body, cleanup)
}
