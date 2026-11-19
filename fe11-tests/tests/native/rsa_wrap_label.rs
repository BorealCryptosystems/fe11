// SPDX-License-Identifier: Apache-2.0
//! RSA key wrapping with independent decoding and optional OAEP label binding.
use super::{key_wrap_fixture, module_controls, Case, Configuration, Failure, Owner};
use crate::{
    outcome,
    report::{Phase, Report},
};
use fe11::*;
use std::{
    fs::OpenOptions,
    io::{self, Write},
};

const LABEL: &[u8] = b"wrap\0label";

fn parameters(label: &[u8]) -> NativeTransportParameters<'_> {
    NativeTransportParameters::RsaOaep(NativeOaepParameters {
        hash: fe11_sys::CKM_SHA256 as u64,
        mgf: fe11_sys::CKG_MGF1_SHA256 as u64,
        source: fe11_sys::CKZ_DATA_SPECIFIED as u64,
        data: Some(label),
    })
}

fn unwrap(
    owner: &Owner,
    key: &NativeObjectRef,
    envelope: &[u8],
    parameters: NativeTransportParameters<'_>,
) -> Result<CreatedObjects<NativeUnwrappedObject>> {
    let attributes = key_wrap_fixture::template();
    let template = GenerationTemplate {
        attributes: &attributes,
        limits: key_wrap_fixture::limits(attributes.len(), 0),
        observation: None,
        destination: DestinationPlan {
            search: DestinationSearchPlan::NotRequested,
            user: DestinationUserObservation::NotRequested,
        },
    };
    match owner {
        Owner::Session(s) => s.unwrap_native_key(
            key,
            envelope,
            parameters,
            ManagedClass::SecretKey,
            template,
        ),
        Owner::Advanced(s) => s.unwrap_native_key(
            key,
            envelope,
            parameters,
            ManagedClass::SecretKey,
            template,
        ),
    }
}

pub(super) fn execute<W: Write>(
    module: Module,
    config: &Configuration,
    case: Case,
    mut report: Report<W>,
) -> io::Result<bool> {
    let mut owner = None;
    let mut keys = Vec::new();
    let mut created = Vec::new();
    let setup = (|| -> std::result::Result<(), Failure> {
        owner = Some(Owner::open(
            &module,
            config,
            case.label_owner.ok_or(Failure::Input("wrap_label_owner"))?,
        )?);
        let o = owner.as_ref().ok_or(Failure::Input("wrap_label_owner"))?;
        keys.push(o.import_rsa_public_usage_enabled(
            &case.key[0],
            &case.key[1],
            StandardAttribute::WRAP,
            true,
        )?);
        keys.push(o.import_rsa_private(&case.key, StandardAttribute::UNWRAP)?);
        keys.push(key_wrap_fixture::import_target(o, &case.plain)?);
        Ok(())
    })();
    let body = (|| -> std::result::Result<(), Failure> {
        if setup.is_err() {
            return Ok(());
        }
        let o = owner.as_ref().ok_or(Failure::Input("wrap_label_owner"))?;
        let [public, private, target] = keys.as_slice() else {
            return Err(Failure::Input("wrap_label_keys"));
        };
        let mechanism = || if case.secret_class { case.parameters() } else { parameters(LABEL) };
        let envelope = match o {
            Owner::Session(s) => {
                s.wrap_native_key(public, target, mechanism(), case.key[0].len())
            }
            Owner::Advanced(s) => {
                s.wrap_native_key(public, target, mechanism(), case.key[0].len())
            }
        }?;
        if envelope.as_bytes().len() != case.key[0].len() {
            return Err(Failure::Oracle("wrap_label_envelope_length"));
        }
        // Ciphertext of a public fixture only. The supervisor owns this fresh
        // directory and independently decodes OAEP before admitting the case.
        let mut options = OpenOptions::new();
        options.write(true).create_new(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            options.mode(0o600);
        }
        let mut output = options
            .open("public-wrap-ciphertext.bin")
            .map_err(|_| Failure::Input("wrap_reference_create"))?;
        output
            .write_all(envelope.as_bytes())
            .map_err(|_| Failure::Input("wrap_reference_write"))?;
        output
            .flush()
            .map_err(|_| Failure::Input("wrap_reference_flush"))?;
        let input = if case.secret_class { case.envelope.as_slice() } else { envelope.as_bytes() };
        let value = unwrap(o, private, input, mechanism())?;
        created.push(value.objects);
        value.observation?;
        if value.remainder.is_some() {
            return Err(Failure::Oracle("wrap_label_remainder"));
        }
        let set = created
            .last()
            .ok_or(Failure::Input("wrap_label_created"))?
            .as_slice();
        let [recovered] = set else {
            return Err(Failure::Oracle("wrap_label_object_count"));
        };
        let plan = FlatAttributeReadPlan::Buffer {
            capacity: case.plain.len(),
        };
        let value = match o {
            Owner::Session(s) => s.read_flat_attribute(recovered, StandardAttribute::VALUE, plan),
            Owner::Advanced(s) => s.read_flat_attribute(recovered, StandardAttribute::VALUE, plan),
        }?;
        if value.calls != (AttributeReadCalls::Direct { code: 0 }) {
            return Err(Failure::Oracle("wrap_label_value_code"));
        }
        match value.value {
            FlatAttributeValue::Available(v) if v.as_bytes() == case.plain => (),
            _ => return Err(Failure::Oracle("wrap_label_recovered_value")),
        }
        if case.secret_class {
            let Owner::Session(session) = o else { return Err(Failure::Input("secret_class_owner")); };
            // HMAC-MD5 over "abc" with the public 001122...eeff test key.
            const EXPECTED: [u8; 16] = [0xc9, 0x1e, 0xbd, 0x2e, 0xb8, 0xba, 0xbb, 0x2e,
                0x05, 0x07, 0x72, 0xdb, 0xe3, 0xcf, 0x29, 0x91];
            let mac = session.compute_native_mac(recovered,
                NativeMacParameters::Full(NativeMacAlgorithm::MD5_HMAC), MessageRoute::Single,
                &[b"abc".as_slice()], InputLimits { maximum_parts: 1, maximum_total_bytes: 3 }, 16, None)?;
            return if mac.as_bytes() == EXPECTED { Ok(()) }
                else { Err(Failure::Oracle("recovered_generic_secret_mac")) };
        }
        // Only the last label byte changes; an embedded NUL is never a terminator.
        match unwrap(o, private, envelope.as_bytes(), parameters(b"wrap\0labeh")) {
            Err(
                error @ Error::Native {
                    function: "C_UnwrapKey",
                    code,
                    may_have_effect: true,
                },
            ) if code == fe11_sys::CKR_GENERAL_ERROR as u64 => {
                outcome::record(&mut report, Phase::Body, &Failure::Product(error))
                    .map_err(|_| Failure::Input("report_write"))?;
            }
            Err(error) => return Err(error.into()),
            Ok(value) => {
                created.push(value.objects);
                return Err(Failure::Oracle("wrap_wrong_label_accepted"));
            }
        }
        Ok(())
    })();
    let mut cleanup = Vec::new();
    if let Some(o) = &owner {
        for set in &created {
            for key in set.as_slice() {
                if let Err(e) = key_wrap_fixture::destroy(o, key) {
                    cleanup.push(e.into());
                }
            }
        }
        for key in &keys {
            if let Err(e) = key_wrap_fixture::destroy(o, key) {
                cleanup.push(e.into());
            }
        }
        cleanup.extend(o.close(None));
    }
    drop(created);
    drop(keys);
    drop(owner);
    if let Err(e) = module.close() {
        cleanup.push(e.into());
    }
    module_controls::finish(report, setup, body, cleanup)
}
