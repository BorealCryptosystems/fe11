// SPDX-License-Identifier: Apache-2.0
//! Known answers through the verification component's published C ABI.
//!
//! These calls test the component itself. They do not stand in for PKCS#11
//! verification or a classical Rust method on VerifyEngine.
use super::super::{arguments::hex, outcome::Failure};
use fe11::VerifyEngine;
use fe11_verify_engine_api as api;
use libloading::Library;
use std::{fs::File, io::Read, mem::size_of, path::Path};

#[path = "engine_signature_format.rs"]
mod signature_format;

struct Component {
    table: api::Interface,
    _image: Library,
}

impl Component {
    fn load(selected: &VerifyEngine) -> Result<Self, Failure> {
        // SAFETY: VerifyEngine has already explicitly loaded and pinned this
        // integrity-checked trusted component. The runner checks the same image
        // identity. This extra library owner retains every function pointer.
        let image = unsafe { Library::new(&selected.info().source_path) }
            .map_err(|_| Failure::Input("engine_component_load"))?;
        // SAFETY: the published discovery symbol has exactly this C signature;
        // its image remains owned throughout discovery and every later call.
        let discover = unsafe { image.get::<api::GetInterface>(api::ENTRY_POINT) }
            .map_err(|_| Failure::Input("engine_component_entry"))?;
        let mut table = api::Interface {
            structure_size: 0,
            abi_version: 0,
            information: None,
            probe: None,
            verification_algorithms: None,
            verify: None,
            digest: None,
            release: None,
        };
        // SAFETY: exclusive aligned initialized table storage of the exact ABI
        // size; discovery copies synchronously and retains no pointer to it.
        let status = unsafe { discover(api::ABI_VERSION, &mut table, size_of::<api::Interface>()) };
        if status != api::status::OK
            || table.abi_version != api::ABI_VERSION
            || table.structure_size as usize != size_of::<api::Interface>()
        {
            return Err(Failure::Oracle("engine_component_interface"));
        }
        Ok(Self {
            table,
            _image: image,
        })
    }
}

/// Even a failed shape/status assertion releases an owner returned by the call.
struct Output<'a> {
    value: api::OwnedBytes,
    release: api::Release,
    _component: &'a Component,
}
impl Drop for Output<'_> {
    fn drop(&mut self) {
        // SAFETY: this descriptor is initialized empty, then written only by
        // the originating component. We never mutate its owner; it is released
        // once, before the borrowed component image can be dropped.
        unsafe { (self.release)(self.value.owner) };
    }
}

fn number<T: std::str::FromStr>(text: &str) -> Result<T, Failure> {
    text.parse()
        .map_err(|_| Failure::Input("engine_fixture_number"))
}

pub(super) fn check(selected: &VerifyEngine, path: &Path) -> Result<(), Failure> {
    let mut raw = Vec::new();
    File::open(path)
        .map_err(|_| Failure::Input("engine_fixture_open"))?
        .take(1_048_577)
        .read_to_end(&mut raw)
        .map_err(|_| Failure::Input("engine_fixture_read"))?;
    if raw.len() > 1_048_576 {
        return Err(Failure::Input("engine_fixture_size"));
    }
    let text = std::str::from_utf8(&raw).map_err(|_| Failure::Input("engine_fixture_utf8"))?;
    let fields: Vec<_> = text.split_terminator('\n').collect();
    if fields.first() != Some(&"api") {
        return Err(Failure::Input("engine_fixture_prefix"));
    }
    let component = Component::load(selected)?;
    match fields.get(1).copied() {
        Some("digest") if fields.len() == 6 => digest(&component, &fields),
        Some("verify" | "unavailable" | "unknown-scheme") if fields.len() == 15 => {
            verify(&component, &fields)
        }
        Some("format") if fields.len() == 16 => verify(&component, &fields),
        _ => Err(Failure::Input("engine_fixture_fields")),
    }
}

fn digest(component: &Component, fields: &[&str]) -> Result<(), Failure> {
    let message = hex(fields[4], 262_144).map_err(Failure::Input)?;
    let expected = hex(fields[5], 4096).map_err(Failure::Input)?;
    let request = api::DigestRequest {
        algorithm: api::Bytes::from_slice(fields[2].as_bytes()),
        output_length: expected.len(),
        xof: number(fields[3])?,
        message: api::Bytes::from_slice(&message),
    };
    let call = component
        .table
        .digest
        .ok_or(Failure::Oracle("engine_digest_entry"))?;
    let mut output = Output {
        value: api::OwnedBytes::EMPTY,
        release: component
            .table
            .release
            .ok_or(Failure::Oracle("engine_release_entry"))?,
        _component: component,
    };
    // SAFETY: immutable request/name/message buffers live through this synchronous
    // call. The exclusive output slot is disjoint and the selected image is live.
    let status = unsafe { call(&request, size_of::<api::DigestRequest>(), &mut output.value) };
    if status != api::status::OK
        || output.value.bytes.length != expected.len()
        || output.value.owner.is_null()
        || (!expected.is_empty() && output.value.bytes.pointer.is_null())
    {
        return Err(Failure::Oracle("engine_digest_result_shape"));
    }
    let bytes = if expected.is_empty() {
        &[]
    } else {
        // SAFETY: the trusted component's successful ABI result owns this exact
        // checked-length readable view. Output retains it until after comparison.
        unsafe { std::slice::from_raw_parts(output.value.bytes.pointer, expected.len()) }
    };
    if bytes != expected {
        return Err(Failure::Oracle("engine_digest_known_answer"));
    }
    Ok(())
}

fn verify(component: &Component, fields: &[&str]) -> Result<(), Failure> {
    let key = hex(fields[10], 32_768).map_err(Failure::Input)?;
    let message = hex(fields[11], 262_144).map_err(Failure::Input)?;
    let signature = hex(fields[12], 32_768).map_err(Failure::Input)?;
    let context = hex(fields[8], 255).map_err(Failure::Input)?;
    let request = api::VerificationRequest {
        algorithm: api::Bytes::from_slice(fields[2].as_bytes()),
        key_format: number(fields[3])?,
        key: api::Bytes::from_slice(&key),
        scheme: number(fields[4])?,
        digest: api::Bytes::from_slice(fields[5].as_bytes()),
        mgf_digest: api::Bytes::from_slice(fields[6].as_bytes()),
        salt_length: number(fields[7])?,
        context: api::Bytes::from_slice(&context),
        message_encoding: number(fields[9])?,
    };
    let expected_status: u32 = number(fields[13])?;
    let expected_verdict: u32 = number(fields[14])?;
    if fields[1] == "format" {
        if request.scheme != api::scheme::DIGEST_SIGNATURE
            || fields[2] != "EC"
            || expected_status != api::status::OK
            || expected_verdict != 1
        {
            return Err(Failure::Input("engine_format_control"));
        }
        return signature_format::check(component, &request, &message, &signature, fields[15]);
    }
    if fields[1] == "unavailable" {
        if fields[2] != "ED25519"
            || request.key_format != api::key_format::RAW_PUBLIC
            || request.scheme != api::scheme::EDDSA
            || request.message_encoding != api::eddsa_instance::ED25519_CONTEXT
            || !context.is_empty()
            || !fields[5].is_empty()
            || !fields[6].is_empty()
            || request.salt_length != 0
            || expected_status != api::status::UNAVAILABLE
            || expected_verdict != 2
        {
            return Err(Failure::Input("engine_unavailable_fixture"));
        }
        return unavailable(component, &request, &message, &signature);
    }
    if expected_verdict > 1 || expected_status != api::status::OK {
        return Err(Failure::Input("engine_vector_expected_verdict"));
    }
    if fields[1] == "unknown-scheme" {
        if expected_verdict != 1 {
            return Err(Failure::Input("engine_unknown_scheme_control"));
        }
        return signature_format::unknown_scheme(component, &request, &message, &signature);
    }
    let probe = component
        .table
        .probe
        .ok_or(Failure::Oracle("engine_probe_entry"))?;
    // SAFETY: all request descriptors borrow the live owned fixture buffers;
    // the component retains no pointer after its synchronous probe returns.
    let prepared = unsafe { probe(&request, size_of::<api::VerificationRequest>()) };
    if prepared != api::status::OK {
        return Err(Failure::Oracle("engine_verification_preparation"));
    }
    let call = component
        .table
        .verify
        .ok_or(Failure::Oracle("engine_verify_entry"))?;
    let mut verified = 2u32;
    // SAFETY: initialized immutable request/message/signature buffers and an
    // exclusive aligned disjoint result slot remain alive until return.
    let status = unsafe {
        call(
            &request,
            size_of::<api::VerificationRequest>(),
            api::Bytes::from_slice(&message),
            api::Bytes::from_slice(&signature),
            &mut verified,
        )
    };
    if status != expected_status || verified != expected_verdict {
        return Err(Failure::Oracle("engine_verification_known_answer"));
    }
    Ok(())
}

/// The published component reports its unavailable empty Ed25519ctx preparation
/// explicitly. A pure Ed25519 control proves that the same key/signature and
/// loaded engine work; an operational error is never called invalid verification.
fn unavailable(
    component: &Component,
    request: &api::VerificationRequest,
    message: &[u8],
    signature: &[u8],
) -> Result<(), Failure> {
    let probe = component
        .table
        .probe
        .ok_or(Failure::Oracle("engine_probe_entry"))?;
    let call = component
        .table
        .verify
        .ok_or(Failure::Oracle("engine_verify_entry"))?;
    let control = api::VerificationRequest {
        message_encoding: api::eddsa_instance::ED25519,
        ..*request
    };
    let mut verified = 2;
    // SAFETY: both descriptors borrow live fixture storage, the component owns
    // the code image, and the exclusive output scalar is disjoint from inputs.
    let (prepared, status) = unsafe {
        (
            probe(&control, size_of::<api::VerificationRequest>()),
            call(
                &control,
                size_of::<api::VerificationRequest>(),
                api::Bytes::from_slice(message),
                api::Bytes::from_slice(signature),
                &mut verified,
            ),
        )
    };
    if prepared != api::status::OK || status != api::status::OK || verified != 1 {
        return Err(Failure::Oracle("engine_unavailable_positive_control"));
    }
    // SAFETY: identical live buffers and owner; only the explicit instance is
    // different. The output value on failure is not inspected or credited.
    let (prepared, status) = unsafe {
        (
            probe(request, size_of::<api::VerificationRequest>()),
            call(
                request,
                size_of::<api::VerificationRequest>(),
                api::Bytes::from_slice(message),
                api::Bytes::from_slice(signature),
                &mut verified,
            ),
        )
    };
    if prepared != api::status::UNAVAILABLE || status != api::status::UNAVAILABLE {
        return Err(Failure::Oracle("engine_unavailable_status"));
    }
    Ok(())
}
