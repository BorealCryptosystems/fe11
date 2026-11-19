// SPDX-License-Identifier: Apache-2.0
//! Explicit ABI declarations use the same owned-key harness as typed operations.
use super::{
    arguments::Arguments, credentials::Credentials, report::Report, signature_extension_route,
    single_key_case,
};
use fe11::Module;
use std::io::{self, Write};
#[path = "hkdf_widths.rs"]
mod hkdf_widths;
#[path = "session_widths.rs"]
mod session_widths;
#[path = "attribute_probe_object.rs"]
mod attribute_probe_object;
#[path = "attribute_creation_change.rs"]
mod attribute_creation_change;
#[path = "attribute_mixed_fields.rs"]
mod attribute_mixed_fields;
#[path = "attribute_value_partitions.rs"]
mod attribute_value_partitions;
#[path = "absent_object_attributes.rs"]
mod absent_attributes;
#[path = "aes_transport_classes.rs"]
mod aes_transport_classes;
#[path = "result_metadata.rs"]
mod result_metadata;
#[path = "extension_cipher.rs"]
mod cipher;
#[path = "extension_gcm.rs"]
mod gcm;
#[path = "extension_generation.rs"]
mod generation;
#[path = "kem_wrong_key.rs"]
mod kem_wrong_key;
#[path = "extension_oaep.rs"]
mod oaep;
#[path = "extension_objects.rs"]
mod objects;
#[path = "extension_pair.rs"]
mod pair;
#[path = "extension_signature.rs"]
mod signature;
#[path = "rsa_private_transport.rs"]
mod rsa_private_transport;
#[path = "trusted_wrap.rs"]
mod trusted_wrap;

pub fn accepts(mode: &str) -> bool {
    matches!(
        mode,
        "signature-extension-stream-route"
            | "kem-wrong-key"
            | "gcm-result-metadata"
            | "hkdf-hash-widths"
            | "session-abi-widths"
            | "attribute-value-partitions"
            | "attribute-mixed-values"
            | "attribute-creation-change"
            | "optional-rsa-crt-import"
            | "absent-object-attributes"
            | "aes-transport-class"
            | "signature-result-metadata"
            | "rsa-aes-private-unwrap"
            | "rsa-aes-private-wrap"
            | "trusted-wrap-session"
            | "trusted-wrap-advanced"
            | "signature-extension-single-route"
            | "extension-cipher"
            | "extension-gcm"
            | "extension-oaep"
            | "extension-oaep-null"
            | "extension-signature"
            | "extension-generation"
            | "extension-pair"
            | "extension-objects"
            | "extension-rsa-aes-session"
            | "extension-rsa-aes-advanced"
    )
}

pub fn execute<W: Write>(
    module: Module,
    args: &Arguments,
    pins: &Credentials,
    report: Report<W>,
) -> io::Result<bool> {
    match args.mode.as_str() {
        "rsa-aes-private-unwrap" | "rsa-aes-private-wrap" => rsa_private_transport::execute(module, args, pins, report),
        "hkdf-hash-widths" => hkdf_widths::execute(module, args, report),
        "session-abi-widths" => single_key_case::execute::<session_widths::Case, _>(
            module, &args.config, &args.vector, report,
        ),
        "optional-rsa-crt-import" => single_key_case::execute::<attribute_creation_change::Case<true>, _>(
            module, &args.config, &args.vector, report,
        ),
        "attribute-creation-change" => single_key_case::execute::<attribute_creation_change::Case, _>(
            module, &args.config, &args.vector, report,
        ),
        "attribute-mixed-values" => single_key_case::execute::<attribute_value_partitions::Case<true>, _>(
            module, &args.config, &args.vector, report,
        ),
        "attribute-value-partitions" => single_key_case::execute::<attribute_value_partitions::Case, _>(
            module, &args.config, &args.vector, report,
        ),
        "absent-object-attributes" => single_key_case::execute::<absent_attributes::Case, _>(
            module, &args.config, &args.vector, report,
        ),
        "aes-transport-class" => aes_transport_classes::execute(module, args, pins, report),
        "gcm-result-metadata" => single_key_case::execute::<result_metadata::Gcm, _>(
            module, &args.config, &args.vector, report,
        ),
        "signature-result-metadata" => single_key_case::execute::<result_metadata::Signature, _>(
            module, &args.config, &args.vector, report,
        ),
        "kem-wrong-key" => kem_wrong_key::execute(module, args, report),
        "trusted-wrap-session" | "trusted-wrap-advanced" => {
            trusted_wrap::execute(module, args, pins, report)
        }
        "extension-rsa-aes-session" | "extension-rsa-aes-advanced" => {
            super::extension_rsa_aes::execute(module, args, pins, report)
        }
        "extension-oaep" => single_key_case::execute::<oaep::Case<false>, _>(
            module,
            &args.config,
            &args.vector,
            report,
        ),
        "extension-oaep-null" => single_key_case::execute::<oaep::Case<true>, _>(
            module,
            &args.config,
            &args.vector,
            report,
        ),
        "extension-gcm" => {
            single_key_case::execute::<gcm::Case, _>(module, &args.config, &args.vector, report)
        }
        "extension-objects" => objects::execute(module, args, report),
        "extension-pair" => pair::execute(module, args, report),
        "extension-generation" => generation::execute(module, args, report),
        "signature-extension-stream-route" => single_key_case::execute::<
            signature_extension_route::Route<true>,
            _,
        >(module, &args.config, &args.vector, report),
        "signature-extension-single-route" => single_key_case::execute::<
            signature_extension_route::Route<false>,
            _,
        >(module, &args.config, &args.vector, report),
        "extension-cipher" => {
            single_key_case::execute::<cipher::Case, _>(module, &args.config, &args.vector, report)
        }
        "extension-signature" => single_key_case::execute::<signature::Case, _>(
            module,
            &args.config,
            &args.vector,
            report,
        ),
        _ => Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "extension route",
        )),
    }
}
