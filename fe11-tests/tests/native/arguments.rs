// SPDX-License-Identifier: Apache-2.0
//! Public invocation metadata only; credentials are read from the separate stdin pipe.
use super::configuration::Configuration;
use fe11::InterfaceSelection;
use std::path::PathBuf;

pub struct Arguments {
    pub mode: String,
    pub case: String,
    pub source_digest: String,
    pub recipe_digest: String,
    pub module_digest: String,
    pub config: Configuration,
    pub vector: PathBuf,
}

pub fn hex(value: &str, limit: usize) -> Result<Vec<u8>, &'static str> {
    if value.len() % 2 != 0 || value.len() / 2 > limit {
        return Err("invalid_hex_length");
    }
    let mut result = Vec::with_capacity(value.len() / 2);
    for pair in value.as_bytes().chunks_exact(2) {
        let digit = |byte: u8| match byte {
            b'0'..=b'9' => Some(byte - b'0'),
            b'a'..=b'f' => Some(byte - b'a' + 10),
            b'A'..=b'F' => Some(byte - b'A' + 10),
            _ => None,
        };
        let high = digit(pair[0]).ok_or("invalid_hex_digit")?;
        let low = digit(pair[1]).ok_or("invalid_hex_digit")?;
        result.push(high * 16 + low);
    }
    Ok(result)
}

pub fn parse() -> Result<Arguments, &'static str> {
    let values: Vec<_> = std::env::args_os().skip(1).collect();
    if values.len() != 9 {
        return Err("invalid_argument_count");
    }
    let text = |index: usize| values[index].to_str().ok_or("invalid_metadata_encoding");
    let mode = text(0)?;
    if !matches!(
        mode,
        "provision"
            | "digest-vector"
            | "digest-stream"
            | "ecdsa-encoding"
            | "ecdsa-vector"
            | "rsa-vector"
            | "ticket-family"
            | "ticket-identity"
            | "ticket-boundary"
            | "key-wrap-vector"
            | "key-wrap-controlled"
            | "oaep-vector"
            | "oaep-encrypt"
            | "dsa-vector"
            | "mac-vector"
            | "mac-equivalence"
            | "cipher-vector"
            | "gcm-vector"
            | "gcm-parameters"
            | "gcm-usage"
            | "gcm-withholding"
            | "edwards-vector"
            | "edwards-negative"
            | "ecdh-vector"
            | "ecdh-invalid"
            | "dh-vector"
            | "pqc-import-guard"
            | "batch-state"
            | "typed-selection"
            | "module-accessor"
            | "advanced-setting"
            | "admission-family"
            | "authenticated-transport-guard"
            | "oaep-reference-guard"
            | "oaep-destination-guard"
            | "foreign-info"
            | "foreign-callback"
            | "foreign-event-guard"
            | "foreign-session"
            | "foreign-slot-guard"
            | "digest-live-alias"
            | "retained-digest"
            | "retained-cipher"
            | "retained-signature"
            | "oaep-encrypt-denied"
            | "oaep-decrypt-denied"
            | "module-boundary"
            | "builder-observation"
            | "builder-choices"
            | "borrowed-client"
            | "runtime-successor"
            | "cross-runtime-guard"
            | "engine-choices"
            | "builder-runtime-choices"
            | "derive-usage-negative"
            | "derive-template-negative"
            | "dh-usage-denied"
            | "dh-template-denied"
            | "ecdh-usage-denied"
            | "ecdh-template-denied"
            | "encrypt-data-vector"
            | "digest-cancel"
            | "digest-transition"
            | "authentication-admission"
            | "authentication-state"
            | "search-transition"
            | "search-population"
            | "context-login"
            | "context-wrong-pin"
            | "context-local-guards"
            | "context-missing-login"
            | "context-pss-login"
            | "object-contract"
            | "random-contract"
            | "interface-contract"
            | "initialization-contract"
            | "session-contract"
            | "pin-contract"
            | "legacy-contract"
            | "token-label-contract"
            | "discovery-contract"
            | "cipher-transition"
            | "gcm-transition"
            | "mac-transition"
            | "rsa-transition"
            | "pqc-transition"
            | "edwards-transition"
            | "ecdsa-transition"
            | "single-signature-transition"
            | "kem-vector"
            | "kem-import"
            | "kem-lifecycle"
            | "absent-mechanism"
            | "aead-preinit"
            | "import-encoding"
            | "cipher-batch-transition"
            | "digest-capacity"
            | "digest-refused"
            | "pin-admission"
            | "rsa-domain"
            | "rsa-known"
            | "rsa-usage"
            | "rsa-negative"
            | "single-part-guard-0"
            | "single-part-guard-1"
            | "single-part-guard-2"
            | "single-part-guard-3"
            | "single-part-guard-4"
            | "single-part-guard-5"
            | "attribute-guard"
            | "trusted-wrap-session"
            | "trusted-wrap-advanced"
            | "kem-wrong-key"
            | "extension-cipher"
            | "extension-gcm"
            | "extension-oaep"
            | "extension-oaep-null"
            | "extension-signature"
            | "extension-generation"
            | "extension-pair"
            | "extension-objects"
            | "signature-extension-stream-route"
            | "signature-extension-single-route"
            | "classical-sign-denied"
            | "classical-changed"
            | "concatenation-negative"
            | "concatenation-values"
            | "transport-negative"
            | "rsa-unwrap-negative"
            | "extension-rsa-aes-session"
            | "extension-rsa-aes-advanced"
            | "rsa-wrap-negative"
            | "rsa-aes-private-unwrap"
            | "rsa-aes-private-wrap"
            | "signature-result-metadata"
            | "gcm-result-metadata"
            | "hkdf-hash-widths"
            | "session-abi-widths"
            | "attribute-value-partitions"
            | "attribute-mixed-values"
            | "attribute-creation-change"
            | "optional-rsa-crt-import"
                | "absent-object-attributes"
            | "aes-transport-class"
            | "aes-entry-guard"
            | "binary-generation"
            | "classical-verify-denied"
            | "generation-transition"
            | "digest-ticket-cipher"
            | "digest-family-view"
            | "input-guard"
            | "admission-scope"
            | "module-lifecycle"
            | "active-pair"
            | "module-controls"
            | "verification-guards"
            | "signing-guards"
            | "session-conversion"
            | "generated-aes"
            | "pqc-verification-guards"
            | "token-drain-session"
            | "drain-ticket-identity"
            | "agreement-input-guards"
            | "mechanism-request-guard"
            | "digest-key-identity"
            | "aead-input-guards"
            | "pqc-signing-guard"
            | "unsupported-lifecycle"
            | "symmetric-guards"
            | "dual-cbc"
            | "shared-module"
            | "direct-generation"
            | "direct-material"
            | "ticket-state-guard"
            | "object-transition"
            | "public-guard"
            | "record-parser"
            | "recovery-record"
            | "generation-negative"
            | "cipher-usage"
            | "des-parity"
            | "ticket-owner-identity"
            | "rsa-changed-signature"
            | "pqc-vector"
            | "pqc-random"
            | "classical-sign"
            | "dsa-import-identity"
            | "dh-import-identity" | "dh-public-import"
            | "generation-vector"
            | "observer-control"
            | "discovery-probe"
            | "catalog-probe"
            | "algorithm-probe"
    ) {
        return Err("unknown_worker_mode");
    }
    let module_digest = text(5)?;
    let module_sha256 = hex(module_digest, 32)?
        .try_into()
        .map_err(|_| "invalid_module_digest")?;
    let interface = match text(6)? {
        "Legacy240" => InterfaceSelection::Legacy240,
        "Standard32" => InterfaceSelection::Standard {
            version: (3, 2),
            required_flags: 0,
        },
        _ => return Err("unknown_interface_selection"),
    };
    let label = text(7)?;
    if label.is_empty()
        || label.len() > 32
        || !label
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || b"-_".contains(&byte))
    {
        return Err("invalid_token_label");
    }
    let module = PathBuf::from(&values[4]);
    let vector = PathBuf::from(&values[8]);
    if !module.is_absolute() || !vector.is_absolute() {
        return Err("absolute_input_path_required");
    }
    Ok(Arguments {
        mode: mode.to_owned(),
        case: text(1)?.to_owned(),
        source_digest: text(2)?.to_owned(),
        recipe_digest: text(3)?.to_owned(),
        module_digest: module_digest.to_owned(),
        config: Configuration {
            module,
            module_sha256,
            interface,
            label: label.to_owned(),
        },
        vector,
    })
}
