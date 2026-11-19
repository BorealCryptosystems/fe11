// SPDX-License-Identifier: Apache-2.0
//! Public API contracts and runner input validation that need no native module.
#[path = "local/cancellation_flags.rs"]
mod cancellation_flags;
#[path = "local/catalogs.rs"]
mod catalogs;
#[path = "local/credential_frames.rs"]
mod credential_frames;
#[path = "support/credentials.rs"]
mod credentials;
#[path = "local/digest_parameters.rs"]
mod digest_parameters;
#[path = "local/eddsa_parameters.rs"]
mod eddsa_parameters;
#[cfg(target_os = "linux")]
#[path = "local/engine_host.rs"]
mod engine_host;
#[path = "local/engine_paths.rs"]
mod engine_paths;
#[path = "local/kem_coefficient_support.rs"]
mod kem_coefficient_support;
#[path = "local/kem_coefficients.rs"]
mod kem_coefficients;
#[path = "local/kem_parameters.rs"]
mod kem_parameters;
#[path = "local/montgomery_spki.rs"]
mod montgomery_spki;
#[path = "local/pqc_parameters.rs"]
mod pqc_parameters;
#[path = "local/prepared_digests.rs"]
mod prepared_digests;
#[path = "local/representation_guards.rs"]
mod representation_guards;
#[path = "local/spki_parameters.rs"]
mod spki_parameters;

#[path = "local/agreement_domain.rs"]
mod agreement_domain;

#[path = "local/public_encoding_boundaries.rs"]
mod public_encoding_boundaries;

#[path = "local/cancellation_width.rs"]
mod cancellation_width;

#[path = "local/otp_parameters.rs"]
mod otp_parameters;

#[path = "local/stream_parameters.rs"]
mod stream_parameters;

#[path = "local/stateful_signature_parameters.rs"]
mod stateful_signature_parameters;

#[path = "local/integer_conversion_boundaries.rs"]
mod integer_conversion_boundaries;

#[path = "local/diagnostic_values.rs"]
mod diagnostic_values;

#[path = "local/error_payloads.rs"]
mod error_payloads;

#[path = "local/mac_general_identity.rs"]
mod mac_general_identity;

#[path = "local/owned_value_constructors.rs"]
mod owned_value_constructors;

#[path = "local/attribute_layouts.rs"]
mod attribute_layouts;

#[path = "local/der_framing.rs"]
mod der_framing;

#[path = "local/allocation_boundaries.rs"]
mod allocation_boundaries;

#[path = "local/selector_contracts.rs"]
mod selector_contracts;

#[path = "local/derivation_selectors.rs"]
mod derivation_selectors;

#[path = "local/selector_members.rs"]
mod selector_members;

#[path = "local/diagnostic_equality.rs"]
mod diagnostic_equality;

#[path = "local/public_widths.rs"]
mod public_widths;

#[path = "local/owned_encodings.rs"]
mod owned_encodings;

#[path = "local/unit_variant_identity.rs"]
mod unit_variant_identity;

#[path = "local/scalar_records.rs"]
mod scalar_records;

#[path = "local/enum_fields.rs"]
mod enum_fields;

#[path = "local/composite_records.rs"]
mod composite_records;

#[path = "local/enum_payloads.rs"]
mod enum_payloads;

#[path = "local/algorithm_metadata.rs"]
mod algorithm_metadata;

#[path = "local/aggregate_fields.rs"]
mod aggregate_fields;
