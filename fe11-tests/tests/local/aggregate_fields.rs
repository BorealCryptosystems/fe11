// SPDX-License-Identifier: Apache-2.0
//! Independent roundtrips for fields of complete public records.
#[path = "aggregate_fields/fixtures.rs"]
mod fixtures;
#[path = "aggregate_fields/aead_parameters.rs"]
mod aead_parameters;
#[path = "aggregate_fields/agreement_key_spec.rs"]
mod agreement_key_spec;
#[path = "aggregate_fields/ccm_decrypt_message.rs"]
mod ccm_decrypt_message;
#[path = "aggregate_fields/ccm_encrypt_message.rs"]
mod ccm_encrypt_message;
#[path = "aggregate_fields/ccm_parameters.rs"]
mod ccm_parameters;
#[path = "aggregate_fields/certificate_spec.rs"]
mod certificate_spec;
#[path = "aggregate_fields/content_mutation_plan.rs"]
mod content_mutation_plan;
#[path = "aggregate_fields/creation_observation.rs"]
mod creation_observation;
#[path = "aggregate_fields/data_spec.rs"]
mod data_spec;
#[path = "aggregate_fields/derivation_observation_plan.rs"]
mod derivation_observation_plan;
#[path = "aggregate_fields/destination_plan.rs"]
mod destination_plan;
#[path = "aggregate_fields/extension_output_region.rs"]
mod extension_output_region;
#[path = "aggregate_fields/extension_pointer.rs"]
mod extension_pointer;
#[path = "aggregate_fields/gcm_decrypt_message.rs"]
mod gcm_decrypt_message;
#[path = "aggregate_fields/gcm_encrypt_message.rs"]
mod gcm_encrypt_message;
#[path = "aggregate_fields/hkdf_key_spec.rs"]
mod hkdf_key_spec;
#[path = "aggregate_fields/interface_descriptor.rs"]
mod interface_descriptor;
#[path = "aggregate_fields/kem_key_spec.rs"]
mod kem_key_spec;
#[path = "aggregate_fields/key_spec.rs"]
mod key_spec;
#[path = "aggregate_fields/montgomery_key_spec.rs"]
mod montgomery_key_spec;
#[path = "aggregate_fields/oaep_key_spec.rs"]
mod oaep_key_spec;
#[path = "aggregate_fields/object_admission.rs"]
mod object_admission;
#[path = "aggregate_fields/object_metadata.rs"]
mod object_metadata;
#[path = "aggregate_fields/object_selector.rs"]
mod object_selector;
#[path = "aggregate_fields/pqc_key_spec.rs"]
mod pqc_key_spec;
#[path = "aggregate_fields/pqc_private_import_spec.rs"]
mod pqc_private_import_spec;
#[path = "aggregate_fields/public_key_import_options.rs"]
mod public_key_import_options;
#[path = "aggregate_fields/rsa_key_encryption_spec.rs"]
mod rsa_key_encryption_spec;
#[path = "aggregate_fields/signature_message.rs"]
mod signature_message;
#[path = "aggregate_fields/stream_aead_encrypt_message.rs"]
mod stream_aead_encrypt_message;
#[path = "aggregate_fields/stream_aead_parameters.rs"]
mod stream_aead_parameters;
#[path = "aggregate_fields/stream_progress.rs"]
mod stream_progress;
#[path = "aggregate_fields/symmetric_key_spec.rs"]
mod symmetric_key_spec;
#[path = "aggregate_fields/tls_prf_request.rs"]
mod tls_prf_request;
#[path = "aggregate_fields/token_resource_status.rs"]
mod token_resource_status;
#[path = "aggregate_fields/token_session_limit.rs"]
mod token_session_limit;
#[path = "aggregate_fields/validation_observation.rs"]
mod validation_observation;
#[path = "aggregate_fields/windows_loader_search_directories.rs"]
mod windows_loader_search_directories;

#[path = "aggregate_fields/trait_contracts.rs"]
mod trait_contracts;
