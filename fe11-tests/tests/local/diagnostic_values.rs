// SPDX-License-Identifier: Apache-2.0
//! Diagnostic construction proves representation, not occurrence of native faults.
#[path = "diagnostic_values/busy_aead_messages.rs"]
mod busy_aead_messages;
#[path = "diagnostic_values/busy_asynchronous_execution.rs"]
mod busy_asynchronous_execution;
#[path = "diagnostic_values/busy_authentication.rs"]
mod busy_authentication;
#[path = "diagnostic_values/busy_callbacks.rs"]
mod busy_callbacks;
#[path = "diagnostic_values/busy_cancellation.rs"]
mod busy_cancellation;
#[path = "diagnostic_values/busy_checkpoint_capture.rs"]
mod busy_checkpoint_capture;
#[path = "diagnostic_values/busy_cipher_continuation.rs"]
mod busy_cipher_continuation;
#[path = "diagnostic_values/busy_combined_operations.rs"]
mod busy_combined_operations;
#[path = "diagnostic_values/busy_derived_object_creation.rs"]
mod busy_derived_object_creation;
#[path = "diagnostic_values/busy_detachment.rs"]
mod busy_detachment;
#[path = "diagnostic_values/busy_digest_continuation.rs"]
mod busy_digest_continuation;
#[path = "diagnostic_values/busy_external_execution.rs"]
mod busy_external_execution;
#[path = "diagnostic_values/busy_key_admission.rs"]
mod busy_key_admission;
#[path = "diagnostic_values/busy_local_admission.rs"]
mod busy_local_admission;
#[path = "diagnostic_values/busy_memory_accounting.rs"]
mod busy_memory_accounting;
#[path = "diagnostic_values/busy_module_lifecycle.rs"]
mod busy_module_lifecycle;
#[path = "diagnostic_values/busy_native_execution.rs"]
mod busy_native_execution;
#[path = "diagnostic_values/busy_native_loading.rs"]
mod busy_native_loading;
#[path = "diagnostic_values/busy_native_messages.rs"]
mod busy_native_messages;
#[path = "diagnostic_values/busy_object_cleanup.rs"]
mod busy_object_cleanup;
#[path = "diagnostic_values/busy_object_copy.rs"]
mod busy_object_copy;
#[path = "diagnostic_values/busy_object_creation.rs"]
mod busy_object_creation;
#[path = "diagnostic_values/busy_object_mutation.rs"]
mod busy_object_mutation;
#[path = "diagnostic_values/busy_object_observation.rs"]
mod busy_object_observation;
#[path = "diagnostic_values/busy_object_publication.rs"]
mod busy_object_publication;
#[path = "diagnostic_values/busy_operation_ownership.rs"]
mod busy_operation_ownership;
#[path = "diagnostic_values/busy_operation_recovery.rs"]
mod busy_operation_recovery;
#[path = "diagnostic_values/busy_operation_state.rs"]
mod busy_operation_state;
#[path = "diagnostic_values/busy_reference_registry.rs"]
mod busy_reference_registry;
#[path = "diagnostic_values/busy_restoration.rs"]
mod busy_restoration;
#[path = "diagnostic_values/busy_session_accounting.rs"]
mod busy_session_accounting;
#[path = "diagnostic_values/busy_session_lifecycle.rs"]
mod busy_session_lifecycle;
#[path = "diagnostic_values/busy_signature_continuation.rs"]
mod busy_signature_continuation;
#[path = "diagnostic_values/busy_signature_messages.rs"]
mod busy_signature_messages;
#[path = "diagnostic_values/busy_token_administration.rs"]
mod busy_token_administration;
#[path = "diagnostic_values/rejection_aead_messages.rs"]
mod rejection_aead_messages;
#[path = "diagnostic_values/rejection_asynchronous_execution.rs"]
mod rejection_asynchronous_execution;
#[path = "diagnostic_values/rejection_attribute_preparation.rs"]
mod rejection_attribute_preparation;
#[path = "diagnostic_values/rejection_attribute_values.rs"]
mod rejection_attribute_values;
#[path = "diagnostic_values/rejection_authentication.rs"]
mod rejection_authentication;
#[path = "diagnostic_values/rejection_callbacks.rs"]
mod rejection_callbacks;
#[path = "diagnostic_values/rejection_cancellation.rs"]
mod rejection_cancellation;
#[path = "diagnostic_values/rejection_checkpoint_capture.rs"]
mod rejection_checkpoint_capture;
#[path = "diagnostic_values/rejection_checkpoint_format.rs"]
mod rejection_checkpoint_format;
#[path = "diagnostic_values/rejection_cipher_continuation.rs"]
mod rejection_cipher_continuation;
#[path = "diagnostic_values/rejection_classical_signatures.rs"]
mod rejection_classical_signatures;
#[path = "diagnostic_values/rejection_combined_operations.rs"]
mod rejection_combined_operations;
#[path = "diagnostic_values/rejection_derived_object_creation.rs"]
mod rejection_derived_object_creation;
#[path = "diagnostic_values/rejection_detachment.rs"]
mod rejection_detachment;
#[path = "diagnostic_values/rejection_diagnostics.rs"]
mod rejection_diagnostics;
#[path = "diagnostic_values/rejection_digest_continuation.rs"]
mod rejection_digest_continuation;
#[path = "diagnostic_values/rejection_external_execution.rs"]
mod rejection_external_execution;
#[path = "diagnostic_values/rejection_input_bounds.rs"]
mod rejection_input_bounds;
#[path = "diagnostic_values/rejection_key_admission.rs"]
mod rejection_key_admission;
#[path = "diagnostic_values/rejection_key_derivation.rs"]
mod rejection_key_derivation;
#[path = "diagnostic_values/rejection_key_encapsulation.rs"]
mod rejection_key_encapsulation;
#[path = "diagnostic_values/rejection_key_encoding.rs"]
mod rejection_key_encoding;
#[path = "diagnostic_values/rejection_key_transport.rs"]
mod rejection_key_transport;
#[path = "diagnostic_values/rejection_local_admission.rs"]
mod rejection_local_admission;
#[path = "diagnostic_values/rejection_mechanism_extensions.rs"]
mod rejection_mechanism_extensions;
#[path = "diagnostic_values/rejection_mechanisms.rs"]
mod rejection_mechanisms;
#[path = "diagnostic_values/rejection_memory_accounting.rs"]
mod rejection_memory_accounting;
#[path = "diagnostic_values/rejection_memory_allocation.rs"]
mod rejection_memory_allocation;
#[path = "diagnostic_values/rejection_message_record.rs"]
mod rejection_message_record;
#[path = "diagnostic_values/rejection_module_configuration.rs"]
mod rejection_module_configuration;
#[path = "diagnostic_values/rejection_module_lifecycle.rs"]
mod rejection_module_lifecycle;
#[path = "diagnostic_values/rejection_native_derivation.rs"]
mod rejection_native_derivation;
#[path = "diagnostic_values/rejection_native_digest.rs"]
mod rejection_native_digest;
#[path = "diagnostic_values/rejection_native_encapsulation.rs"]
mod rejection_native_encapsulation;
#[path = "diagnostic_values/rejection_native_execution.rs"]
mod rejection_native_execution;
#[path = "diagnostic_values/rejection_native_interfaces.rs"]
mod rejection_native_interfaces;
#[path = "diagnostic_values/rejection_native_loading.rs"]
mod rejection_native_loading;
#[path = "diagnostic_values/rejection_native_mac.rs"]
mod rejection_native_mac;
#[path = "diagnostic_values/rejection_native_messages.rs"]
mod rejection_native_messages;
#[path = "diagnostic_values/rejection_native_otp.rs"]
mod rejection_native_otp;
#[path = "diagnostic_values/rejection_native_protocols.rs"]
mod rejection_native_protocols;
#[path = "diagnostic_values/rejection_native_signature.rs"]
mod rejection_native_signature;
#[path = "diagnostic_values/rejection_native_transport.rs"]
mod rejection_native_transport;
#[path = "diagnostic_values/rejection_object_cleanup.rs"]
mod rejection_object_cleanup;
#[path = "diagnostic_values/rejection_object_content.rs"]
mod rejection_object_content;
#[path = "diagnostic_values/rejection_object_copy.rs"]
mod rejection_object_copy;
#[path = "diagnostic_values/rejection_object_creation.rs"]
mod rejection_object_creation;
#[path = "diagnostic_values/rejection_object_destination.rs"]
mod rejection_object_destination;
#[path = "diagnostic_values/rejection_object_mutation.rs"]
mod rejection_object_mutation;
#[path = "diagnostic_values/rejection_object_observation.rs"]
mod rejection_object_observation;
#[path = "diagnostic_values/rejection_object_publication.rs"]
mod rejection_object_publication;
#[path = "diagnostic_values/rejection_object_references.rs"]
mod rejection_object_references;
#[path = "diagnostic_values/rejection_object_search.rs"]
mod rejection_object_search;
#[path = "diagnostic_values/rejection_operation_keys.rs"]
mod rejection_operation_keys;
#[path = "diagnostic_values/rejection_operation_ownership.rs"]
mod rejection_operation_ownership;
#[path = "diagnostic_values/rejection_operation_record.rs"]
mod rejection_operation_record;
#[path = "diagnostic_values/rejection_operation_recovery.rs"]
mod rejection_operation_recovery;
#[path = "diagnostic_values/rejection_operation_state.rs"]
mod rejection_operation_state;
#[path = "diagnostic_values/rejection_persistence.rs"]
mod rejection_persistence;
#[path = "diagnostic_values/rejection_post_quantum_keys.rs"]
mod rejection_post_quantum_keys;
#[path = "diagnostic_values/rejection_public_verification.rs"]
mod rejection_public_verification;
#[path = "diagnostic_values/rejection_random_generation.rs"]
mod rejection_random_generation;
#[path = "diagnostic_values/rejection_recovery_record.rs"]
mod rejection_recovery_record;
#[path = "diagnostic_values/rejection_reference_registry.rs"]
mod rejection_reference_registry;
#[path = "diagnostic_values/rejection_restoration.rs"]
mod rejection_restoration;
#[path = "diagnostic_values/rejection_session_accounting.rs"]
mod rejection_session_accounting;
#[path = "diagnostic_values/rejection_session_lifecycle.rs"]
mod rejection_session_lifecycle;
#[path = "diagnostic_values/rejection_signature_continuation.rs"]
mod rejection_signature_continuation;
#[path = "diagnostic_values/rejection_signature_messages.rs"]
mod rejection_signature_messages;
#[path = "diagnostic_values/rejection_symmetric_parameters.rs"]
mod rejection_symmetric_parameters;
#[path = "diagnostic_values/rejection_token_administration.rs"]
mod rejection_token_administration;
#[path = "diagnostic_values/rejection_verification_engine.rs"]
mod rejection_verification_engine;
#[path = "diagnostic_values/unsupported_aead_messages.rs"]
mod unsupported_aead_messages;
#[path = "diagnostic_values/unsupported_cipher_continuation.rs"]
mod unsupported_cipher_continuation;
#[path = "diagnostic_values/unsupported_mechanism_extensions.rs"]
mod unsupported_mechanism_extensions;
#[path = "diagnostic_values/unsupported_mechanisms.rs"]
mod unsupported_mechanisms;
#[path = "diagnostic_values/unsupported_module_configuration.rs"]
mod unsupported_module_configuration;
#[path = "diagnostic_values/unsupported_module_lifecycle.rs"]
mod unsupported_module_lifecycle;
#[path = "diagnostic_values/unsupported_native_interfaces.rs"]
mod unsupported_native_interfaces;
#[path = "diagnostic_values/unsupported_native_loading.rs"]
mod unsupported_native_loading;
#[path = "diagnostic_values/unsupported_native_mac.rs"]
mod unsupported_native_mac;
#[path = "diagnostic_values/unsupported_native_messages.rs"]
mod unsupported_native_messages;
#[path = "diagnostic_values/unsupported_object_creation.rs"]
mod unsupported_object_creation;
#[path = "diagnostic_values/unsupported_post_quantum_keys.rs"]
mod unsupported_post_quantum_keys;
#[path = "diagnostic_values/unsupported_signature_continuation.rs"]
mod unsupported_signature_continuation;
