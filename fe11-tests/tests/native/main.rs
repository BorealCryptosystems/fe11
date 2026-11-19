// SPDX-License-Identifier: Apache-2.0
//! One isolated native case per process, with provisioning in a separate invocation.
#![deny(unsafe_op_in_unsafe_fn)]
mod absent_mechanism;
mod absent_mechanism_fixture;
mod admission_family;
mod admission_scope;
mod advanced_settings;
mod aead_input_guards;
mod aead_preinit;
mod aes_entry_guard;
mod agreement_input_guards;
mod algorithm_probe;
mod application_mutex;
mod arguments;
mod attribute_guard;
mod authenticated_transport_guard;
mod authentication_admission;
mod authentication_state;
mod authentication_state_action;
mod authentication_state_case;
mod batch_capacity;
mod batch_state;
mod binary_curve;
mod binary_generation;
mod borrowed_client;
mod builder_choices;
mod builder_observations;
mod builder_runtime_choices;
mod catalog_probe;
mod cipher_batch_transition;
mod cipher_owner;
mod cipher_transition;
mod cipher_transition_action;
mod cipher_transition_fixture;
mod cipher_usage;
mod cipher_vector;
mod classical_changed_signature;
mod classical_sign_fixture;
mod classical_sign_operation;
mod classical_sign_vector;
mod classical_usage;
mod concatenation_negative;
mod concatenation_values;
mod configuration;
mod context_login;
#[path = "../support/credentials.rs"]
mod credentials;
mod cross_runtime_guard;
mod derive_negative;
mod derived_value;
mod derived_value_case;
mod des_parity;
mod dh_fixture;
mod digest_cancel;
mod digest_capacity;
mod digest_capacity_action;
mod digest_capacity_fixture;
mod digest_family_views;
mod digest_fixture;
mod digest_key_identity;
mod digest_key_value;
mod digest_live_alias;
mod digest_owner;
mod digest_refused;
mod digest_stream;
mod digest_ticket_cipher;
mod digest_transition;
mod digest_vector;
mod direct_digest;
mod direct_generation;
mod direct_generation_fixture;
mod direct_material;
mod direct_material_fixture;
mod direct_material_operation;
mod discovery_contract;
mod discovery_probe;
mod domain_identity;
mod drain_ticket_identity;
mod dsa_public;
mod dsa_vector;
mod dual_cbc;
mod ecdh_fixture;
mod ecdh_invalid;
mod ecdsa_encoding;
mod ecdsa_vector;
mod edwards_fixture;
mod edwards_negative;
mod edwards_vector;
mod encrypt_data_fixture;
mod engine_choices;
mod extension_cases;
mod extension_rsa_aes;
mod foreign_callback;
mod foreign_event_guard;
mod foreign_info;
mod foreign_info_image;
mod foreign_session;
mod gcm_fixture;
mod gcm_operation;
mod gcm_parameters;
mod gcm_transition;
mod gcm_transition_action;
mod gcm_transition_fixture;
mod gcm_usage;
mod gcm_vector;
mod gcm_withholding;
mod generation_family_observation;
mod generation_family_spec;
mod generation_fixture;
mod generation_negative;
mod generation_observation;
mod generation_selectors;
mod generation_transition;
mod generation_transition_action;
mod generation_transition_fixture;
mod generation_transition_spec;
mod generation_vector;
mod import_encoding;
mod initialization_contract;
mod input_guard;
mod interface_contract;
mod interface_slots;
mod kem_fixture;
mod kem_import;
mod kem_lifecycle;
mod kem_lifecycle_fixture;
mod kem_vector;
mod key_wrap_fixture;
mod key_wrap_operation;
mod key_wrap_vector;
mod legacy_contract;
mod mac_equivalence;
mod mac_owner;
mod mac_vector;
mod mechanism_request_guard;
mod metadata_access;
mod module_accessors;
mod module_boundaries;
mod module_controls;
mod module_lifecycle;
mod native_support;
mod oaep_destination_guard;
mod oaep_encrypt;
mod oaep_fixture;
mod oaep_reference_guard;
mod oaep_usage;
mod oaep_vector;
mod object_contract;
mod object_fixture;
mod object_lifetime;
mod object_owner;
mod object_transition;
mod object_transition_action;
mod object_transition_fixture;
mod outcome;
mod pin_admission;
mod pin_contract;
mod pqc_absent;
mod pqc_fixture;
mod pqc_import_guard;
mod pqc_operation;
mod pqc_parameters;
mod pqc_signing_guard;
mod pqc_vector;
mod pqc_verification_guards;
mod probe_agreement;
mod probe_digests;
mod probe_kem;
mod probe_parameters;
mod probe_session;
mod probe_signatures;
mod probe_symmetric;
mod probe_template;
mod provision;
mod public_guard;
mod random_contract;
mod record_parser;
mod recovery_record;
#[path = "../support/report.rs"]
mod report;
mod retained_crypto;
mod retained_digest;
mod rsa_changed_signature;
mod rsa_domain;
mod rsa_known;
mod rsa_known_fixture;
mod rsa_known_operation;
mod rsa_negative;
mod rsa_parameters;
mod rsa_private;
mod rsa_unwrap_negative;
mod rsa_usage;
mod rsa_vector;
mod rsa_wrap_negative;
mod runtime_successor;
mod search_action;
mod search_fixture;
mod search_population;
mod search_vector;
mod selection_additional;
mod selection_asymmetric;
mod selection_exact;
mod selection_negative;
mod selection_rsa;
mod selection_symmetric;
mod session_contract;
mod generated_aes;
mod session_conversion;
mod signature_extension_route;
mod signature_owner;
mod signature_transition;
mod signature_transition_action;
mod signature_transition_case;
mod signature_transition_ecdsa;
mod signature_transition_edwards;
mod signature_transition_fixture;
mod signature_transition_pqc;
mod signing_guards;
mod single_key_case;
mod single_part_guard;
mod symmetric_guards;
mod ticket_family;
mod ticket_family_dispatch;
mod ticket_identity;
mod ticket_identity_action;
mod ticket_identity_dispatch;
mod ticket_state_guard;
mod token_admin_open;
mod token_drain_session;
mod token_label_contract;
mod token_pin_boundary;
mod transport_negative;
mod transport_negative_fixture;
mod typed_selection;
mod unsupported_lifecycle;
mod verification_guards;

use report::{Observation, Phase, PhaseResult, Producer, Report};
use std::io;

fn execute() -> io::Result<bool> {
    let args = match arguments::parse() {
        Ok(args) => args,
        Err(category) => {
            eprintln!("worker_input:{category}");
            return Ok(false);
        }
    };
    let mut report = Report::new(
        io::stdout().lock(),
        &args.case,
        &args.source_digest,
        &args.recipe_digest,
        &args.module_digest,
    )?;
    let mut pins = match credentials::read(&mut io::stdin().lock(), credentials::MAXIMUM_PIN_BYTES)
    {
        Ok(pins) => pins,
        Err(_) => {
            report.observation(
                Phase::Setup,
                "credential_frames",
                Producer::Supervisor,
                Observation::Boolean(false),
            )?;
            return report.finish(
                PhaseResult::Failed,
                PhaseResult::NotExecuted,
                PhaseResult::NotExecuted,
            );
        }
    };
    if args.mode == "provision" {
        return provision::execute(&args.config, &mut pins, report);
    }
    if args.mode == "algorithm-probe" {
        let result = algorithm_probe::run(&args.config, &mut pins, &args.case);
        if let Err(error) = &result.body {
            outcome::record(&mut report, Phase::Setup, error)?;
        }
        for error in &result.cleanup {
            outcome::record(&mut report, Phase::Cleanup, error)?;
        }
        return report.finish_preparation(
            if result.body.is_ok() {
                PhaseResult::Passed
            } else {
                PhaseResult::Failed
            },
            if result.cleanup.is_empty() {
                PhaseResult::Passed
            } else {
                PhaseResult::Failed
            },
        );
    }
    if args.mode == "catalog-probe" {
        let result = catalog_probe::run(&args.config, &args.vector, &mut report)?;
        if let Err(error) = &result.body {
            outcome::record(&mut report, Phase::Setup, error)?;
        }
        for error in &result.cleanup {
            outcome::record(&mut report, Phase::Cleanup, error)?;
        }
        return report.finish_preparation(
            if result.body.is_ok() {
                PhaseResult::Passed
            } else {
                PhaseResult::Failed
            },
            if result.cleanup.is_empty() {
                PhaseResult::Passed
            } else {
                PhaseResult::Failed
            },
        );
    }
    if args.mode == "discovery-probe" {
        let result = discovery_probe::run(&args.config, &mut report)?;
        if let Err(error) = &result {
            outcome::record(&mut report, Phase::Setup, error)?;
        }
        return report.finish_preparation(
            if result.is_ok() {
                PhaseResult::Passed
            } else {
                PhaseResult::Failed
            },
            PhaseResult::Passed,
        );
    }
    if args.mode == "observer-control" {
        let result = direct_digest::run(&args.config, &mut report)?;
        if let Err(error) = &result.body {
            outcome::record(&mut report, Phase::Body, error)?;
        }
        for error in &result.cleanup {
            outcome::record(&mut report, Phase::Cleanup, error)?;
        }
        // An observer control is a prerequisite, not a Fe11 test verdict.
        return report.finish_preparation(
            if result.body.is_ok() {
                PhaseResult::Passed
            } else {
                PhaseResult::Failed
            },
            if result.cleanup.is_empty() {
                PhaseResult::Passed
            } else {
                PhaseResult::Failed
            },
        );
    }
    if args.mode == "discovery-contract" {
        return discovery_contract::execute(&args.config, &args.vector, report);
    }
    if args.mode == "initialization-contract" {
        return initialization_contract::execute(&args.config, &args.vector, report);
    }
    if args.mode == "session-contract" {
        return session_contract::execute(&args.config, &args.vector, &pins, report);
    }
    if args.mode == "pin-contract" {
        return pin_contract::execute(&args.config, &args.vector, &pins, report);
    }
    if args.mode == "token-label-contract" {
        return token_label_contract::execute(&args.config, &args.vector, &pins, report);
    }
    if args.mode == "interface-contract" {
        return interface_contract::execute(&args.config, &args.vector, report);
    }
    if args.mode == "runtime-successor" {
        return runtime_successor::execute(&args.config, &args.vector, &pins, report);
    }
    if args.mode == "builder-runtime-choices" {
        return builder_runtime_choices::execute(&args.config, &args.vector, report);
    }
    if args.mode == "cross-runtime-guard" {
        return cross_runtime_guard::execute(&args.config, &args.vector, report);
    }
    if args.mode == "borrowed-client" {
        return borrowed_client::execute(&args.config, report);
    }
    if args.mode == "engine-choices" {
        return engine_choices::execute(&args.config, &args.vector, report);
    }
    if args.mode == "builder-choices" {
        return builder_choices::execute(&args.config, &args.vector, report);
    }
    if args.mode == "builder-observation" {
        return builder_observations::execute(&args.config, &args.vector, report);
    }
    if args.mode == "module-boundary" {
        return module_boundaries::execute(&args.config, &args.vector, report);
    }
    if args.mode == "foreign-slot-guard" {
        return foreign_session::execute_other_token(&args.config, &pins, report);
    }
    if args.mode == "foreign-session" {
        return foreign_session::execute(&args, &pins, report);
    }
    if args.mode == "foreign-event-guard" {
        return foreign_event_guard::execute(&args.config, report);
    }
    if args.mode == "foreign-callback" {
        return foreign_callback::execute(&args.config, &args.vector, report);
    }
    if args.mode == "foreign-info" {
        return foreign_info::execute(&args.config, &args.vector, report);
    }
    if args.mode == "shared-module" {
        return module_controls::execute_shared(&args.config, &args.vector, report);
    }
    if args.mode == "module-accessor" {
        return module_accessors::execute(&args.config, &args.vector, report);
    }
    let mut budgets = configuration::Budgets::ordinary();
    if args.mode == "import-encoding" {
        budgets.input_bytes = 32768;
    }
    if args.mode == "input-guard" {
        budgets.parts = 1;
        budgets.input_bytes = 3;
    }
    if args.mode == "authenticated-transport-guard" {
        return authenticated_transport_guard::open(&args.config, &args.vector, &budgets, report);
    }
    let module = match args.config.open(&budgets) {
        Ok(module) => module,
        Err(error) => {
            outcome::record(&mut report, Phase::Setup, &error.into())?;
            return report.finish(
                PhaseResult::Failed,
                PhaseResult::NotExecuted,
                PhaseResult::NotExecuted,
            );
        }
    };
    report.observation(
        Phase::Setup,
        "module_opened",
        Producer::Fe11Local,
        Observation::Boolean(true),
    )?;
    if args.mode == "ecdsa-encoding" {
        return ecdsa_encoding::execute(module, &args.config, &args.vector, report);
    }
    if args.mode == "ecdsa-vector" {
        return ecdsa_vector::execute(module, &args.config, &args.vector, report);
    }
    if args.mode == "dsa-vector" {
        return dsa_vector::execute(module, &args.config, &args.vector, report);
    }
    if matches!(
        args.mode.as_str(),
        "key-wrap-vector" | "key-wrap-controlled"
    ) {
        return key_wrap_vector::execute(
            module,
            &args.config,
            &args.vector,
            args.mode == "key-wrap-controlled",
            report,
        );
    }
    if args.mode == "oaep-encrypt" {
        return oaep_encrypt::execute(module, &args.config, &args.vector, report);
    }
    if args.mode == "oaep-vector" {
        return oaep_vector::execute(module, &args.config, &args.vector, report);
    }
    if matches!(
        args.mode.as_str(),
        "ticket-family" | "ticket-identity" | "ticket-boundary"
    ) {
        return ticket_family::execute(module, &args.config, &args.vector, report);
    }
    if args.mode == "rsa-vector" {
        return rsa_vector::execute(module, &args.config, &args.vector, report);
    }
    if args.mode == "digest-transition" {
        return digest_transition::execute(module, &args.config, &args.vector, &pins, report);
    }
    if args.mode == "edwards-negative" {
        return edwards_negative::execute(module, &args.config, &args.vector, &pins, report);
    }
    if args.mode == "generation-vector" {
        return generation_vector::execute(module, &args.config, &args.vector, &pins, report);
    }
    if matches!(args.mode.as_str(), "pqc-vector" | "pqc-random") {
        return single_key_case::execute::<pqc_fixture::Vector, _>(
            module,
            &args.config,
            &args.vector,
            report,
        );
    }
    if matches!(
        args.mode.as_str(),
        "dsa-import-identity" | "dh-import-identity" | "dh-public-import"
    ) {
        return domain_identity::execute(module, &args, report);
    }
    if args.mode == "classical-sign" {
        return single_key_case::execute::<classical_sign_fixture::Vector, _>(
            module,
            &args.config,
            &args.vector,
            report,
        );
    }
    if args.mode == "dh-usage-denied" || args.mode == "dh-template-denied" {
        return derive_negative::execute::<dh_fixture::Vector, _>(
            module,
            &args.config,
            &args.vector,
            args.mode == "dh-usage-denied",
            report,
        );
    }
    if args.mode == "ecdh-usage-denied" || args.mode == "ecdh-template-denied" {
        return derive_negative::execute::<ecdh_fixture::Vector, _>(
            module,
            &args.config,
            &args.vector,
            args.mode == "ecdh-usage-denied",
            report,
        );
    }
    if args.mode == "derive-usage-negative" || args.mode == "derive-template-negative" {
        return derive_negative::execute::<encrypt_data_fixture::Vector, _>(
            module,
            &args.config,
            &args.vector,
            args.mode == "derive-usage-negative",
            report,
        );
    }
    if matches!(
        args.mode.as_str(),
        "encrypt-data-vector" | "dh-vector" | "ecdh-vector" | "concatenation-values"
    ) {
        return derived_value_case::dispatch(module, &args, report);
    }
    if args.mode == "typed-selection" {
        return typed_selection::execute(module, &args.config, &args.vector, &pins, report);
    }
    if args.mode == "batch-state" {
        return batch_state::execute(module, &args.config, &args.vector, report);
    }
    if args.mode == "pqc-import-guard" {
        return pqc_import_guard::execute(module, &args.config, &args.vector, report);
    }

    if args.mode == "ecdh-invalid" {
        return ecdh_invalid::execute(module, &args.config, &args.vector, report);
    }

    if args.mode == "gcm-usage" {
        return single_key_case::execute::<gcm_usage::Usage, _>(
            module,
            &args.config,
            &args.vector,
            report,
        );
    }
    if args.mode == "gcm-parameters" {
        return single_key_case::execute::<gcm_parameters::Case, _>(
            module,
            &args.config,
            &args.vector,
            report,
        );
    }
    if args.mode == "gcm-vector" {
        return single_key_case::execute::<gcm_fixture::Vector, _>(
            module,
            &args.config,
            &args.vector,
            report,
        );
    }
    if args.mode == "rsa-changed-signature" {
        return single_key_case::execute::<rsa_changed_signature::Changed, _>(
            module,
            &args.config,
            &args.vector,
            report,
        );
    }
    if args.mode == "ticket-owner-identity" {
        return ticket_identity::execute(module, &args.config, &args.vector, &pins, report);
    }
    if args.mode == "des-parity" {
        return des_parity::execute(module, &args.config, &args.vector, report);
    }
    if args.mode == "cipher-usage" {
        return cipher_usage::execute(module, &args.config, &args.vector, report);
    }
    if args.mode == "generation-negative" {
        return generation_negative::execute(module, &args.config, &args.vector, &pins, report);
    }
    if args.mode == "recovery-record" {
        return recovery_record::execute(module, &args.config, &args.vector, &pins, report);
    }
    if args.mode == "record-parser" {
        return record_parser::execute(module, &args.vector, report);
    }
    if args.mode == "public-guard" {
        return public_guard::execute(module, &args.config, &args.vector, report);
    }
    if args.mode == "object-transition" {
        return object_transition::execute(module, &args.config, &args.vector, &pins, report);
    }
    if args.mode == "ticket-state-guard" {
        return ticket_state_guard::execute(module, &args.config, &args.vector, &pins, report);
    }
    if args.mode == "direct-material" {
        return direct_material::execute(module, &args.config, &args.vector, &pins, report);
    }
    if args.mode == "direct-generation" {
        return direct_generation::execute(module, &args.config, &args.vector, &pins, report);
    }
    if args.mode == "symmetric-guards" {
        return symmetric_guards::execute(module, &args.config, &args.vector, report);
    }
    if args.mode == "unsupported-lifecycle" {
        return unsupported_lifecycle::execute(module, &args.config, &args.vector, report);
    }
    if args.mode == "pqc-signing-guard" {
        return pqc_signing_guard::execute(module, &args.config, &pins, report);
    }
    if args.mode == "aead-input-guards" {
        return aead_input_guards::execute(module, &args.config, &args.vector, report);
    }
    if args.mode == "digest-key-identity" {
        return digest_key_identity::execute(module, &args.config, &args.vector, report);
    }
    if args.mode == "mechanism-request-guard" {
        return mechanism_request_guard::execute(module, &args.config, &args.vector, report);
    }
    if args.mode == "agreement-input-guards" {
        return agreement_input_guards::execute(module, &args.config, &args.vector, &pins, report);
    }
    if args.mode == "drain-ticket-identity" {
        return drain_ticket_identity::execute(module, &args.config, &args.vector, report);
    }
    if args.mode == "token-drain-session" {
        return token_drain_session::execute(module, &args.config, &args.vector, &pins, report);
    }
    if args.mode == "pqc-verification-guards" {
        return pqc_verification_guards::execute(module, &args.config, &args.vector, report);
    }
    if args.mode == "generated-aes" {
        return generated_aes::execute(module, &args.config, &args.vector, &pins, report);
    }
    if args.mode == "session-conversion" {
        return session_conversion::execute(module, &args.config, &args.vector, &pins, report);
    }
    if args.mode == "signing-guards" {
        return signing_guards::execute(module, &args.config, &args.vector, &pins, report);
    }
    if args.mode == "verification-guards" {
        return verification_guards::execute(module, &args.config, &args.vector, report);
    }
    if args.mode == "module-controls" || args.mode == "active-pair" {
        return module_controls::execute(module, &args.config, &args.vector, &args.mode, report);
    }
    if args.mode == "advanced-setting" {
        return advanced_settings::execute(module, &args.config, &args.vector, report);
    }
    if args.mode == "retained-cipher" || args.mode == "retained-signature" {
        return retained_crypto::execute(
            module,
            &args.config,
            &args.vector,
            args.mode == "retained-signature",
            &pins,
            report,
        );
    }
    if args.mode == "oaep-encrypt-denied" {
        return single_key_case::execute::<oaep_usage::Usage<true>, _>(
            module,
            &args.config,
            &args.vector,
            report,
        );
    }
    if args.mode == "oaep-decrypt-denied" {
        return single_key_case::execute::<oaep_usage::Usage<false>, _>(
            module,
            &args.config,
            &args.vector,
            report,
        );
    }
    if args.mode == "retained-digest" {
        return retained_digest::execute(module, &args.config, &args.vector, report);
    }
    if args.mode == "digest-live-alias" {
        return digest_live_alias::execute(module, &args.config, &args.vector, report);
    }
    if args.mode == "oaep-destination-guard" {
        return oaep_destination_guard::execute(module, &args.config, &pins, report);
    }
    if args.mode == "oaep-reference-guard" {
        return oaep_reference_guard::execute(module, &args.config, &args.vector, &pins, report);
    }
    if args.mode == "admission-family" {
        return admission_family::execute(module, &args.config, &args.vector, report);
    }
    if args.mode == "module-lifecycle" {
        return module_lifecycle::execute(module, &args.config, &args.vector, report);
    }
    if args.mode == "legacy-contract" {
        return legacy_contract::execute(module, &args.config, &args.vector, report);
    }
    if args.mode == "admission-scope" {
        return admission_scope::execute(module, &args.config, &args.vector, report);
    }
    if args.mode == "input-guard" {
        return input_guard::execute(module, &args.config, &args.vector, &pins, report);
    }
    if args.mode == "digest-family-view" {
        return digest_family_views::execute(module, &args.config, &args.vector, report);
    }
    if args.mode == "digest-ticket-cipher" {
        return digest_ticket_cipher::execute(module, &args.config, &args.vector, &pins, report);
    }
    if args.mode == "generation-transition" {
        return generation_transition::execute(module, &args.config, &args.vector, &pins, report);
    }
    if args.mode == "binary-generation" {
        return binary_generation::execute(module, &args.config, &args.vector, &pins, report);
    }
    if args.mode == "aes-entry-guard" {
        return aes_entry_guard::execute(module, &args.config, &args.vector, report);
    }
    if args.mode == "rsa-wrap-negative" {
        return rsa_wrap_negative::execute(module, &args.config, &args.vector, &pins, report);
    }
    if args.mode == "rsa-unwrap-negative" {
        return rsa_unwrap_negative::execute(module, &args.config, &args.vector, &pins, report);
    }
    if args.mode == "transport-negative" {
        return transport_negative::execute(module, &args.config, &args.vector, report);
    }
    if args.mode == "concatenation-negative" {
        return concatenation_negative::execute(module, &args.config, &args.vector, report);
    }
    if args.mode == "classical-changed" {
        return single_key_case::execute::<classical_changed_signature::Changed, _>(
            module,
            &args.config,
            &args.vector,
            report,
        );
    }
    if args.mode == "classical-sign-denied" {
        return single_key_case::execute::<classical_usage::Usage<true>, _>(
            module,
            &args.config,
            &args.vector,
            report,
        );
    }
    if args.mode == "classical-verify-denied" {
        return single_key_case::execute::<classical_usage::Usage<false>, _>(
            module,
            &args.config,
            &args.vector,
            report,
        );
    }
    if extension_cases::accepts(&args.mode) {
        return extension_cases::execute(module, &args, &pins, report);
    }
    if args.mode == "single-part-guard-0" {
        return single_key_case::execute::<single_part_guard::Guard<0>, _>(
            module,
            &args.config,
            &args.vector,
            report,
        );
    }
    if args.mode == "single-part-guard-1" {
        return single_key_case::execute::<single_part_guard::Guard<1>, _>(
            module,
            &args.config,
            &args.vector,
            report,
        );
    }
    if args.mode == "single-part-guard-2" {
        return single_key_case::execute::<single_part_guard::Guard<2>, _>(
            module,
            &args.config,
            &args.vector,
            report,
        );
    }
    if args.mode == "single-part-guard-3" {
        return single_key_case::execute::<single_part_guard::Guard<3>, _>(
            module,
            &args.config,
            &args.vector,
            report,
        );
    }
    if args.mode == "single-part-guard-4" {
        return single_key_case::execute::<single_part_guard::Guard<4>, _>(
            module,
            &args.config,
            &args.vector,
            report,
        );
    }
    if args.mode == "single-part-guard-5" {
        return single_key_case::execute::<single_part_guard::Guard<5>, _>(
            module,
            &args.config,
            &args.vector,
            report,
        );
    }
    if args.mode == "attribute-guard" {
        return single_key_case::execute::<attribute_guard::Nested, _>(
            module,
            &args.config,
            &args.vector,
            report,
        );
    }
    if args.mode == "rsa-negative" {
        return single_key_case::execute::<rsa_negative::Negative, _>(
            module,
            &args.config,
            &args.vector,
            report,
        );
    }
    if args.mode == "rsa-usage" {
        return single_key_case::execute::<rsa_usage::Usage, _>(
            module,
            &args.config,
            &args.vector,
            report,
        );
    }
    if args.mode == "gcm-withholding" {
        return single_key_case::execute::<gcm_withholding::Vector, _>(
            module,
            &args.config,
            &args.vector,
            report,
        );
    }
    if args.mode == "edwards-vector" {
        return single_key_case::execute::<edwards_fixture::Vector, _>(
            module,
            &args.config,
            &args.vector,
            report,
        );
    }
    if args.mode == "rsa-known" {
        return single_key_case::execute::<rsa_known_fixture::Vector, _>(
            module,
            &args.config,
            &args.vector,
            report,
        );
    }
    if args.mode == "rsa-domain" {
        return rsa_domain::execute(module, &args.config, &args.vector, report);
    }
    if args.mode == "pin-admission" {
        return pin_admission::execute(module, &args.config, &args.vector, &pins, report);
    }
    if args.mode == "search-transition" {
        return search_vector::execute(module, &args.config, &args.vector, &pins, report);
    }
    if args.mode == "search-population" {
        return search_population::execute(module, &args.config, &args.vector, &pins, report);
    }
    if args.mode == "digest-refused" {
        return digest_refused::execute(module, &args.config, &args.vector, &pins, report);
    }
    if args.mode == "digest-capacity" {
        return digest_capacity::execute(module, &args.config, &args.vector, &pins, report);
    }
    if args.mode == "cipher-batch-transition" {
        return cipher_batch_transition::execute(module, &args.config, &args.vector, report);
    }
    if args.mode == "import-encoding" {
        return import_encoding::execute(module, &args.config, &args.vector, &pins, report);
    }
    if args.mode == "aead-preinit" {
        return aead_preinit::execute(module, &args.config, &args.vector, &pins, report);
    }
    if args.mode == "absent-mechanism" {
        return absent_mechanism::execute(module, &args.config, &args.vector, &pins, report);
    }
    if args.mode == "kem-lifecycle" {
        return kem_lifecycle::execute(module, &args.config, &args.vector, &pins, report);
    }
    if args.mode == "kem-import" {
        return kem_import::execute(module, &args.config, &args.vector, &pins, report);
    }
    if args.mode == "kem-vector" {
        return kem_vector::execute(module, &args.config, &args.vector, report);
    }
    if matches!(
        args.mode.as_str(),
        "mac-transition"
            | "rsa-transition"
            | "pqc-transition"
            | "edwards-transition"
            | "ecdsa-transition"
            | "single-signature-transition"
    ) {
        return signature_transition::execute(module, &args.config, &args.vector, &pins, report);
    }
    if args.mode == "dual-cbc" {
        return dual_cbc::execute(module, &args.config, &args.vector, &pins, report);
    }
    if args.mode == "gcm-transition" {
        return gcm_transition::execute(module, &args.config, &args.vector, &pins, report);
    }
    if args.mode == "cipher-transition" {
        return cipher_transition::execute(module, &args.config, &args.vector, &pins, report);
    }
    if matches!(
        args.mode.as_str(),
        "context-login"
            | "context-wrong-pin"
            | "context-local-guards"
            | "context-missing-login"
            | "context-pss-login"
    ) {
        return context_login::execute(
            module,
            &args.config,
            &args.vector,
            &pins,
            &args.mode,
            report,
        );
    }
    if args.mode == "object-contract" {
        return object_contract::execute(module, &args.config, &args.vector, &pins, report);
    }
    if args.mode == "random-contract" {
        return random_contract::execute(module, &args.config, &args.vector, &pins, report);
    }
    if args.mode == "authentication-state" {
        return authentication_state::execute(module, &args.config, &args.vector, &pins, report);
    }
    if args.mode == "authentication-admission" {
        return authentication_admission::execute(
            module,
            &args.config,
            &args.vector,
            &pins,
            report,
        );
    }
    if args.mode == "cipher-vector" {
        return cipher_vector::run(module, &args.config, &args.vector, &pins, report);
    }
    if args.mode == "mac-equivalence" {
        return mac_equivalence::execute(module, &args.config, &args.vector, report);
    }
    if args.mode == "mac-vector" {
        return mac_vector::execute(module, &args.config, &args.vector, report);
    }
    if args.mode == "digest-cancel" {
        return digest_cancel::execute(module, &args.config, &args.vector, &pins, report);
    }
    let result = if args.mode == "digest-stream" {
        digest_stream::run(&module, &args.config, &args.vector, &mut report)?
    } else {
        digest_vector::run(&module, &args.config, &args.vector)
    };
    digest_vector::finish(module, result, report)
}

fn main() {
    // Panic payloads can contain third-party formatting. A missing terminal
    // record is an incomplete run; the supervisor must not turn it into PASS.
    std::panic::set_hook(Box::new(|_| eprintln!("worker_panic")));
    match execute() {
        Ok(true) => (),
        Ok(false) => std::process::exit(1),
        Err(_) => {
            eprintln!("worker_report_error");
            std::process::exit(2);
        }
    }
}
