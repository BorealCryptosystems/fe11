// SPDX-License-Identifier: Apache-2.0
use fe11::*;

pub(super) fn attribute_read_plan(alternate: bool) -> AttributeReadPlan {
    AttributeReadPlan {
        clarification: if alternate {
            AttributeClarification::ClarifyIndeterminate
        } else {
            AttributeClarification::BatchOnly
        },
        maximum_bytes: if alternate { usize::MAX } else { 4 },
    }
}

pub(super) fn ccm_nonce(alternate: bool) -> CcmNonce {
    CcmNonce {
        bytes: if alternate {
            std::sync::Arc::from(&[0u8, 1, 254, 255][..])
        } else {
            std::sync::Arc::from(&[][..])
        },
        fixed_bits: if alternate { u64::MAX } else { 4 },
        generator: if alternate { u64::MAX } else { 5 },
    }
}

pub(super) fn current_key_protection(alternate: bool) -> CurrentKeyProtection {
    CurrentKeyProtection {
        extractable: if alternate { false } else { true },
        sensitive: if alternate { false } else { true },
    }
}

pub(super) fn destination_plan(alternate: bool) -> DestinationPlan {
    DestinationPlan {
        search: if alternate {
            DestinationSearchPlan::Observe {
                resources: search_plan(false),
                source: DestinationSource::Exclude,
                template: ReferenceTemplate::Fields(std::sync::Arc::new(
                    std::collections::BTreeSet::new(),
                )),
            }
        } else {
            DestinationSearchPlan::NotRequested
        },
        user: if alternate {
            DestinationUserObservation::Read
        } else {
            DestinationUserObservation::NotRequested
        },
    }
}

pub(super) fn history_observation_plan(alternate: bool) -> HistoryObservationPlan {
    HistoryObservationPlan {
        always_sensitive: if alternate { false } else { true },
        extractable: if alternate { false } else { true },
        generation: if alternate { false } else { true },
        local: if alternate { false } else { true },
        maximum_bytes: if alternate { usize::MAX } else { 7 },
        never_extractable: if alternate { false } else { true },
        sensitive: if alternate { false } else { true },
    }
}

pub(super) fn key_usage_request(alternate: bool) -> KeyUsageRequest {
    KeyUsageRequest {
        always_authenticate: if alternate { Some(true) } else { None },
        decapsulate: if alternate { Some(true) } else { None },
        decrypt: if alternate { Some(true) } else { None },
        derive: if alternate { Some(true) } else { None },
        encapsulate: if alternate { Some(true) } else { None },
        encrypt: if alternate { Some(true) } else { None },
        sign: if alternate { Some(true) } else { None },
        sign_recover: if alternate { Some(true) } else { None },
        trusted: if alternate { Some(true) } else { None },
        unwrap: if alternate { Some(true) } else { None },
        verify: if alternate { Some(true) } else { None },
        verify_recover: if alternate { Some(true) } else { None },
        wrap: if alternate { Some(true) } else { None },
        wrap_with_trusted: if alternate { Some(true) } else { None },
    }
}

pub(super) fn object_admission(alternate: bool) -> ObjectAdmission {
    ObjectAdmission {
        destination: if alternate {
            destination_plan(true)
        } else {
            destination_plan(false)
        },
        metadata: if alternate {
            attribute_read_plan(true)
        } else {
            attribute_read_plan(false)
        },
        observation: if alternate {
            object_observation_plan(true)
        } else {
            object_observation_plan(false)
        },
        public_attributes: if alternate {
            std::sync::Arc::new(vec![Attribute::Label, Attribute::Id])
        } else {
            std::sync::Arc::new(vec![])
        },
        search: if alternate {
            search_plan(true)
        } else {
            search_plan(false)
        },
        selection: if alternate {
            object_search_selection(true)
        } else {
            object_search_selection(false)
        },
    }
}

pub(super) fn object_observation_plan(alternate: bool) -> ObjectObservationPlan {
    ObjectObservationPlan {
        always_authenticate: if alternate { false } else { true },
        always_sensitive: if alternate { false } else { true },
        copyable: if alternate { false } else { true },
        decapsulate: if alternate { false } else { true },
        decrypt: if alternate { false } else { true },
        derive: if alternate { false } else { true },
        destroyable: if alternate { false } else { true },
        encapsulate: if alternate { false } else { true },
        encrypt: if alternate { false } else { true },
        extractable: if alternate { false } else { true },
        local: if alternate { false } else { true },
        maximum_bytes: if alternate { usize::MAX } else { 14 },
        modifiable: if alternate { false } else { true },
        never_extractable: if alternate { false } else { true },
        private: if alternate { false } else { true },
        sensitive: if alternate { false } else { true },
        sign: if alternate { false } else { true },
        sign_recover: if alternate { false } else { true },
        token: if alternate { false } else { true },
        trusted: if alternate { false } else { true },
        unwrap: if alternate { false } else { true },
        verify: if alternate { false } else { true },
        verify_recover: if alternate { false } else { true },
        wrap: if alternate { false } else { true },
        wrap_with_trusted: if alternate { false } else { true },
    }
}

pub(super) fn object_search_selection(alternate: bool) -> ObjectSearchSelection {
    ObjectSearchSelection {
        index: if alternate { usize::MAX } else { 3 },
    }
}

pub(super) fn search_plan(alternate: bool) -> SearchPlan {
    SearchPlan {
        batch_size: if alternate {
            std::num::NonZeroUsize::new(usize::MAX).unwrap()
        } else {
            std::num::NonZeroUsize::new(1).unwrap()
        },
        maximum_objects: if alternate { Some(usize::MAX) } else { None },
    }
}

pub(super) fn session_limit(alternate: bool) -> SessionLimit {
    SessionLimit {
        read_write: if alternate { usize::MAX } else { 3 },
        total: if alternate { usize::MAX } else { 4 },
    }
}

pub(super) fn session_usage(alternate: bool) -> SessionUsage {
    SessionUsage {
        closing: if alternate { usize::MAX } else { 3 },
        deferred_close: if alternate { usize::MAX } else { 4 },
        open: if alternate { usize::MAX } else { 5 },
        opening: if alternate { usize::MAX } else { 6 },
        quarantined: if alternate { usize::MAX } else { 7 },
        read_write: if alternate { usize::MAX } else { 8 },
        recovering: if alternate { usize::MAX } else { 9 },
        reserved: if alternate { usize::MAX } else { 10 },
        retained_returned: if alternate { usize::MAX } else { 11 },
        total: if alternate { usize::MAX } else { 12 },
    }
}

pub(super) fn token_identity(alternate: bool) -> TokenIdentity {
    TokenIdentity {
        manufacturer: if alternate {
            std::array::from_fn(|i| i as u8 ^ 35)
        } else {
            [2; 32]
        },
        model: if alternate {
            std::array::from_fn(|i| i as u8 ^ 36)
        } else {
            [3; 16]
        },
        serial: if alternate {
            std::array::from_fn(|i| i as u8 ^ 37)
        } else {
            [4; 16]
        },
        slot: if alternate { u64::MAX } else { 6 },
    }
}

pub(super) fn attribute_batch_call(alternate: bool) -> AttributeBatchCall {
    AttributeBatchCall {
        attribute_count: if alternate { usize::MAX } else { 3 },
        code: if alternate { u64::MAX } else { 4 },
    }
}

pub(super) fn extension_output_region(alternate: bool) -> ExtensionOutputRegion {
    ExtensionOutputRegion {
        block: if alternate { usize::MAX } else { 3 },
        capacity: if alternate { usize::MAX } else { 4 },
        length: if alternate {
            ExtensionOutputLength::NativeUnsigned {
                block: 6,
                offset: 7,
            }
        } else {
            ExtensionOutputLength::Fixed
        },
        offset: if alternate { usize::MAX } else { 6 },
    }
}

pub(super) fn extension_pointer(alternate: bool) -> ExtensionPointer {
    ExtensionPointer {
        block: if alternate { usize::MAX } else { 3 },
        offset: if alternate { usize::MAX } else { 4 },
        target: if alternate {
            ExtensionPointerTarget::Null
        } else {
            ExtensionPointerTarget::Block {
                block: 6,
                offset: 7,
            }
        },
    }
}

pub(super) fn historical_pss_parameters(alternate: bool) -> HistoricalPssParameters {
    HistoricalPssParameters {
        hash: if alternate {
            HistoricalHash::Sha1
        } else {
            HistoricalHash::Md5
        },
        mgf_hash: if alternate {
            HistoricalHash::Sha1
        } else {
            HistoricalHash::Md5
        },
        salt_length: if alternate { usize::MAX } else { 5 },
    }
}

pub(super) fn mechanism_info(alternate: bool) -> MechanismInfo {
    MechanismInfo {
        flags: if alternate { u64::MAX } else { 3 },
        maximum: if alternate { u64::MAX } else { 4 },
        minimum: if alternate { u64::MAX } else { 5 },
    }
}

pub(super) fn public_key_import_options(alternate: bool) -> PublicKeyImportOptions {
    PublicKeyImportOptions {
        admission: if alternate {
            object_admission(true)
        } else {
            object_admission(false)
        },
        copyable: if alternate { false } else { true },
        destroyable: if alternate { false } else { true },
        metadata: if alternate {
            PublicImportMetadata::SpkiSha256 {
                label: vec![],
                prefix: vec![],
            }
        } else {
            PublicImportMetadata::Exact {
                id: vec![],
                label: vec![],
            }
        },
        modifiable: if alternate { false } else { true },
        persistent: if alternate { false } else { true },
        usages: if alternate {
            key_usage_request(true)
        } else {
            key_usage_request(false)
        },
        visibility: if alternate {
            ObjectVisibility::Public
        } else {
            ObjectVisibility::Private
        },
    }
}

pub(super) fn rsa_pss_parameters(alternate: bool) -> RsaPssParameters {
    RsaPssParameters {
        hash: if alternate {
            HashAlgorithm::Sha512
        } else {
            HashAlgorithm::Sha224
        },
        mgf_hash: if alternate {
            HashAlgorithm::Sha512
        } else {
            HashAlgorithm::Sha224
        },
        salt_length: if alternate { usize::MAX } else { 5 },
    }
}

pub(super) fn stream_progress(alternate: bool) -> StreamProgress {
    StreamProgress {
        delivered_bytes: if alternate { 7 } else { 0 },
        input_bytes: if alternate { 8 } else { 0 },
        key_inputs: if alternate { u64::MAX } else { 5 },
        output_bytes: if alternate { 10 } else { 0 },
        submissions: if alternate { u64::MAX } else { 7 },
    }
}

pub(super) fn token_resource_status(alternate: bool) -> TokenResourceStatus {
    TokenResourceStatus {
        generation: if alternate { u64::MAX } else { 3 },
        identity: if alternate {
            token_identity(true)
        } else {
            token_identity(false)
        },
        usage: if alternate {
            session_usage(true)
        } else {
            session_usage(false)
        },
    }
}

pub(super) fn validation_observation(alternate: bool) -> ValidationObservation {
    ValidationObservation {
        function: if alternate { "field0" } else { "" },
        message_index: if alternate { Some(usize::MAX) } else { None },
        validation: if alternate {
            SessionValidation::Unavailable
        } else {
            SessionValidation::Reported(6)
        },
    }
}

pub(super) fn windows_loader_observation_limits(alternate: bool) -> WindowsLoaderObservationLimits {
    WindowsLoaderObservationLimits {
        maximum_activation_assemblies: if alternate { usize::MAX } else { 3 },
        maximum_activation_files: if alternate { usize::MAX } else { 4 },
        maximum_activation_query_bytes: if alternate {
            std::num::NonZeroUsize::new(usize::MAX).unwrap()
        } else {
            std::num::NonZeroUsize::new(1).unwrap()
        },
        maximum_modules: if alternate { usize::MAX } else { 6 },
        maximum_path_code_units: if alternate {
            std::num::NonZeroUsize::new(usize::MAX).unwrap()
        } else {
            std::num::NonZeroUsize::new(1).unwrap()
        },
        maximum_registry_entries: if alternate { usize::MAX } else { 8 },
        maximum_registry_value_bytes: if alternate {
            std::num::NonZeroUsize::new(usize::MAX).unwrap()
        } else {
            std::num::NonZeroUsize::new(1).unwrap()
        },
    }
}

pub(super) fn windows_loader_requests(alternate: bool) -> WindowsLoaderRequests {
    WindowsLoaderRequests {
        activation_context: if alternate {
            WindowsLoaderRequest::RequireKnown
        } else {
            WindowsLoaderRequest::NotRequested
        },
        api_sets: if alternate {
            WindowsLoaderRequest::RequireKnown
        } else {
            WindowsLoaderRequest::NotRequested
        },
        dev_override_effective: if alternate {
            WindowsLoaderRequest::RequireKnown
        } else {
            WindowsLoaderRequest::NotRequested
        },
        dev_override_registry: if alternate {
            WindowsLoaderRequest::RequireKnown
        } else {
            WindowsLoaderRequest::NotRequested
        },
        dot_local: if alternate {
            WindowsLoaderRequest::RequireKnown
        } else {
            WindowsLoaderRequest::NotRequested
        },
        global_search_state: if alternate {
            WindowsLoaderRequest::RequireKnown
        } else {
            WindowsLoaderRequest::NotRequested
        },
        known_dlls: if alternate {
            WindowsLoaderRequest::RequireKnown
        } else {
            WindowsLoaderRequest::NotRequested
        },
        loaded_modules: if alternate {
            WindowsLoaderRequest::RequireKnown
        } else {
            WindowsLoaderRequest::NotRequested
        },
        package_dependency_graph: if alternate {
            WindowsLoaderRequest::RequireKnown
        } else {
            WindowsLoaderRequest::NotRequested
        },
        packaged_dot_local: if alternate {
            WindowsLoaderRequest::RequireKnown
        } else {
            WindowsLoaderRequest::NotRequested
        },
        search_directories: if alternate {
            WindowsLoaderRequest::RequireKnown
        } else {
            WindowsLoaderRequest::NotRequested
        },
    }
}
