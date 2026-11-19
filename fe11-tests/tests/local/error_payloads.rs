// SPDX-License-Identifier: Apache-2.0
//! Public error payloads retain independent native, local and cleanup facts.
//! These are value contracts, not injected native failures or resource requests.
use fe11::*;
use std::error::Error as StdError;

fn check(error: Error, assertion: impl FnOnce(&Error) -> bool) {
    assert!(assertion(&error));
    let cloned = error.clone();
    assert_eq!(cloned, error);
    assert!(!error.to_string().is_empty());
    assert!(!format!("{error:?}").is_empty());
}

fn native(code: u64, may_have_effect: bool) -> Error {
    Error::Native {
        function: "C_Test",
        code,
        may_have_effect,
    }
}

#[test]
fn native_codes_and_effects_are_independent_of_integer_width() {
    for code in [0, 1, u32::MAX as u64, u32::MAX as u64 + 1, u64::MAX] {
        for may_have_effect in [false, true] {
            check(native(code, may_have_effect), |e| {
                matches!(e,
                Error::Native { function: "C_Test", code: c, may_have_effect: effect }
                if *c == code && *effect == may_have_effect)
            });
            assert!(StdError::source(&native(code, may_have_effect)).is_none());
        }
    }
}

#[test]
fn output_size_payloads_keep_distinct_required_and_supplied_values() {
    for (required, capacity) in [(0, 1), (1, usize::MAX), (usize::MAX, 0)] {
        for code in [0, 0x150, u64::MAX] {
            let cipher = CipherBufferRequest {
                function: "C_EncryptFinal",
                code,
                required,
                previous_capacity: capacity,
            };
            check(Error::CipherBufferRequired(cipher), |e| {
                matches!(e,
                Error::CipherBufferRequired(CipherBufferRequest { function: "C_EncryptFinal", code: c, required: r, previous_capacity: p })
                if *c == code && *r == required && *p == capacity)
            });
            let signature = SignatureBufferRequest {
                function: "C_SignFinal",
                code,
                required,
                previous_capacity: capacity,
            };
            check(Error::SignatureBufferRequired(signature), |e| {
                matches!(e,
                Error::SignatureBufferRequired(SignatureBufferRequest { function: "C_SignFinal", code: c, required: r, previous_capacity: p })
                if *c == code && *r == required && *p == capacity)
            });
            check(
                Error::OutputBufferTooSmall {
                    function: "C_WrapKey",
                    code,
                    required,
                    capacity,
                },
                |e| {
                    matches!(e,
                Error::OutputBufferTooSmall { function: "C_WrapKey", code: c, required: r, capacity: p }
                if *c == code && *r == required && *p == capacity)
                },
            );
        }
    }
    for reported in [0, 1, u32::MAX as u64, u32::MAX as u64 + 1, u64::MAX] {
        let size = NativeOutputSize {
            function: "C_EncapsulateKey",
            code: 0x150,
            reported,
            limit: 7,
        };
        let reason = InputBoundsRejection::LengthConversion;
        check(Error::OutputSizeRejected { size, reason }, |e| {
            matches!(e,
            Error::OutputSizeRejected { size: actual, reason: InputBoundsRejection::LengthConversion }
            if actual.function == "C_EncapsulateKey" && actual.code == 0x150 && actual.reported == reported && actual.limit == 7)
        });
        assert!(!size.to_string().is_empty());
    }
}

#[test]
fn compound_errors_preserve_both_payloads_and_the_documented_source_chain() {
    let primary = native(u64::MAX, true);
    let secondary = Error::AdmissionDeadline;
    let size = NativeOutputSize {
        function: "C_GetOperationState",
        code: 0x150,
        reported: u64::MAX,
        limit: 3,
    };
    let cases = [
        Error::OperationCompleted {
            function: "C_CreateObject",
            cause: Box::new(primary.clone()),
        },
        Error::NativeAndLocalFailure {
            function: "C_DeriveKey",
            code: 5,
            cause: Box::new(primary.clone()),
        },
        Error::NativeOutputAndLocalFailure {
            size,
            cause: Box::new(primary.clone()),
        },
        Error::ObjectsMayRemain(Box::new(primary.clone())),
        Error::CleanupFailed {
            operation: Box::new(primary.clone()),
            cleanup: Box::new(secondary.clone()),
        },
    ];
    for error in cases {
        assert_eq!(
            StdError::source(&error).unwrap().downcast_ref::<Error>(),
            Some(&primary)
        );
        check(error, |e| match e {
            Error::OperationCompleted { function, cause } => {
                *function == "C_CreateObject" && **cause == primary
            }
            Error::NativeAndLocalFailure {
                function,
                code,
                cause,
            } => *function == "C_DeriveKey" && *code == 5 && **cause == primary,
            Error::NativeOutputAndLocalFailure {
                size: actual,
                cause,
            } => *actual == size && **cause == primary,
            Error::ObjectsMayRemain(cause) => **cause == primary,
            Error::CleanupFailed { operation, cleanup } => {
                **operation == primary && **cleanup == secondary
            }
            _ => false,
        });
    }
    let nested = Error::ObjectsMayRemain(Box::new(Error::CleanupFailed {
        operation: Box::new(primary.clone()),
        cleanup: Box::new(secondary),
    }));
    let source = StdError::source(&nested).unwrap();
    assert!(matches!(
        source.downcast_ref::<Error>(),
        Some(Error::CleanupFailed { .. })
    ));
    assert_eq!(
        source.source().unwrap().downcast_ref::<Error>(),
        Some(&primary)
    );
}

#[test]
fn resource_and_attribute_errors_preserve_ordered_provenance() {
    for (requested, limit) in [(0, 1), (1, usize::MAX), (usize::MAX, 0)] {
        let resource = ResourceKind::SymmetricByteBudget;
        check(
            Error::ResourceLimitExceeded {
                resource,
                requested,
                limit,
            },
            |e| {
                matches!(e,
            Error::ResourceLimitExceeded { resource: ResourceKind::SymmetricByteBudget, requested: r, limit: l }
            if *r == requested && *l == limit)
            },
        );
        let first = AttributeBatchCall {
            code: 0x11,
            attribute_count: requested,
        };
        let second = AttributeBatchCall {
            code: 0x12,
            attribute_count: limit,
        };
        let reason = RejectionReason::InputBounds(InputBoundsRejection::LengthConversion);
        for calls in [
            AttributeBatchCalls::None,
            AttributeBatchCalls::One(first),
            AttributeBatchCalls::Two { first, second },
        ] {
            for cause in [
                AttributeAdmissionFailure::Busy(BusyReason::from(
                    AeadMessagesBusy::AeadControlChanged,
                )),
                AttributeAdmissionFailure::ResourceLimitExceeded {
                    resource,
                    requested,
                    limit,
                },
                AttributeAdmissionFailure::Cancelled,
                AttributeAdmissionFailure::Deadline,
            ] {
                assert!(!cause.to_string().is_empty());
                check(Error::AttributeReadInterrupted { calls, cause }, |e| {
                    matches!(e,
                    Error::AttributeReadInterrupted { calls: c, cause: a } if *c == calls && *a == cause)
                });
            }
        }
        check(
            Error::AttributeReadInvalid {
                call: first,
                reason,
            },
            |e| {
                matches!(e,
            Error::AttributeReadInvalid { call, reason: actual } if call.code == 0x11 && call.attribute_count == requested && *actual == reason)
            },
        );
    }
}

#[test]
fn initialization_fields_and_simple_states_remain_distinct() {
    for field in [
        MessageInitField::IvLength,
        MessageInitField::IvFixedBits,
        MessageInitField::IvGenerator,
        MessageInitField::TagBits,
        MessageInitField::NonceLength,
        MessageInitField::NonceFixedBits,
        MessageInitField::NonceGenerator,
        MessageInitField::MacLength,
        MessageInitField::DataLength,
    ] {
        check(Error::InitParameterChangeBeforeEffect { field }, |e| {
            matches!(e,
            Error::InitParameterChangeBeforeEffect { field: actual } if *actual == field)
        });
    }
    let cases = [
        Error::InvalidCiphertext,
        Error::AdmissionCancelled,
        Error::AdmissionDeadline,
        Error::Poisoned,
    ];
    for (i, error) in cases.iter().enumerate() {
        assert!(StdError::source(error).is_none());
        for (j, other) in cases.iter().enumerate() {
            assert_eq!(error == other, i == j);
        }
        check(error.clone(), |e| e == error);
    }
    for function in ["", "C_Test", "fonction_é", "a\0b"] {
        check(
            Error::Unsupported(UnsupportedReason::NativeFunction { function }),
            |e| {
                matches!(e,
            Error::Unsupported(UnsupportedReason::NativeFunction { function: actual }) if *actual == function)
            },
        );
    }
}

#[test]
fn loader_diagnostics_separate_os_codes_from_pkcs11_codes() {
    let channels = [
        WindowsLoaderChannel::DotLocal,
        WindowsLoaderChannel::PackagedDotLocal,
        WindowsLoaderChannel::DevOverrideRegistry,
        WindowsLoaderChannel::DevOverrideEffective,
        WindowsLoaderChannel::ApiSets,
        WindowsLoaderChannel::ActivationContext,
        WindowsLoaderChannel::LoadedModules,
        WindowsLoaderChannel::KnownDlls,
        WindowsLoaderChannel::PackageDependencyGraph,
        WindowsLoaderChannel::SearchDirectories,
        WindowsLoaderChannel::GlobalSearchState,
    ];
    for channel in channels {
        for cause in [
            WindowsLoaderUnavailable::Os {
                function: "GetTest",
                code: u32::MAX,
            },
            WindowsLoaderUnavailable::OsErrorWithoutCode { function: "Probe" },
            WindowsLoaderUnavailable::NoDocumentedProbe,
            WindowsLoaderUnavailable::ProvenanceUnavailable,
            WindowsLoaderUnavailable::ResourceLimit,
            WindowsLoaderUnavailable::Allocation,
            WindowsLoaderUnavailable::InvalidOutput,
            WindowsLoaderUnavailable::ChangedDuringObservation,
        ] {
            check(
                Error::LoaderObservationUnavailable { channel, cause },
                |e| {
                    matches!(e,
                Error::LoaderObservationUnavailable { channel: c, cause: r } if *c == channel && *r == cause)
                },
            );
        }
    }
}

#[test]
fn content_diagnostics_preserve_unavailability_and_interpretation_causes() {
    for status in [ContentStatus::NotRequested, ContentStatus::Available] {
        check(
            Error::ContentUnavailable { status },
            |e| matches!(e, Error::ContentUnavailable { status: actual } if *actual == status),
        );
    }
    for attribute in [0, 1, u32::MAX as u64, u32::MAX as u64 + 1, u64::MAX] {
        for cause in [
            AttributeUnavailableCause::Sensitive,
            AttributeUnavailableCause::Unsupported,
            AttributeUnavailableCause::Unspecified,
        ] {
            check(
                Error::ContentUnavailable {
                    status: ContentStatus::Unavailable { attribute, cause },
                },
                |e| {
                    matches!(e,
                Error::ContentUnavailable { status: ContentStatus::Unavailable { attribute: a, cause: c } } if *a == attribute && *c == cause)
                },
            );
        }
        for issue in [
            ContentIssue::IntegerEncoding,
            ContentIssue::NotPublicKey,
            ContentIssue::EmptyPublicMaterial,
            ContentIssue::ObjectChanged,
        ] {
            check(
                Error::ContentUnavailable {
                    status: ContentStatus::Unusable { attribute, issue },
                },
                |e| {
                    matches!(e,
                Error::ContentUnavailable { status: ContentStatus::Unusable { attribute: a, issue: i } } if *a == attribute && *i == issue)
                },
            );
        }
    }
}
