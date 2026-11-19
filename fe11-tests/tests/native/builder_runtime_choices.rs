// SPDX-License-Identifier: Apache-2.0
//! Replaced builder settings are observed through native metadata and ownership.
use super::{
    configuration::{select_token, Budgets, Configuration},
    module_controls, module_lifecycle,
    outcome::Failure,
    report::Report,
};
use fe11::*;
use std::{
    fs::File,
    io::{self, Read, Write},
    path::Path,
    sync::{
        atomic::{AtomicUsize, Ordering},
        Arc,
    },
};

struct Lifetime(Arc<AtomicUsize>);
#[path = "absent_operation_selectors.rs"]
mod absent_operation_selectors;
#[path = "configuration_variants.rs"]
mod configuration_variants;
#[path = "imported_private_attributes.rs"]
mod imported_private_attributes;
#[path = "notification_ownership.rs"]
mod notification_ownership;
#[path = "output_credit.rs"]
mod output_credit;
#[path = "protocol_absence.rs"]
mod protocol_absence;
#[path = "public_point_forms.rs"]
mod public_point_forms;
#[path = "reference_credit.rs"]
mod reference_credit;
#[path = "resource_controls.rs"]
mod resource_controls;
#[path = "shared_clients.rs"]
mod shared_clients;
impl Drop for Lifetime {
    fn drop(&mut self) {
        self.0.fetch_add(1, Ordering::SeqCst);
    }
}
// A NULL projection has the standard PKCS#11 initialization meaning. No
// allocation is exposed, dereferenced or retained by the native module.
unsafe fn null_reserved(_: *mut Lifetime) -> fe11_sys::CK_VOID_PTR {
    std::ptr::null_mut()
}

pub fn execute<W: Write>(
    config: &Configuration,
    path: &Path,
    report: Report<W>,
) -> io::Result<bool> {
    let mut selector = String::new();
    let selector_read =
        File::open(path).and_then(|file| file.take(65).read_to_string(&mut selector));
    if selector_read.is_ok() {
        if selector.starts_with("imported-private-attributes\n") {
            return imported_private_attributes::execute(config, path, report);
        }
        if let Some(action) = selector
            .strip_prefix("notification-owner:")
            .and_then(|s| s.strip_suffix('\n'))
        {
            return notification_ownership::execute(config, action, report);
        }
        if let Some(selection) = selector.strip_prefix("agreement-absence:").and_then(|s| s.strip_suffix('\n')) {
            return absent_operation_selectors::agreement::execute(config, selection, report);
        }
        if let Some(selection) = selector.strip_prefix("legacy-key-absence:").and_then(|s| s.strip_suffix('\n')) {
            return absent_operation_selectors::legacy::execute(config, selection, report);
        }
        if let Some(selection) = selector
            .strip_prefix("hash-selector-absence:")
            .or_else(|| selector.strip_prefix("cipher-selector-absence:"))
            .or_else(|| selector.strip_prefix("rsa-selector-absence:"))
            .and_then(|s| s.strip_suffix('\n'))
        {
            return absent_operation_selectors::execute(config, selection, report);
        }
        if selector.starts_with("public-point\n") {
            return public_point_forms::execute(config, path, report);
        }
        if let Some(action) = selector
            .strip_prefix("protocol-absence:")
            .and_then(|s| s.strip_suffix('\n'))
        {
            return protocol_absence::execute(config, action, report);
        }
        if selector == "shared-clients\n" {
            return shared_clients::execute(config, report);
        }
        if let Some(action) = selector
            .strip_prefix("output-credit:")
            .and_then(|s| s.strip_suffix('\n'))
        {
            return output_credit::execute(config, action, report);
        }
        if let Some(action) = selector
            .strip_prefix("resource-control:")
            .and_then(|s| s.strip_suffix('\n'))
        {
            return resource_controls::execute(config, action, report);
        }
        if selector.starts_with("configuration:") {
            return configuration_variants::execute(config, path, report);
        }
        if let Some(limit) = selector
            .strip_prefix("reference-credit:")
            .and_then(|s| s.strip_suffix('\n'))
            .and_then(|s| s.parse::<usize>().ok())
        {
            return reference_credit::execute(config, limit, report);
        }
    }
    let mut module = None;
    let mut session = None;
    let dropped = Arc::new(AtomicUsize::new(0));
    let setup = (|| -> std::result::Result<String, Failure> {
        let mut action = String::new();
        File::open(path)
            .map_err(|_| Failure::Input("builder_runtime_fixture"))?
            .take(33)
            .read_to_string(&mut action)
            .map_err(|_| Failure::Input("builder_runtime_read"))?;
        let action = action
            .strip_suffix('\n')
            .ok_or(Failure::Input("builder_runtime_fields"))?;
        let builder = config
            .builder(&Budgets::ordinary())
            .object_limits(ObjectLimits {
                object_references: Some(77),
                managed_references: Some(66),
                destination_reservations: Some(55),
            });
        let builder = match action {
            "initialization" => builder
                .initialization(InitializationOptions {
                    cannot_create_os_threads: true,
                    concurrency: NativeConcurrency::Serialized,
                })
                .initialization(InitializationOptions {
                    cannot_create_os_threads: false,
                    concurrency: NativeConcurrency::Concurrent,
                }),
            "mutexes" => {
                // SAFETY: all callback pointers are NULL; there is no callable
                // code or native mutex state. The owner only records its Drop.
                let owner = unsafe {
                    InitializationMutexes::new(
                        InitializationMutexFunctions::default(),
                        Lifetime(dropped.clone()),
                    )
                };
                builder
                    .initialization_mutexes(Some(owner))
                    .initialization_mutexes(None)
            }
            "reserved" => {
                // SAFETY: the projection is the standard NULL pReserved value;
                // no native access to the Rust owner is possible.
                let owner = unsafe {
                    InitializationReserved::external(
                        Box::new(Lifetime(dropped.clone())),
                        null_reserved,
                    )
                };
                builder
                    .reserved_initialization(Some(owner))
                    .reserved_initialization(None)
            }
            "interfaces" => builder
                .interface_discovery(InterfaceDiscoveryLimits {
                    interfaces: 0,
                    attempts: 1,
                })
                .interface_discovery(InterfaceDiscoveryLimits {
                    interfaces: 16,
                    attempts: 4,
                }),
            "buffers" => builder
                .symmetric_limits(SymmetricLimits {
                    maximum_buffer_bytes: 8 * 1024 * 1024,
                })
                .symmetric_limits(SymmetricLimits {
                    maximum_buffer_bytes: 16 * 1024 * 1024,
                }),
            _ => return Err(Failure::Input("builder_runtime_action")),
        };
        let expected_drops = usize::from(matches!(action, "mutexes" | "reserved"));
        if dropped.load(Ordering::SeqCst) != expected_drops {
            return Err(Failure::Oracle("builder_replaced_owner_retained"));
        }
        module = Some(builder.open()?);
        let m = module
            .as_ref()
            .ok_or(Failure::Input("builder_runtime_module"))?;
        let token =
            select_token(m, &config.label).ok_or(Failure::Input("builder_runtime_token"))?;
        session = Some(m.select(&token)?.open_session(true)?);
        Ok(action.into())
    })();
    let body = (|| -> std::result::Result<(), Failure> {
        let (Ok(action), Some(m), Some(s)) = (&setup, &module, &session) else {
            return Ok(());
        };
        let limits = m.object_limits();
        if limits.object_references != Some(77)
            || limits.managed_references != Some(66)
            || limits.destination_reservations != Some(55)
        {
            return Err(Failure::Oracle("builder_unrelated_limits_changed"));
        }
        module_lifecycle::control(s)?;
        if action == "buffers" {
            let before = m.call_counts()?;
            let request =
                NativeDigestAlgorithm::Null(NativeNullDigestCapacity::new(20 * 1024 * 1024)?);
            match s.digest_native_single(
                request,
                &[],
                InputLimits {
                    maximum_parts: 1,
                    maximum_total_bytes: 0,
                },
            ) {
                Err(Error::ResourceLimitExceeded { limit, .. }) if limit == 16 * 1024 * 1024 => (),
                Err(error) => return Err(error.into()),
                Ok(_) => return Err(Failure::Oracle("builder_buffer_limit_not_applied")),
            }
            if m.call_counts()? != before {
                return Err(Failure::Oracle("builder_buffer_limit_dispatched"));
            }
        }
        Ok(())
    })();
    let mut cleanup = Vec::new();
    if let Some(s) = &session {
        if let Err(error) = s.close() {
            cleanup.push(error.into());
        }
    }
    drop(session);
    if let Some(m) = &module {
        if let Err(error) = m.close() {
            cleanup.push(error.into());
        }
    }
    drop(module);
    if let Ok(action) = &setup {
        if dropped.load(Ordering::SeqCst)
            != usize::from(matches!(action.as_str(), "mutexes" | "reserved"))
        {
            cleanup.push(Failure::Oracle("builder_owner_drop_count"));
        }
    }
    module_controls::finish(report, setup.map(|_| ()), body, cleanup)
}
