// SPDX-License-Identifier: Apache-2.0
//! Builder snapshots are compared with the independently inventoried native table.
use super::{
    configuration::{Budgets, Configuration},
    module_controls,
    outcome::Failure,
    report::Report,
};
use fe11::*;
use std::{
    fs::File,
    io::{self, Read, Write},
    path::Path,
};

struct Expected {
    interfaces: bool,
    concurrent: bool,
    functions: Vec<String>,
}

fn read(path: &Path) -> std::result::Result<Expected, Failure> {
    let mut text = String::new();
    File::open(path)
        .map_err(|_| Failure::Input("builder_fixture_open"))?
        .take(8193)
        .read_to_string(&mut text)
        .map_err(|_| Failure::Input("builder_fixture_read"))?;
    if text.len() > 8192 {
        return Err(Failure::Input("builder_fixture_size"));
    }
    let mut lines = text.lines();
    let selector = lines.next();
    let concurrent = matches!(
        selector,
        Some("concurrent-interfaces" | "concurrent-functions")
    );
    let interfaces = match selector {
        Some("interfaces" | "concurrent-interfaces") => true,
        Some("functions" | "concurrent-functions") => false,
        _ => return Err(Failure::Input("builder_fixture_action")),
    };
    let functions: Vec<String> = lines.map(String::from).collect();
    if functions.len() != 104 || functions.iter().any(|s| !s.starts_with("C_")) {
        return Err(Failure::Input("builder_fixture_functions"));
    }
    Ok(Expected {
        interfaces,
        concurrent,
        functions,
    })
}

fn check(config: &Configuration, expected: &Expected) -> std::result::Result<(), Failure> {
    let builder = config.builder(&Budgets::ordinary());
    if expected.interfaces {
        // The independent recipe inventory establishes one standard descriptor.
        // Its version is independent of the builder's later table selection.
        let inventory = builder.observe_interfaces(InterfaceInventoryLimits {
            interfaces: 16,
            attempts: 4,
            name_bytes: 32,
            total_name_bytes: 256,
        })?;
        if inventory.interfaces
            != vec![InterfaceDescriptor {
                name: b"PKCS 11".to_vec(),
                standard_version: Some((3, 2)),
                flags: fe11_sys::CKF_INTERFACE_FORK_SAFE as u64,
            }]
        {
            return Err(Failure::Oracle("builder_interface_descriptor"));
        }
        drop(builder);
        // The copied descriptor remains usable without a builder or image lease.
        if inventory.interfaces[0].name != b"PKCS 11" {
            return Err(Failure::Oracle("builder_descriptor_ownership"));
        }
    } else {
        let catalog = builder.observe_functions()?;
        drop(builder);
        let present = match config.interface {
            InterfaceSelection::Legacy240 => 68,
            InterfaceSelection::Standard {
                version: (3, 2), ..
            } => 104,
            _ => return Err(Failure::Input("builder_fixture_interface")),
        };
        if catalog.observations().len() != expected.functions.len() {
            return Err(Failure::Oracle("builder_catalogue_count"));
        }
        for (index, ((name, actual), expected_name)) in
            catalog.observations().zip(&expected.functions).enumerate()
        {
            let expected_presence = if index < present {
                FunctionPresence::Present
            } else {
                FunctionPresence::OutsideSelectedInterface
            };
            if name != expected_name
                || actual != expected_presence
                || catalog.observation(name) != Some(actual)
            {
                return Err(Failure::Oracle("builder_catalogue_entry"));
            }
        }
        if catalog.observation("C_NoSuchFunction").is_some() {
            return Err(Failure::Oracle("builder_catalogue_unknown_name"));
        }
    }
    Ok(())
}

// Only safe copied metadata crosses the thread boundary. Both image users are
// joined before cleanup; the barrier expresses contention, not a speed target.
fn concurrent_check(
    config: &Configuration,
    expected: &Expected,
) -> std::result::Result<(), Failure> {
    let barrier = std::sync::Barrier::new(3);
    std::thread::scope(|scope| {
        let run = || {
            barrier.wait();
            check(config, expected)
        };
        let left = scope.spawn(run);
        let right = scope.spawn(run);
        barrier.wait();
        let left = left.join();
        let right = right.join();
        for result in [left, right] {
            result.map_err(|_| Failure::Oracle("discovery_worker_panicked"))??;
        }
        Ok(())
    })
}

pub fn execute<W: Write>(
    config: &Configuration,
    path: &Path,
    report: Report<W>,
) -> io::Result<bool> {
    let mut preparation = None;
    let mut cleanup = Vec::new();
    let setup = (|| {
        let expected = read(path)?;
        // Load the complete recipe dependencies during explicit preparation.
        // Finalize before observing: the body must not initialize another owner.
        preparation = Some(config.open(&Budgets::ordinary())?);
        preparation
            .as_ref()
            .ok_or(Failure::Input("builder_preparation"))?
            .close()?;
        preparation.take();
        Ok::<_, Failure>(expected)
    })();
    let body = match &setup {
        Ok(expected) if expected.concurrent => concurrent_check(config, expected),
        Ok(expected) => check(config, expected),
        Err(_) => Ok(()),
    };
    if let Some(module) = preparation {
        if let Err(error) = module.close() {
            cleanup.push(error.into());
        }
    }
    module_controls::finish(report, setup.map(|_| ()), body, cleanup)
}
