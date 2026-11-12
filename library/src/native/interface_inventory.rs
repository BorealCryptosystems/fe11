// SPDX-License-Identifier: Apache-2.0
//! Direct interface discovery retaining every image and borrowed descriptor.
use super::{loading::LoadingImage, platform, process_image, Native};
use crate::{Error, InterfaceInventory, InterfaceInventoryLimits, Result};
use std::{cell::Cell, path::Path};

impl Native {
    pub(crate) fn observe_interfaces_file(
        path: &Path,
        identity: platform::FileIdentity,
        source: platform::SourceFiles,
        export_check: platform::ExportFileCheck,
        limits: InterfaceInventoryLimits,
        dependencies: crate::WindowsDependencySearch,
        observations: crate::WindowsLoaderObservations,
    ) -> Result<InterfaceInventory> {
        super::reserve_file(identity)?;
        let uncertain = Cell::new(false);
        let result = (|| {
            // SAFETY: the application chooses a trusted module and loader policy.
            let (library, report) =
                unsafe { platform::load_library(path, dependencies, observations) }?;
            let (library, export_check) = platform::check_loaded_image(library, export_check)?;
            let image = LoadingImage::new(library, Some(source), Vec::new(), &uncertain);
            observe(&image, export_check, limits, report)
        })();
        if !uncertain.get() {
            super::release_file(identity);
        }
        result
    }

    pub(crate) fn observe_interfaces_process(
        limits: InterfaceInventoryLimits,
    ) -> Result<InterfaceInventory> {
        let uncertain = Cell::new(false);
        let process = process_image::open_inventory()?;
        let image = LoadingImage::new(process.library, None, process.providers, &uncertain);
        observe(
            &image,
            platform::ExportFileCheck::NotRequested,
            limits,
            crate::WindowsLoaderReport::not_requested(),
        )
    }
}

fn observe(
    image: &LoadingImage<'_>,
    export_check: platform::ExportFileCheck,
    limits: InterfaceInventoryLimits,
    loader_report: crate::WindowsLoaderReport,
) -> Result<InterfaceInventory> {
    let library = image.library();
    // SAFETY: the named export has the exact standard C ABI; retained below
    // before invocation, including a dependency image providing this symbol.
    let entry = unsafe {
        library.get::<unsafe extern "C" fn(
            *mut fe11_sys::CK_INTERFACE,
            *mut fe11_sys::CK_ULONG,
        ) -> fe11_sys::CK_RV>(b"C_GetInterfaceList\0")
    }
    .map_err(|_| {
        Error::Rejected(crate::RejectionReason::NativeInterfaces(
            crate::NativeInterfacesRejection::InterfaceListExport,
        ))
    })?;
    let address = *entry as usize;
    export_check.check(address)?;
    image.retain_entry_image(address)?;
    // Image retention lasts through all provider-owned name/prefix copies.
    // It is not runtime ownership or exclusion of another caller's Finalize.
    let interfaces = crate::interfaces::observe_inventory(*entry, limits, image.uncertain)?;
    Ok(InterfaceInventory {
        interfaces,
        loader_report,
    })
}
