// SPDX-License-Identifier: Apache-2.0
//! Function-pointer resolution before native effects or ownership transitions.

use crate::{Error, Result};
use fe11_sys::{CK_INFO_PTR, CK_RV, CK_VOID_PTR};

pub(crate) type InitializationCall = unsafe extern "C" fn(CK_VOID_PTR) -> CK_RV;
pub(crate) type FinalizationCall = unsafe extern "C" fn(CK_VOID_PTR) -> CK_RV;
pub(crate) type InformationCall = unsafe extern "C" fn(CK_INFO_PTR) -> CK_RV;

/// Mandatory lifecycle entries copied from the exact selected interface.
///
/// Construction precedes Initialize. Native retains the selected library image
/// for the entire lifetime of these addresses, including uncertain cleanup.
/// Optional operation functions are deliberately absent from this requirement.
pub(crate) struct Lifecycle {
    pub(crate) initialize: InitializationCall,
    pub(crate) finalize: FinalizationCall,
    pub(crate) information: InformationCall,
}

impl Lifecycle {
    pub(super) fn resolve(table: &crate::interfaces::CommonFunctions) -> Result<Self> {
        Ok(Self {
            initialize: required(table.C_Initialize, "C_Initialize")?,
            finalize: required(table.C_Finalize, "C_Finalize")?,
            information: required(table.C_GetInfo, "C_GetInfo")?,
        })
    }
}

fn required<T>(pointer: Option<T>, function: &'static str) -> Result<T> {
    pointer.ok_or(Error::Rejected(crate::RejectionReason::NativeLoading(
        crate::NativeLoadingRejection::RequiredFunctionMissing { function },
    )))
}

/// Resolve only the selected optional entry, before counting or issuing it.
/// The returned pointer remains borrowed in meaning from the owning Native;
/// copying it does not extend the loaded image's lifetime or grant call authority.
pub(crate) fn resolve<T>(pointer: Option<T>, function: &'static str) -> Result<T> {
    pointer.ok_or(Error::Unsupported(
        crate::UnsupportedReason::NativeFunction { function },
    ))
}
