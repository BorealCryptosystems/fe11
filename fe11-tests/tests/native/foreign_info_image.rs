// SPDX-License-Identifier: Apache-2.0
//! Foreign adapters retain synchronous functions from the selected image.
use super::{configuration::Configuration, native_support, outcome::Failure};
use fe11::InterfaceSelection;
use fe11_sys::*;
use std::{ptr, sync::Arc};

pub(super) type GetInfo = unsafe extern "C" fn(CK_INFO_PTR) -> CK_RV;
type OpenSession = unsafe extern "C" fn(
    CK_SLOT_ID,
    CK_FLAGS,
    CK_VOID_PTR,
    CK_NOTIFY,
    CK_SESSION_HANDLE_PTR,
) -> CK_RV;
type Login =
    unsafe extern "C" fn(CK_SESSION_HANDLE, CK_USER_TYPE, CK_UTF8CHAR_PTR, CK_ULONG) -> CK_RV;
type Logout = unsafe extern "C" fn(CK_SESSION_HANDLE) -> CK_RV;
type CloseSession = unsafe extern "C" fn(CK_SESSION_HANDLE) -> CK_RV;
type CreateObject = unsafe extern "C" fn(
    CK_SESSION_HANDLE,
    CK_ATTRIBUTE_PTR,
    CK_ULONG,
    CK_OBJECT_HANDLE_PTR,
) -> CK_RV;
type DestroyObject = unsafe extern "C" fn(CK_SESSION_HANDLE, CK_OBJECT_HANDLE) -> CK_RV;
type WaitForSlotEvent = unsafe extern "C" fn(CK_FLAGS, CK_SLOT_ID_PTR, CK_VOID_PTR) -> CK_RV;
type GetLegacy = unsafe extern "C" fn(CK_FUNCTION_LIST_PTR_PTR) -> CK_RV;
type GetInterface =
    unsafe extern "C" fn(CK_UTF8CHAR_PTR, CK_VERSION_PTR, CK_INTERFACE_PTR_PTR, CK_FLAGS) -> CK_RV;

pub(super) struct Image {
    // Retained by the registered participant until the runtime releases it.
    _library: libloading::Library,
    pub get_info: GetInfo,
    pub open_session: OpenSession,
    pub close_session: CloseSession,
    pub create_object: Option<CreateObject>,
    pub destroy_object: Option<DestroyObject>,
    pub login: Option<Login>,
    pub logout: Option<Logout>,
    pub wait_for_slot_event: Option<WaitForSlotEvent>,
    pub identity: fe11::ExternalModuleIdentity,
}

impl Image {
    pub fn load(config: &Configuration) -> Result<Arc<Self>, Failure> {
        native_support::verify_image(config)?;
        // SAFETY: this is the explicit, digest-checked provider already opened by
        // Fe11. This lease neither initializes nor finalizes the native runtime.
        let library = unsafe { libloading::Library::new(&config.module) }
            .map_err(|_| Failure::Input("foreign_image_load"))?;
        let (table, expected, interface_flags) = match config.interface {
            InterfaceSelection::Legacy240 => {
                // SAFETY: exact public export signature; image remains retained.
                let get: libloading::Symbol<'_, GetLegacy> =
                    unsafe { library.get(b"C_GetFunctionList\0") }
                        .map_err(|_| Failure::Input("foreign_legacy_export"))?;
                let mut table = ptr::null_mut();
                // SAFETY: writable table pointer; no initialization or session action.
                native_support::status("C_GetFunctionList", unsafe { get(&mut table) })?;
                (table, (2, 40), 0)
            }
            InterfaceSelection::Standard {
                version,
                required_flags: flags,
            } => {
                // SAFETY: exact PKCS#11 interface-selection signature.
                let get: libloading::Symbol<'_, GetInterface> =
                    unsafe { library.get(b"C_GetInterface\0") }
                        .map_err(|_| Failure::Input("foreign_interface_export"))?;
                let mut requested = CK_VERSION {
                    major: version.0,
                    minor: version.1,
                };
                let mut name = *b"PKCS 11\0";
                let mut descriptor: CK_INTERFACE_PTR = ptr::null_mut();
                let flags = CK_FLAGS::try_from(flags)
                    .map_err(|_| Failure::Input("foreign_interface_flags"))?;
                // SAFETY: terminated name, readable version and writable descriptor.
                native_support::status("C_GetInterface", unsafe {
                    get(name.as_mut_ptr(), &mut requested, &mut descriptor, flags)
                })?;
                if descriptor.is_null() {
                    return Err(Failure::Oracle("foreign_descriptor_null"));
                }
                // SAFETY: successful selection returned a descriptor held by library.
                let descriptor = unsafe { &*descriptor };
                if descriptor.flags & flags != flags {
                    return Err(Failure::Oracle("foreign_interface_flags"));
                }
                (
                    descriptor.pFunctionList.cast::<CK_FUNCTION_LIST>(),
                    version,
                    descriptor.flags as u64,
                )
            }
            _ => return Err(Failure::Input("foreign_interface_selection")),
        };
        if table.is_null() {
            return Err(Failure::Oracle("foreign_table_null"));
        }
        // SAFETY: every returned function table begins with CK_VERSION. Check it
        // before accessing the common PKCS#11 2.40 prefix of the selected table.
        let version = unsafe { ptr::read(table.cast::<CK_VERSION>()) };
        if (version.major, version.minor) != expected {
            return Err(Failure::Oracle("foreign_table_version"));
        }
        // SAFETY: verified 2.40 or 3.2 table contains this common prefix; copy the
        // function pointer while retaining its image, never a borrowed table owner.
        let get_info = native_support::required(unsafe { (*table).C_GetInfo })?;
        // SAFETY: these entries belong to the same verified common prefix.
        let open_session = native_support::required(unsafe { (*table).C_OpenSession })?;
        // SAFETY: copied function retains the image lease above.
        let close_session = native_support::required(unsafe { (*table).C_CloseSession })?;
        // SAFETY: optional common-prefix functions; image remains retained.
        let (create_object, destroy_object) =
            unsafe { ((*table).C_CreateObject, (*table).C_DestroyObject) };
        // SAFETY: optional entry in the same verified common table prefix.
        // Its absence does not change the other foreign-call prerequisites.
        // SAFETY: these optional entries use the same verified common prefix.
        let login = unsafe { (*table).C_Login };
        // SAFETY: copying an entry does not perform authentication.
        let logout = unsafe { (*table).C_Logout };
        let wait_for_slot_event = unsafe { (*table).C_WaitForSlotEvent };
        // SAFETY: lifecycle entries have the same checked common-prefix layout.
        // Merely copying them does not authorize a lifecycle call.
        let identity = unsafe {
            fe11::ExternalModuleIdentity {
                initialize: (*table).C_Initialize,
                finalize: (*table).C_Finalize,
                function_list_version: expected,
                interface_flags,
            }
        };
        Ok(Arc::new(Self {
            _library: library,
            get_info,
            open_session,
            close_session,
            create_object,
            destroy_object,
            login,
            logout,
            wait_for_slot_event,
            identity,
        }))
    }
}
