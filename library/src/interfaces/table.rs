// SPDX-License-Identifier: Apache-2.0
//! The exact selected native table stays owned by the loaded library.
use super::{
    AsyncFunctions, AuthenticatedKeyTransportFunctions, CommonFunctions, KemFunctions,
    MessageFunctions, VerifySignatureFunctions,
};
use fe11_sys::*;

pub(crate) enum SelectedTable {
    // The 68-entry historical table also represents explicitly selected 2.20
    // and draft 2.30. Its actual version remains in the copied header.
    V240(CK_FUNCTION_LIST),
    // OASIS 3.1 retains the CK_FUNCTION_LIST_3_0 declaration and 92 fields.
    V30Or31(CK_FUNCTION_LIST_3_0),
    V32(CK_FUNCTION_LIST_3_2),
}

pub(crate) struct FunctionViews {
    pub common: CommonFunctions,
    pub login_user: CK_C_LoginUser,
    pub authenticated_transport: Option<AuthenticatedKeyTransportFunctions>,
    pub messages: Option<MessageFunctions>,
    pub asynchronous: Option<AsyncFunctions>,
    pub kem: Option<KemFunctions>,
    pub verify_signature: Option<VerifySignatureFunctions>,
}

impl SelectedTable {
    // These immutable views preserve the existing operation owners. Only this
    // constructor derives them from the one selected layout; none is negotiated.
    pub(crate) fn views(&self) -> FunctionViews {
        match self {
            Self::V240(table) => FunctionViews {
                common: common_table!(table),
                login_user: None,
                authenticated_transport: None,
                messages: None,
                asynchronous: None,
                kem: None,
                verify_signature: None,
            },
            Self::V30Or31(table) => FunctionViews {
                common: common_table!(table),
                login_user: table.C_LoginUser,
                authenticated_transport: None,
                messages: Some(message_functions!(table)),
                asynchronous: None,
                kem: None,
                verify_signature: None,
            },
            Self::V32(table) => FunctionViews {
                common: common_table!(table),
                login_user: table.C_LoginUser,
                authenticated_transport: Some(AuthenticatedKeyTransportFunctions {
                    wrap: table.C_WrapKeyAuthenticated,
                    unwrap: table.C_UnwrapKeyAuthenticated,
                }),
                messages: Some(message_functions!(table)),
                asynchronous: Some(AsyncFunctions {
                    complete: table.C_AsyncComplete,
                    get_id: table.C_AsyncGetID,
                    join: table.C_AsyncJoin,
                    validation: table.C_GetSessionValidationFlags,
                }),
                kem: Some(KemFunctions {
                    encapsulate: table.C_EncapsulateKey,
                    decapsulate: table.C_DecapsulateKey,
                }),
                verify_signature: Some(VerifySignatureFunctions {
                    init: table.C_VerifySignatureInit,
                    single: table.C_VerifySignature,
                    update: table.C_VerifySignatureUpdate,
                    finish: table.C_VerifySignatureFinal,
                }),
            },
        }
    }
}
