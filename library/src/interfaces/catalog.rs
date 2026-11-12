// SPDX-License-Identifier: Apache-2.0
//! Presence observations from the exact table, never operation support claims.
use super::SelectedTable;

/// Presence of a standard entry in the selected native function table.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum FunctionPresence {
    /// The selected table contains a non-null pointer. This does not establish
    /// a callable Fe11 API, mechanism support or a successful native operation.
    Present,
    /// This function belongs to the selected layout, but its pointer is null.
    Null,
    /// The selected interface has no field for this function. Exports outside
    /// that table are deliberately not represented by this observation.
    OutsideSelectedInterface,
}

/// Immutable observations of the 104 standard PKCS#11 functions through 3.2.
/// Contains only static names and presence states; no native addresses.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct FunctionCatalog([FunctionPresence; 104]);

// Lists follow the pinned OASIS function order. Each extension appends to its
// exact preceding layout; field accesses are checked by the Rust compiler.
macro_rules! fields_240 {
    ($callback:ident, $table:expr $(, $tail:ident)* $(,)?) => {
        $callback!($table,
            C_Initialize,
            C_Finalize,
            C_GetInfo,
            C_GetFunctionList,
            C_GetSlotList,
            C_GetSlotInfo,
            C_GetTokenInfo,
            C_GetMechanismList,
            C_GetMechanismInfo,
            C_InitToken,
            C_InitPIN,
            C_SetPIN,
            C_OpenSession,
            C_CloseSession,
            C_CloseAllSessions,
            C_GetSessionInfo,
            C_GetOperationState,
            C_SetOperationState,
            C_Login,
            C_Logout,
            C_CreateObject,
            C_CopyObject,
            C_DestroyObject,
            C_GetObjectSize,
            C_GetAttributeValue,
            C_SetAttributeValue,
            C_FindObjectsInit,
            C_FindObjects,
            C_FindObjectsFinal,
            C_EncryptInit,
            C_Encrypt,
            C_EncryptUpdate,
            C_EncryptFinal,
            C_DecryptInit,
            C_Decrypt,
            C_DecryptUpdate,
            C_DecryptFinal,
            C_DigestInit,
            C_Digest,
            C_DigestUpdate,
            C_DigestKey,
            C_DigestFinal,
            C_SignInit,
            C_Sign,
            C_SignUpdate,
            C_SignFinal,
            C_SignRecoverInit,
            C_SignRecover,
            C_VerifyInit,
            C_Verify,
            C_VerifyUpdate,
            C_VerifyFinal,
            C_VerifyRecoverInit,
            C_VerifyRecover,
            C_DigestEncryptUpdate,
            C_DecryptDigestUpdate,
            C_SignEncryptUpdate,
            C_DecryptVerifyUpdate,
            C_GenerateKey,
            C_GenerateKeyPair,
            C_WrapKey,
            C_UnwrapKey,
            C_DeriveKey,
            C_SeedRandom,
            C_GenerateRandom,
            C_GetFunctionStatus,
            C_CancelFunction,
            C_WaitForSlotEvent,
            $($tail),*
        )
    };
}

macro_rules! fields_30 {
    ($callback:ident, $table:expr $(, $tail:ident)* $(,)?) => {
        fields_240!($callback, $table,
            C_GetInterfaceList,
            C_GetInterface,
            C_LoginUser,
            C_SessionCancel,
            C_MessageEncryptInit,
            C_EncryptMessage,
            C_EncryptMessageBegin,
            C_EncryptMessageNext,
            C_MessageEncryptFinal,
            C_MessageDecryptInit,
            C_DecryptMessage,
            C_DecryptMessageBegin,
            C_DecryptMessageNext,
            C_MessageDecryptFinal,
            C_MessageSignInit,
            C_SignMessage,
            C_SignMessageBegin,
            C_SignMessageNext,
            C_MessageSignFinal,
            C_MessageVerifyInit,
            C_VerifyMessage,
            C_VerifyMessageBegin,
            C_VerifyMessageNext,
            C_MessageVerifyFinal,
            $($tail),*
        )
    };
}

macro_rules! fields_32 {
    ($callback:ident, $table:expr $(, $tail:ident)* $(,)?) => {
        fields_30!($callback, $table,
            C_EncapsulateKey,
            C_DecapsulateKey,
            C_VerifySignatureInit,
            C_VerifySignature,
            C_VerifySignatureUpdate,
            C_VerifySignatureFinal,
            C_GetSessionValidationFlags,
            C_AsyncComplete,
            C_AsyncGetID,
            C_AsyncJoin,
            C_WrapKeyAuthenticated,
            C_UnwrapKeyAuthenticated,
            $($tail),*
        )
    };
}

macro_rules! names {
    ($unused:expr, $($field:ident),* $(,)?) => {
        [$(stringify!($field)),*]
    };
}

const FUNCTION_NAMES: [&str; 104] = fields_32!(names, ());

macro_rules! observe {
    ($table:expr, $($field:ident),* $(,)?) => {{
        let table = $table;
        FunctionCatalog::from_presence([$({
            // Copy first: the selected Windows ABI table may be packed.
            // Option::is_some borrows its receiver, which must be aligned.
            let function = table.$field;
            function.is_some()
        }),*])
    }};
}

impl FunctionCatalog {
    /// Observe one exact standard name, without calling native code. Unknown
    /// names return None; a known function outside the selected layout has its
    /// own explicit state.
    pub fn observation(&self, name: &str) -> Option<FunctionPresence> {
        FUNCTION_NAMES
            .iter()
            .position(|candidate| *candidate == name)
            .map(|index| self.0[index])
    }

    /// Iterate the 104 standard names in normative table order and their states.
    pub fn observations(
        &self,
    ) -> impl ExactSizeIterator<Item = (&'static str, FunctionPresence)> + '_ {
        FUNCTION_NAMES.iter().copied().zip(self.0.iter().copied())
    }

    fn from_presence<const N: usize>(present: [bool; N]) -> Self {
        assert!(matches!(N, 68 | 92 | 104));
        let mut states = [FunctionPresence::OutsideSelectedInterface; 104];
        for (state, present) in states.iter_mut().zip(present) {
            *state = if present {
                FunctionPresence::Present
            } else {
                FunctionPresence::Null
            };
        }
        Self(states)
    }
}

impl SelectedTable {
    pub(crate) fn catalog(&self) -> FunctionCatalog {
        match self {
            Self::V240(table) => fields_240!(observe, table),
            Self::V30Or31(table) => fields_30!(observe, table),
            Self::V32(table) => fields_32!(observe, table),
        }
    }
}
