// SPDX-License-Identifier: Apache-2.0
/// Explicit PKCS#11 CKA_PRIVATE value, independent of the object's class.
/// A public key can require USER authentication for access to its native object.
/// This does not revoke public key bytes already held by the caller.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ObjectVisibility {
    /// CKA_PRIVATE=false; object access does not require USER authentication.
    Public,
    /// CKA_PRIVATE=true; object access requires USER authentication.
    Private,
}

impl ObjectVisibility {
    pub(crate) fn is_private(self) -> bool {
        match self {
            Self::Public => false,
            Self::Private => true,
        }
    }
}
