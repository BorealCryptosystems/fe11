// SPDX-License-Identifier: Apache-2.0
//! Explicit native usage requests, independent of observations and comparisons.
use fe11_sys::*;

/// Each Some(value) emits that exact native boolean; None explicitly omits it.
/// The module decides whether the attribute applies to the requested key class.
/// No readback or permission guarantee follows from a creation request.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct KeyUsageRequest {
    /// Native CKA_ENCRYPT request.
    pub encrypt: Option<bool>,
    /// Native CKA_DECRYPT request.
    pub decrypt: Option<bool>,
    /// Native CKA_SIGN request.
    pub sign: Option<bool>,
    /// Native CKA_VERIFY request.
    pub verify: Option<bool>,
    /// Native CKA_SIGN_RECOVER request.
    pub sign_recover: Option<bool>,
    /// Native CKA_VERIFY_RECOVER request.
    pub verify_recover: Option<bool>,
    /// Native CKA_WRAP request.
    pub wrap: Option<bool>,
    /// Native CKA_UNWRAP request.
    pub unwrap: Option<bool>,
    /// Native CKA_DERIVE request.
    pub derive: Option<bool>,
    /// Native CKA_ENCAPSULATE request.
    pub encapsulate: Option<bool>,
    /// Native CKA_DECAPSULATE request.
    pub decapsulate: Option<bool>,
    /// Native CKA_TRUSTED request.
    pub trusted: Option<bool>,
    /// Native CKA_WRAP_WITH_TRUSTED request.
    pub wrap_with_trusted: Option<bool>,
    /// Native CKA_ALWAYS_AUTHENTICATE request.
    pub always_authenticate: Option<bool>,
}
impl KeyUsageRequest {
    /// Explicitly omit all native usage attributes. This is not a library default.
    pub const fn omitted() -> Self {
        Self {
            encrypt: None,
            decrypt: None,
            sign: None,
            verify: None,
            sign_recover: None,
            verify_recover: None,
            wrap: None,
            unwrap: None,
            derive: None,
            encapsulate: None,
            decapsulate: None,
            trusted: None,
            wrap_with_trusted: None,
            always_authenticate: None,
        }
    }
    pub(crate) fn apply(self, template: &mut impl crate::attributes::TemplateSink) {
        for (attribute, request) in [
            (CKA_ENCRYPT, self.encrypt),
            (CKA_DECRYPT, self.decrypt),
            (CKA_SIGN, self.sign),
            (CKA_VERIFY, self.verify),
            (CKA_SIGN_RECOVER, self.sign_recover),
            (CKA_VERIFY_RECOVER, self.verify_recover),
            (CKA_WRAP, self.wrap),
            (CKA_UNWRAP, self.unwrap),
            (CKA_DERIVE, self.derive),
            (CKA_ENCAPSULATE, self.encapsulate),
            (CKA_DECAPSULATE, self.decapsulate),
            (CKA_TRUSTED, self.trusted),
            (CKA_WRAP_WITH_TRUSTED, self.wrap_with_trusted),
            (CKA_ALWAYS_AUTHENTICATE, self.always_authenticate),
        ] {
            if let Some(value) = request {
                template.boolean(attribute, value);
            }
        }
    }
}
