// SPDX-License-Identifier: Apache-2.0
//! Separate ownership for private C_CreateObject components; never public Template bytes.

use crate::Error;
use crate::{
    attributes::Template,
    bounds,
    symmetric::memory::{Buffer, Credit},
    Result,
};
use fe11_sys::*;

mod preparation;
pub(crate) use preparation::NativeSecretStorage;

fn private_field(kind: CK_ATTRIBUTE_TYPE) -> bool {
    matches!(
        kind,
        CKA_SEED
            | CKA_VALUE
            | CKA_PRIVATE_EXPONENT
            | CKA_PRIME_1
            | CKA_PRIME_2
            | CKA_EXPONENT_1
            | CKA_EXPONENT_2
            | CKA_COEFFICIENT
    )
}

pub(crate) struct SecretTemplate {
    _public: Template,
    components: Vec<(CK_ATTRIBUTE_TYPE, Buffer)>,
    _descriptor_credit: Credit,
}
pub(crate) struct NativeSecretTemplate {
    inner: SecretTemplate,
    native: Vec<CK_ATTRIBUTE>,
    expected: Vec<(CK_ATTRIBUTE_TYPE, CK_VOID_PTR, CK_ULONG)>,
    public_witness: Template,
    secret_witnesses: Vec<Buffer>,
    _credit: Credit,
}
// SAFETY: every native pointer addresses the inner owner's heap allocations.
// Moving this value does not move any referent, and no native pointer refers to
// the witnesses. The enclosing NativeFrame retains this complete value.
unsafe impl Send for NativeSecretTemplate {}
impl NativeSecretTemplate {
    pub(crate) fn count(&self) -> Result<CK_ULONG> {
        bounds::ck_length(self.native.len())
    }
    pub(crate) fn as_mut_ptr(&mut self) -> *mut CK_ATTRIBUTE {
        self.native.as_mut_ptr()
    }
    pub(crate) fn unchanged(&self) -> bool {
        use crypto_bigint::subtle::{Choice, ConstantTimeEq};
        let mut secret_equal = Choice::from(1);
        for ((_, component), witness) in self.inner.components.iter().zip(&self.secret_witnesses) {
            secret_equal &= component.as_slice().ct_eq(witness.as_slice());
        }
        bool::from(secret_equal)
            && self.inner.components.len() == self.secret_witnesses.len()
            && self.inner._public.same_values(&self.public_witness)
            && self.native.len() == self.expected.len()
            && self
                .native
                .iter()
                .zip(&self.expected)
                .all(|(a, e)| (a.r#type, a.pValue, a.ulValueLen) == *e)
    }
}
