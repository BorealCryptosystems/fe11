// SPDX-License-Identifier: Apache-2.0
use fe11::*;
use std::num::NonZeroUsize;

/// Search all private RSA objects with an exact application-supplied CKA_ID.
pub fn find_private_rsa(
    session: &Session, id: &[u8], batch_size: NonZeroUsize,
    maximum_objects: Option<usize>, template_limits: AttributeTemplateLimits,
) -> Result<NativeObjectMatches> {
    let template = [
        AttributeInput {
            attribute: AttributeType::Standard(StandardAttribute::CLASS),
            value: AttributeInputValue::Unsigned(fe11_sys::CKO_PRIVATE_KEY as u64),
        },
        AttributeInput {
            attribute: AttributeType::Standard(StandardAttribute::KEY_TYPE),
            value: AttributeInputValue::Unsigned(fe11_sys::CKK_RSA as u64),
        },
        AttributeInput {
            attribute: AttributeType::Standard(StandardAttribute::ID),
            value: AttributeInputValue::Bytes(id),
        },
    ];
    session.find_native_objects(
        &template,
        template_limits,
        SearchPlan { maximum_objects, batch_size },
    )
}

/// Preserve native objects and the independent descriptive result.
pub fn generate_rsa(
    session: &Session, mut spec: KeySpec,
) -> Result<CreatedObjects<KeyPair>> {
    spec.public_usages.verify = Some(true);
    spec.private_usages.sign = Some(true);
    session.generate_rsa_signing_key_pair(spec)
}
