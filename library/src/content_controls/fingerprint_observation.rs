// SPDX-License-Identifier: Apache-2.0
//! Pure stages of the caller-selected public fingerprint format.
//!
//! Native observation and resource admission belong to the surrounding owner.
//! Class/type rereads detect observed changes, not external ABA replacement.
use super::*;
use attributes::FingerprintAttribute as Public;
pub(crate) mod resident;

pub(super) const FINGERPRINT_HEADER: [Public; 2] = [Public::Class, Public::KeyType];

// Domain separation is part of the fingerprint encoding, followed by the
// big-endian key type and the selected public fields. Keep these exact bytes:
// changing a label must not silently change an existing object's fingerprint.
const FINGERPRINT_DOMAIN: &[u8] = &[
    0x42, 0x65, 0x61, 0x76, 0x65, 0x72, 0x50, 0x4b, 0x49, 0x2d, 0x6d, 0x61, 0x6e, 0x61, 0x67, 0x65,
    0x64, 0x2d, 0x70, 0x75, 0x62, 0x6c, 0x69, 0x63, 0x2d, 0x76, 0x31,
];

/// Borrows completed native allocations whose resource credits remain owned.
pub(super) trait Values {
    fn len(&self) -> usize;
    fn bytes(&self, index: usize) -> Result<std::result::Result<&[u8], AttributeUnavailableCause>>;
}
impl Values for attributes::owned::resident::FingerprintValues<'_> {
    fn len(&self) -> usize {
        self.len()
    }
    fn bytes(&self, index: usize) -> Result<std::result::Result<&[u8], AttributeUnavailableCause>> {
        self.get(index)
    }
}

fn observed_bytes(
    values: &impl Values,
    index: usize,
    field: CK_ATTRIBUTE_TYPE,
) -> Result<std::result::Result<&[u8], ProtectedContent>> {
    Ok(values
        .bytes(index)?
        .map_err(|cause| unavailable(field, cause)))
}

pub(super) enum Step<T> {
    Continue(T),
    Complete(ProtectedContent),
}
pub(super) struct Header {
    class: [u8; std::mem::size_of::<CK_ULONG>()],
    kind: [u8; std::mem::size_of::<CK_ULONG>()],
    pub(super) kind_value: CK_ULONG,
    pub(super) remaining: usize,
}
pub(super) fn material(kind: CK_ULONG) -> (&'static [Public], bool) {
    match kind {
        CKK_RSA => (&[Public::Modulus, Public::PublicExponent], false),
        CKK_DSA => (&[Public::Prime, Public::Subprime, Public::Base], true),
        CKK_EC | CKK_EC_EDWARDS | CKK_EC_MONTGOMERY => {
            (&[Public::EcParams, Public::EcPoint], false)
        }
        CKK_ML_KEM | CKK_ML_DSA | CKK_SLH_DSA => (&[Public::ParameterSet], true),
        _ => (&[Public::PublicKeyInfo], false),
    }
}
impl Header {
    pub(super) fn from_values(values: impl Values, maximum: usize) -> Result<Step<Self>> {
        if values.len() != FINGERPRINT_HEADER.len() {
            return Err(Error::Rejected(crate::RejectionReason::ObjectContent(
                crate::ObjectContentRejection::FingerprintHeaderCount,
            )));
        }
        let class = match observed_bytes(&values, 0, CKA_CLASS)? {
            Ok(bytes) => bytes,
            Err(status) => return Ok(Step::Complete(status)),
        };
        let class_value = match class.try_into() {
            Ok(bytes) => CK_ULONG::from_ne_bytes(bytes),
            Err(_) => {
                return Ok(Step::Complete(unusable(
                    CKA_CLASS,
                    ContentIssue::IntegerEncoding,
                )))
            }
        };
        if class_value != CKO_PUBLIC_KEY {
            return Ok(Step::Complete(unusable(
                CKA_CLASS,
                ContentIssue::NotPublicKey,
            )));
        }
        let kind = match observed_bytes(&values, 1, CKA_KEY_TYPE)? {
            Ok(bytes) => bytes,
            Err(status) => return Ok(Step::Complete(status)),
        };
        let kind_value = match kind.try_into() {
            Ok(bytes) => CK_ULONG::from_ne_bytes(bytes),
            Err(_) => {
                return Ok(Step::Complete(unusable(
                    CKA_KEY_TYPE,
                    ContentIssue::IntegerEncoding,
                )))
            }
        };
        let remaining = maximum
            .checked_sub(class.len())
            .and_then(|n| n.checked_sub(kind.len()))
            .ok_or(Error::Rejected(crate::RejectionReason::ObjectContent(
                crate::ObjectContentRejection::FingerprintByteBudget,
            )))?;
        Ok(Step::Continue(Self {
            class: class_value.to_ne_bytes(),
            kind: kind_value.to_ne_bytes(),
            kind_value,
            remaining,
        }))
    }
}
pub(super) struct DigestState {
    header: Header,
    digest: ProtectedFingerprintHash,
    pub(super) remaining: usize,
}
impl DigestState {
    pub(super) fn from_material_with_digest(
        header: Header,
        values: impl Values,
        mut digest: ProtectedFingerprintHash,
    ) -> Result<Step<Self>> {
        let (fields, _) = material(header.kind_value);
        if values.len() != fields.len() {
            return Err(Error::Rejected(crate::RejectionReason::ObjectContent(
                crate::ObjectContentRejection::FingerprintMaterialCount,
            )));
        }
        let mut remaining = header.remaining;
        digest.update(FINGERPRINT_DOMAIN);
        digest.update((header.kind_value as u64).to_be_bytes());
        for (index, &field) in fields.iter().enumerate() {
            let raw = field.raw();
            let bytes = match observed_bytes(&values, index, raw)? {
                Ok(bytes) => bytes,
                Err(status) => return Ok(Step::Complete(status)),
            };
            remaining = remaining.checked_sub(bytes.len()).ok_or(Error::Rejected(
                crate::RejectionReason::ObjectContent(
                    crate::ObjectContentRejection::FingerprintByteBudget,
                ),
            ))?;
            if bytes.is_empty() {
                return Ok(Step::Complete(unusable(
                    raw,
                    ContentIssue::EmptyPublicMaterial,
                )));
            }
            let normalized;
            let material = if raw == CKA_PARAMETER_SET {
                normalized = match bytes.try_into() {
                    Ok(bytes) => (CK_ULONG::from_ne_bytes(bytes) as u64).to_be_bytes(),
                    Err(_) => {
                        return Ok(Step::Complete(unusable(raw, ContentIssue::IntegerEncoding)))
                    }
                };
                normalized.as_slice()
            } else {
                bytes
            };
            digest.update((raw as u64).to_be_bytes());
            digest.update((material.len() as u64).to_be_bytes());
            digest.update(material);
        }
        Ok(Step::Continue(Self {
            header,
            digest,
            remaining,
        }))
    }
    pub(super) fn has_value(&self) -> bool {
        material(self.header.kind_value).1
    }
    pub(super) fn accept_value(mut self, observed: ProtectedContent) -> Result<Step<Self>> {
        let bytes = match observed {
            ProtectedContent::Available(bytes) => bytes,
            status => return Ok(Step::Complete(status)),
        };
        self.remaining = self
            .remaining
            .checked_sub(bytes.len())
            .ok_or(Error::Rejected(crate::RejectionReason::ObjectContent(
                crate::ObjectContentRejection::FingerprintByteBudget,
            )))?;
        if bytes.is_empty() {
            return Ok(Step::Complete(unusable(
                CKA_VALUE,
                ContentIssue::EmptyPublicMaterial,
            )));
        }
        self.digest.update((CKA_VALUE as u64).to_be_bytes());
        self.digest.update((bytes.len() as u64).to_be_bytes());
        self.digest.update(bytes.as_slice());
        Ok(Step::Continue(self))
    }
    pub(super) fn finish(mut self, values: impl Values) -> Result<ProtectedContent> {
        if values.len() != FINGERPRINT_HEADER.len() {
            return Err(Error::Rejected(crate::RejectionReason::ObjectContent(
                crate::ObjectContentRejection::FingerprintHeaderCount,
            )));
        }
        for (index, (field, expected)) in [
            (CKA_CLASS, self.header.class.as_slice()),
            (CKA_KEY_TYPE, self.header.kind.as_slice()),
        ]
        .into_iter()
        .enumerate()
        {
            let bytes = match observed_bytes(&values, index, field)? {
                Ok(bytes) => bytes,
                Err(status) => return Ok(status),
            };
            if bytes != expected {
                return Ok(unusable(field, ContentIssue::ObjectChanged));
            }
        }
        Ok(ProtectedContent::Available(self.digest.finish()?))
    }
}
