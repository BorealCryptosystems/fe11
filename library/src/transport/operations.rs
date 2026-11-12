// SPDX-License-Identifier: Apache-2.0
use super::*;
use crate::{
    attributes::Template, bounds, error::check, managed, module::State,
    native_return::MutationCall, symmetric::memory::Buffer, ManagedClass, Session,
};
use fe11_sys::*;
use std::sync::Arc;

mod preparation;
mod resolved;
use preparation::TransportStorage;

fn wrap_output_capacity(required: CK_ULONG, capacity: usize) -> Result<CK_ULONG> {
    usize::try_from(required).map_err(|_| {
        Error::Rejected(crate::RejectionReason::KeyTransport(
            crate::KeyTransportRejection::WrappingSizeRepresentation,
        ))
    })?;
    // Validate the queried size without shrinking the buffer already reserved.
    // Advertise its actual writable capacity; an insufficient caller limit
    // still gets the native refusal, without a retry or a larger allocation.
    bounds::ck_length(capacity)
}
/// Explicit protected-wrapping profile; no PAD or alternate-mechanism fallback.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum WrapParameters<'a> {
    /// CKM_AES_KEY_WRAP with the normative default IV (NULL, length zero).
    AesKw,
    /// CKM_AES_KEY_WRAP_KWP with the normative default IV (NULL, length zero).
    AesKwp,
    /// RSA-OAEP with exact caller-selected hash, MGF and binary label.
    RsaOaep {
        /// Exact PKCS#11 hash mechanism identifier; native support is not inferred.
        hash: u64,
        /// Exact PKCS#11 mask generation identifier, independent of the hash.
        mgf: u64,
        /// Public context bound by OAEP; the empty label is explicitly permitted.
        label: &'a [u8],
    },
    /// Exact PKCS11 3.2 authenticated AES-GCM route, with an explicitly sized detached tag.
    AuthenticatedGcm {
        /// Explicit caller-provided or native-generated IV and complete GCM parameters.
        nonce: crate::AeadNonce,
        /// Authenticated public context; copied into budgeted owned storage.
        aad: &'a [u8],
    },
}
/// Explicit decoding profile for an untrusted envelope.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum UnwrapParameters<'a> {
    /// CKM_AES_KEY_WRAP; does not infer the mechanism from envelope bytes.
    AesKw,
    /// CKM_AES_KEY_WRAP_KWP; does not try another mechanism on refusal.
    AesKwp,
    /// RSA-OAEP with exact caller-selected hash, MGF and binary label.
    RsaOaep {
        /// Exact PKCS#11 hash mechanism identifier; native support is not inferred.
        hash: u64,
        /// Exact PKCS#11 mask generation identifier, independent of the hash.
        mgf: u64,
        /// Public context bound by OAEP; the empty label is explicitly permitted.
        label: &'a [u8],
    },
    /// Exact authenticated 3.2 route; no tag is inferred from ciphertext bytes.
    AuthenticatedGcm {
        /// Exact IV and tag-bit selection from the envelope; no generation.
        nonce: crate::AeadNonce,
        /// Exactly ceil(tag_bits / 8) detached authentication bytes.
        tag: &'a [u8],
        /// Authenticated public context supplied by the caller.
        aad: &'a [u8],
    },
}
/// Mechanism used by a successful protected wrapping operation.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum KeyWrapProfile {
    /// Native AES Key Wrap (RFC3394); the module validates the operands.
    AesKw,
    /// AES Key Wrap with Padding, RFC5649.
    AesKwp,
    /// RSA-OAEP with caller-selected hash, MGF and explicit label.
    RsaOaep,
    /// PKCS11 3.2 authenticated AES-GCM, detached nonce/tag.
    AuthenticatedGcm,
}
impl KeyWrapProfile {
    fn raw(self) -> CK_MECHANISM_TYPE {
        match self {
            Self::AesKw => CKM_AES_KEY_WRAP,
            Self::AesKwp => CKM_AES_KEY_WRAP_KWP,
            Self::RsaOaep => CKM_RSA_PKCS_OAEP,
            Self::AuthenticatedGcm => CKM_AES_GCM,
        }
    }
}
impl WrapParameters<'_> {
    fn profile(&self) -> KeyWrapProfile {
        match self {
            Self::AesKw => KeyWrapProfile::AesKw,
            Self::AesKwp => KeyWrapProfile::AesKwp,
            Self::RsaOaep { .. } => KeyWrapProfile::RsaOaep,
            Self::AuthenticatedGcm { .. } => KeyWrapProfile::AuthenticatedGcm,
        }
    }
}
impl UnwrapParameters<'_> {
    fn profile(&self) -> KeyWrapProfile {
        match self {
            Self::AesKw => KeyWrapProfile::AesKw,
            Self::AesKwp => KeyWrapProfile::AesKwp,
            Self::RsaOaep { .. } => KeyWrapProfile::RsaOaep,
            Self::AuthenticatedGcm { .. } => KeyWrapProfile::AuthenticatedGcm,
        }
    }
}
/// Preallocated output bound; a refusal never triggers automatic resizing/retry.
#[derive(Clone, Copy, Debug)]
pub struct WrapLimits {
    /// Caller-selected output capacity, charged until the result is dropped.
    pub maximum_output_bytes: usize,
}
impl WrapLimits {
    fn validate(self) -> Result<usize> {
        bounds::ck_length(self.maximum_output_bytes)?;
        Ok(self.maximum_output_bytes)
    }
}
#[doc = include_str!("../../docs/api/transport/operations/WrappedKey.md")]
pub struct WrappedKey {
    bytes: Buffer,
    profile: KeyWrapProfile,
    authenticated: Option<super::authenticated::GcmBuffers>,
    oaep: Option<super::oaep::OaepBuffer>,
    _metadata: crate::symmetric::memory::Credit,
}
impl WrappedKey {
    /// Borrow the encrypted bytes; no native key value is exposed.
    pub fn as_bytes(&self) -> &[u8] {
        self.bytes.as_slice()
    }
    /// Exact selected profile, without any provider-dependent interpretation.
    pub fn profile(&self) -> KeyWrapProfile {
        self.profile
    }
    /// Exact OAEP label retained with this envelope, including an explicitly empty label.
    pub fn oaep_label(&self) -> Option<&[u8]> {
        self.oaep.as_ref().map(|p| p.label())
    }
    /// Exact OAEP hash, MGF and label used for this envelope, when selected.
    /// Native acceptance does not attest a normative application profile.
    pub fn oaep_parameters(&self) -> Option<crate::OaepParams<'_>> {
        self.oaep.as_ref().map(|owner| owner.selection())
    }

    /// Actual nonce, only for authenticated wrapping; uniqueness remains caller policy.
    pub fn nonce(&self) -> Option<&[u8]> {
        self.authenticated.as_ref().map(|g| g.nonce())
    }
    /// Requested nonce origin, separate from the actual returned nonce bytes.
    pub fn nonce_origin(&self) -> Option<crate::AeadNonce> {
        self.authenticated.as_ref().map(|g| g.origin())
    }
    /// Complete detached tag; it is never implicitly appended to the ciphertext.
    pub fn tag(&self) -> Option<&[u8]> {
        self.authenticated.as_ref().map(|g| g.tag())
    }
    /// Authenticated context retained with the successful envelope.
    pub fn associated_data(&self) -> Option<&[u8]> {
        self.authenticated.as_ref().map(|g| g.aad())
    }
}

// Repeat native identity checks under the same guards before and after transport.
// Dispatch binds the owned handle/context. Optional metadata comparisons are
// available through observe_managed_reference and are never inferred here.
pub(super) fn bound(
    s: &State,
    session: &Session,
    key: &ManagedObjectRef,
    h: CK_OBJECT_HANDLE,
) -> Result<()> {
    // Visibility and persistence are not key identity. Their optional
    // admission observations do not create implicit transport controls.
    // Recheck local ownership/lifetime even when this binding is called alone.
    if session.managed_handle(s, key)? != h {
        return Err(Error::Rejected(crate::RejectionReason::KeyTransport(
            crate::KeyTransportRejection::TransportHandleBinding,
        )));
    }
    Ok(())
}

fn mechanism(profile: KeyWrapProfile) -> CK_MECHANISM {
    CK_MECHANISM {
        mechanism: profile.raw(),
        pParameter: std::ptr::null_mut(),
        ulParameterLen: 0,
    }
}
fn unchanged(m: &CK_MECHANISM, p: KeyWrapProfile) -> bool {
    m.mechanism == p.raw() && m.pParameter.is_null() && m.ulParameterLen == 0
}

// Owned native parameter alternatives; descriptors are part of the retained
// frame, while their byte referents are held by the corresponding buffers.
enum TransportInputs {
    Standard,
    Oaep {
        buffers: super::oaep::OaepBuffer,
        parameters: CK_RSA_PKCS_OAEP_PARAMS,
    },
    AuthenticatedGcm {
        buffers: super::authenticated::GcmBuffers,
        parameters: CK_GCM_MESSAGE_PARAMS,
        aad: CK_BYTE_PTR,
        aad_len: CK_ULONG,
    },
}
impl TransportInputs {
    fn validate_unwrap(selection: &UnwrapParameters<'_>) -> Result<MutationCall> {
        match selection {
            UnwrapParameters::AesKw | UnwrapParameters::AesKwp => {}
            UnwrapParameters::RsaOaep { label, hash, mgf } => {
                crate::bounds::ck_length(label.len())?;
                CK_MECHANISM_TYPE::try_from(*hash).map_err(|_| {
                    Error::Rejected(crate::RejectionReason::KeyTransport(
                        crate::KeyTransportRejection::OaepHashIdentifierWidth,
                    ))
                })?;
                CK_RSA_PKCS_MGF_TYPE::try_from(*mgf).map_err(|_| {
                    Error::Rejected(crate::RejectionReason::KeyTransport(
                        crate::KeyTransportRejection::OaepMgfIdentifierWidth,
                    ))
                })?;
            }
            UnwrapParameters::AuthenticatedGcm { nonce, tag, aad } => {
                nonce.validate_gcm_message_encrypt(aad.len())?;
                if tag.len() != nonce.tag_bytes()? || nonce.generated() {
                    return Err(Error::Rejected(crate::RejectionReason::KeyTransport(
                        crate::KeyTransportRejection::AuthenticatedUnwrapParameters,
                    )));
                }
                return Ok(MutationCall::UnwrapAuthenticated);
            }
        }
        Ok(MutationCall::Unwrap)
    }

    fn aad(&self) -> Option<(CK_BYTE_PTR, CK_ULONG)> {
        match self {
            Self::AuthenticatedGcm { aad, aad_len, .. } => Some((*aad, *aad_len)),
            _ => None,
        }
    }
    fn unchanged_wrap(
        &self,
        m: &CK_MECHANISM,
        pointer: CK_VOID_PTR,
        selection: &WrapParameters<'_>,
    ) -> bool {
        match (self, selection) {
            (Self::Standard, WrapParameters::AesKw | WrapParameters::AesKwp) => {
                unchanged(m, selection.profile())
            }
            (
                Self::Oaep {
                    buffers,
                    parameters,
                },
                WrapParameters::RsaOaep { label, .. },
            ) => buffers.unchanged(parameters, m, pointer, label),
            (
                Self::AuthenticatedGcm {
                    buffers,
                    parameters,
                    ..
                },
                WrapParameters::AuthenticatedGcm { aad, .. },
            ) => buffers.unchanged(parameters, m, pointer, aad),
            _ => false,
        }
    }
    // Called only after the owner has reached its stable CallData address.
    fn mechanism(&mut self, profile: KeyWrapProfile) -> CK_MECHANISM {
        let mut m = mechanism(profile);
        match self {
            Self::Standard => {}
            Self::Oaep { parameters, .. } => {
                m.pParameter = (parameters as *mut CK_RSA_PKCS_OAEP_PARAMS).cast();
                m.ulParameterLen = std::mem::size_of::<CK_RSA_PKCS_OAEP_PARAMS>() as _;
            }
            Self::AuthenticatedGcm { parameters, .. } => {
                m.pParameter = (parameters as *mut CK_GCM_MESSAGE_PARAMS).cast();
                m.ulParameterLen = std::mem::size_of::<CK_GCM_MESSAGE_PARAMS>() as _;
            }
        }
        m
    }
    fn unchanged(
        &self,
        m: &CK_MECHANISM,
        pointer: CK_VOID_PTR,
        selection: &UnwrapParameters<'_>,
    ) -> bool {
        match (self, selection) {
            (Self::Standard, UnwrapParameters::AesKw | UnwrapParameters::AesKwp) => {
                unchanged(m, selection.profile())
            }
            (
                Self::Oaep {
                    buffers,
                    parameters,
                },
                UnwrapParameters::RsaOaep { label, .. },
            ) => buffers.unchanged(parameters, m, pointer, label),
            (
                Self::AuthenticatedGcm {
                    buffers,
                    parameters,
                    ..
                },
                UnwrapParameters::AuthenticatedGcm { aad, .. },
            ) => buffers.unchanged(parameters, m, pointer, aad),
            _ => false,
        }
    }
}
#[derive(Clone, Copy)]
enum WrapPhase {
    Size,
    Output,
}
struct WrapCall {
    inputs: TransportInputs,
    mechanism: CK_MECHANISM,
    bytes: Buffer,
    length: CK_ULONG,
    _credit: crate::symmetric::memory::Credit,
}
// SAFETY: native pointers address owned buffers or descriptors inside stable
// CallData. No borrowed source or native-exposed allocation is resized.
unsafe impl Send for WrapCall {}
pub(crate) struct UnwrapCall {
    inputs: TransportInputs,
    template: crate::attributes::OwnedTemplate,
    input: Buffer,
    mechanism: CK_MECHANISM,
    output: CK_OBJECT_HANDLE,
    _credit: crate::symmetric::memory::Credit,
}
// SAFETY: all referents are owned. The mechanism is bound to the parameter
// alternative only in stable CallData; no native-exposed allocation resizes.
unsafe impl Send for UnwrapCall {}

enum Destination<'a> {
    Symmetric(SymmetricIntroductionSpec),
    AesKek(AesKeyEncryptionSpec),
    Signing(crate::crypto::PreparedSigningRestore<'a>),
    Rsa(super::rsa::PreparedRsaRestore<'a>),
    Agreement(crate::crypto::derivation::PreparedAgreementRestore),
}
impl Destination<'_> {
    fn with_observation<T>(
        &self,
        f: impl FnOnce(managed::restoration::Plan<'_>) -> Result<T>,
    ) -> Result<T> {
        use crate::crypto::key_evidence::{Introduction, Order, Spec};
        let (key, observation, order) = match self {
            Self::Signing(prepared) => return prepared.with_observation(f),
            Self::Rsa(prepared) => return prepared.with_observation(f),
            Self::Agreement(prepared) => return prepared.with_observation(f),
            Self::Symmetric(spec) => (
                &spec.key,
                spec.history_observation,
                Order::MechanismsThenHistory,
            ),
            Self::AesKek(spec) => (
                &spec.key,
                spec.history_observation,
                Order::HistoryThenMechanisms,
            ),
        };
        let identity = [
            (CKA_CLASS, CKO_SECRET_KEY),
            (CKA_KEY_TYPE, key.algorithm.key_type(key.hmac_key_type)?),
        ];
        f(managed::restoration::Plan::Key(Spec {
            order,
            introduction: Some(Introduction {
                origin: IntroductionOrigin::Unwrapped,
            }),
            identity: &identity,
            maximum: key.admission.metadata.maximum_bytes,
            history: observation,
            mechanisms: Some(&key.mechanisms),
        }))
    }
    fn finish_observed(
        self,
        reference: ManagedObjectRef,
        evidence: managed::restoration::KeyEvidence,
        public: crate::crypto::integer_key::PublicDer,
    ) -> Result<DestinationKey> {
        use managed::restoration::KeyEvidence;
        match (self, evidence) {
            (Self::Signing(prepared), KeyEvidence::Signing(evidence)) => prepared
                .finish_observed(reference, evidence, public)
                .map(DestinationKey::Signing),
            (Self::Rsa(prepared), KeyEvidence::Key(evidence)) => prepared
                .finish_observed(reference, evidence, public)
                .map(DestinationKey::Rsa),
            (Self::Agreement(prepared), KeyEvidence::Key(evidence)) => prepared
                .finish_observed(reference, evidence)
                .map(DestinationKey::Agreement),
            (Self::Symmetric(spec), KeyEvidence::Key(evidence)) => {
                Ok(DestinationKey::Symmetric(secret_keys::finish(
                    reference,
                    &spec,
                    evidence.introduction.ok_or(Error::Rejected(
                        crate::RejectionReason::KeyTransport(
                            crate::KeyTransportRejection::RestoredHistoryReportAbsent,
                        ),
                    ))?,
                    evidence.mechanisms.ok_or(Error::Rejected(
                        crate::RejectionReason::KeyAdmission(
                            crate::KeyAdmissionRejection::SymmetricMechanismReportAbsent,
                        ),
                    ))?,
                )))
            }
            (Self::AesKek(spec), KeyEvidence::Key(evidence)) => {
                Ok(DestinationKey::AesKek(AesKeyEncryptionKey::from_parts(
                    reference,
                    spec.usage,
                    evidence.introduction.ok_or(Error::Rejected(
                        crate::RejectionReason::KeyTransport(
                            crate::KeyTransportRejection::RestoredHistoryReportAbsent,
                        ),
                    ))?,
                    evidence.mechanisms.ok_or(Error::Rejected(
                        crate::RejectionReason::KeyTransport(
                            crate::KeyTransportRejection::AesKekMechanismReportAbsent,
                        ),
                    ))?,
                )))
            }
            _ => Err(Error::Rejected(crate::RejectionReason::KeyTransport(
                crate::KeyTransportRejection::RestorationEvidenceFamilyMismatch,
            ))),
        }
    }

    fn publication_source(&self) -> Option<&[u8]> {
        match self {
            Self::Signing(prepared) => prepared.publication_source(),
            Self::Rsa(prepared) => prepared.publication_source(),
            _ => None,
        }
    }

    fn object_admission(&self) -> &crate::ObjectAdmission {
        match self {
            Self::Symmetric(spec) => &spec.key.admission,
            Self::AesKek(spec) => &spec.key.admission,
            Self::Signing(prepared) => &prepared.key().private_admission,
            Self::Rsa(prepared) => &prepared.spec.private_admission,
            Self::Agreement(prepared) => &prepared.spec.key.private_admission,
        }
    }

    fn class(&self) -> ManagedClass {
        match self {
            Self::Signing(_) | Self::Rsa(_) | Self::Agreement(_) => ManagedClass::PrivateKey,
            _ => ManagedClass::SecretKey,
        }
    }
    fn id(&self) -> &[u8] {
        match self {
            Self::Symmetric(s) => &s.key.id,
            Self::AesKek(s) => &s.key.id,
            Self::Signing(s) => &s.key().id,
            Self::Rsa(s) => &s.spec.id,
            Self::Agreement(s) => &s.spec.key.id,
        }
    }
    fn label(&self) -> &[u8] {
        match self {
            Self::Symmetric(s) => s.key.label.as_bytes(),
            Self::AesKek(s) => s.key.label.as_bytes(),
            Self::Signing(s) => s.key().label.as_bytes(),
            Self::Rsa(s) => s.spec.label.as_bytes(),
            Self::Agreement(s) => s.spec.key.label.as_bytes(),
        }
    }
    fn validate(&self) -> Result<()> {
        match self {
            Self::Symmetric(s) => s.validate(),
            Self::AesKek(s) => s.validate(),
            Self::Signing(s) => s.validate(),
            Self::Rsa(s) => s.spec.validate(),
            Self::Agreement(s) => s.validate(),
        }
    }
    // The AES key tables through PKCS#11 3.1 mark CKA_VALUE_LEN with
    // footnote 6: it must not be supplied to C_UnwrapKey (3.1, section 6.10.2).
    // Version 3.2 removes that note and defines length conflicts in section
    // 5.18.4. Use the selected function table, not CK_INFO's module version.
    // Other key types retain their length request, even under an AES KEK.
    fn unwrap_includes_value_len(&self, table_version: (u8, u8)) -> bool {
        let algorithm = match self {
            Self::Symmetric(spec) => spec.key.algorithm,
            Self::AesKek(spec) => spec.key.algorithm,
            _ => return true,
        };
        let aes = matches!(
            algorithm,
            crate::SymmetricAlgorithm::Aes128
                | crate::SymmetricAlgorithm::Aes192
                | crate::SymmetricAlgorithm::Aes256
        );
        !(aes && matches!(table_version, (2, 20 | 30 | 40) | (3, 0 | 1)))
    }

    fn template_size(&self, include_length: bool) -> Result<crate::attributes::TemplateSize> {
        match self {
            Self::Symmetric(spec) => secret_keys::template_size(spec, include_length),
            Self::AesKek(spec) => kek::template_size(spec, include_length),
            Self::Signing(spec) => Ok(spec.template_size()),
            Self::Rsa(spec) => Ok(spec.template_size()),
            Self::Agreement(spec) => Ok(spec.template_size()),
        }
    }
    fn template(&self, include_length: bool) -> Result<Template> {
        match self {
            Self::Symmetric(s) => secret_keys::template(s, include_length),
            Self::AesKek(s) => kek::template(s, include_length),
            Self::Signing(s) => Ok(s.template()),
            Self::Rsa(s) => Ok(s.template()),
            Self::Agreement(s) => Ok(s.template()),
        }
    }
}
enum DestinationKey {
    Symmetric(IntroducedSymmetricKey),
    AesKek(AesKeyEncryptionKey),
    Signing(crate::IntroducedSigningKey),
    Rsa(RsaKeyEncryptionPrivate),
    Agreement(crate::IntroducedAgreementKey),
}

mod unwrap;
mod wrap;
