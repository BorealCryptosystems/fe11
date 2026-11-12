// SPDX-License-Identifier: Apache-2.0
use super::keys::BaseSpec;
use super::*;
use crate::symmetric::memory::{Buffer, Credit, UnboundBuffer};
use crate::{attributes::Template, bounds, managed, ManagedClass, Session, SymmetricKeySpec};
use std::ptr::null_mut;

fn lengths(parts: &[usize]) -> Result<usize> {
    let n = parts.iter().try_fold(0usize, |n, v| {
        n.checked_add(*v)
            .ok_or(Error::Rejected(crate::RejectionReason::KeyDerivation(
                crate::KeyDerivationRejection::DerivationParameterOverflow,
            )))
    })?;
    bounds::ck_length(n)?;
    Ok(n)
}
fn pointer(b: &mut Buffer) -> CK_BYTE_PTR {
    if b.as_slice().is_empty() {
        null_mut()
    } else {
        b.as_mut().as_mut_ptr()
    }
}
// Weak links prevent a recovery payload from owning its module/session through
// a native key's creator. The actual activity is retained by SessionAccess.
#[derive(Clone)]
pub(super) struct SaltReference {
    inner: std::sync::Weak<crate::module::Inner>,
    identity: std::sync::Weak<managed::ManagedIdentity>,
    handle: CK_OBJECT_HANDLE,
}
impl SaltReference {
    fn from_reference(key: &ManagedObjectRef) -> Self {
        Self {
            inner: std::sync::Arc::downgrade(&key.inner),
            identity: std::sync::Arc::downgrade(&key.identity),
            handle: key.handle,
        }
    }
    fn reference(&self) -> Result<ManagedObjectRef> {
        // An internal alias preserves the exact identity, not a new admission
        // or a newly published report. Reuse the central handle validation.
        let inner =
            self.inner
                .upgrade()
                .ok_or(Error::Rejected(crate::RejectionReason::KeyDerivation(
                    crate::KeyDerivationRejection::HkdfSaltOwnerUnavailable,
                )))?;
        let identity = self.identity.upgrade().ok_or(Error::Rejected(
            crate::RejectionReason::KeyDerivation(
                crate::KeyDerivationRejection::HkdfSaltReferenceUnavailable,
            ),
        ))?;
        Ok(ManagedObjectRef {
            native: crate::NativeObjectRef {
                inner: inner.clone(),
                identity: identity.native.clone(),
                output_slot: None,
            },
            inner,
            identity,
            handle: self.handle,
            mutation_report: None,
            content_report: None,
            destination_report: None,
            search_report: None,
        })
    }
}
pub(super) enum SaltInput {
    Null,
    Data(Buffer),
    Key(SaltReference),
}
impl SaltInput {
    fn native(&mut self) -> Result<(CK_ULONG, CK_BYTE_PTR, CK_ULONG, CK_OBJECT_HANDLE)> {
        match self {
            Self::Null => Ok((CKF_HKDF_SALT_NULL, null_mut(), 0, CK_INVALID_HANDLE)),
            Self::Data(bytes) => Ok((
                CKF_HKDF_SALT_DATA,
                pointer(bytes),
                bounds::ck_length(bytes.as_slice().len())?,
                CK_INVALID_HANDLE,
            )),
            Self::Key(key) => Ok((CKF_HKDF_SALT_KEY, null_mut(), 0, key.handle)),
        }
    }
}
pub(super) enum Parameters {
    Ec {
        p: CK_ECDH1_DERIVE_PARAMS,
        point: Buffer,
        info: Buffer,
        _credit: Credit,
    },
    Hkdf {
        p: CK_HKDF_PARAMS,
        salt: SaltInput,
        info: Buffer,
        _credit: Credit,
    },
}
// Borrowed plans cross reference admission without retaining any new buffers.
pub(super) enum ParameterPlan<'a> {
    Ec {
        public: &'a [u8],
        kdf: CK_EC_KDF_TYPE,
        info: &'a [u8],
    },
    Hkdf {
        hash: CK_MECHANISM_TYPE,
        extract: CK_BBOOL,
        expand: CK_BBOOL,
        salt: HkdfSalt<'a>,
        info: &'a [u8],
    },
}
impl<'a> ParameterPlan<'a> {
    pub(super) fn ec(peer: &'a AgreementPeer, kdf: EcdhKdf, info: &'a [u8]) -> Result<Self> {
        Self::ec_public(&peer.point, kdf, info)
    }
    fn ec_public(public: &'a [u8], kdf: EcdhKdf, info: &'a [u8]) -> Result<Self> {
        let kdf = kdf.raw()?;
        lengths(&[info.len()])?;
        bounds::ck_length(public.len())?;
        Ok(Self::Ec { public, kdf, info })
    }
    fn hkdf(path: DerivationPath, salt: HkdfSalt<'a>, info: &'a [u8]) -> Result<Self> {
        let (hash, extract, expand) = path.hkdf_parameters()?;
        let salt_length = match &salt {
            HkdfSalt::Data(bytes) => bytes.len(),
            _ => 0,
        };
        lengths(&[salt_length, info.len()])?;
        Ok(Self::Hkdf {
            hash,
            extract,
            expand,
            salt,
            info,
        })
    }
    fn allocation_bytes(&self) -> Result<usize> {
        let payload = match self {
            Self::Ec { public, info, .. } => public.len().checked_add(info.len()),
            Self::Hkdf { salt, info, .. } => {
                let salt = match salt {
                    HkdfSalt::Data(bytes) => bytes.len(),
                    _ => 0,
                };
                salt.checked_add(info.len())
            }
        }
        .ok_or(Error::Rejected(crate::RejectionReason::KeyDerivation(
            crate::KeyDerivationRejection::DerivationParameterOverflow,
        )))?;
        payload
            .checked_add(std::mem::size_of::<Parameters>())
            .ok_or(Error::Rejected(crate::RejectionReason::KeyDerivation(
                crate::KeyDerivationRejection::DerivationParameterOverflow,
            )))
    }
    fn salt_reference(&self) -> Option<SaltReference> {
        match self {
            Self::Hkdf {
                salt: HkdfSalt::Key(key),
                ..
            } => Some(SaltReference::from_reference(key)),
            _ => None,
        }
    }
}

// Empty storage is measured with the template/history siblings before any
// borrowed bytes are copied. Binding never asks the budget for more credit.
enum ParameterStorage {
    Ec {
        point: UnboundBuffer,
        info: UnboundBuffer,
    },
    Hkdf {
        salt: Option<UnboundBuffer>,
        info: UnboundBuffer,
    },
}
impl ParameterStorage {
    fn allocate(plan: &ParameterPlan<'_>) -> Result<Self> {
        match plan {
            ParameterPlan::Ec { public, info, .. } => Ok(Self::Ec {
                point: UnboundBuffer::allocate(public.len())?,
                info: UnboundBuffer::allocate(info.len())?,
            }),
            ParameterPlan::Hkdf { salt, info, .. } => Ok(Self::Hkdf {
                salt: match salt {
                    HkdfSalt::Data(bytes) => Some(UnboundBuffer::allocate(bytes.len())?),
                    _ => None,
                },
                info: UnboundBuffer::allocate(info.len())?,
            }),
        }
    }
    fn allocated_bytes(&self) -> Result<usize> {
        let (primary, info) = match self {
            Self::Ec { point, info } => (point.allocated(), info.allocated()),
            Self::Hkdf { salt, info } => (
                salt.as_ref().map_or(0, UnboundBuffer::allocated),
                info.allocated(),
            ),
        };
        primary
            .checked_add(info)
            .and_then(|bytes| bytes.checked_add(std::mem::size_of::<Parameters>()))
            .ok_or(Error::Rejected(crate::RejectionReason::KeyDerivation(
                crate::KeyDerivationRejection::DerivationParameterOverflow,
            )))
    }
    fn bind(self, plan: &ParameterPlan<'_>, prepaid: &mut Credit) -> Result<Parameters> {
        let credit = prepaid.split(std::mem::size_of::<Parameters>())?;
        match (self, plan) {
            (
                Self::Ec { point, info },
                ParameterPlan::Ec {
                    public,
                    kdf,
                    info: source,
                },
            ) => {
                let mut point = point.bind(prepaid)?;
                point.as_mut().copy_from_slice(public);
                let mut info = info.bind(prepaid)?;
                info.as_mut().copy_from_slice(source);
                let p = CK_ECDH1_DERIVE_PARAMS {
                    kdf: *kdf,
                    ulSharedDataLen: bounds::ck_length(info.as_slice().len())?,
                    pSharedData: pointer(&mut info),
                    ulPublicDataLen: bounds::ck_length(point.as_slice().len())?,
                    pPublicData: pointer(&mut point),
                };
                Ok(Parameters::Ec {
                    p,
                    point,
                    info,
                    _credit: credit,
                })
            }
            (
                Self::Hkdf { salt, info },
                ParameterPlan::Hkdf {
                    hash,
                    extract,
                    expand,
                    salt: source_salt,
                    info: source,
                },
            ) => {
                let mut salt = match (salt, source_salt) {
                    (None, HkdfSalt::Null) => SaltInput::Null,
                    (None, HkdfSalt::Key(key)) => {
                        SaltInput::Key(SaltReference::from_reference(key))
                    }
                    (Some(bytes), HkdfSalt::Data(source)) => {
                        let mut bytes = bytes.bind(prepaid)?;
                        bytes.as_mut().copy_from_slice(source);
                        SaltInput::Data(bytes)
                    }
                    _ => {
                        return Err(Error::Rejected(crate::RejectionReason::KeyDerivation(
                            crate::KeyDerivationRejection::DerivationStorageRecipeMismatch,
                        )))
                    }
                };
                let (salt_type, salt_pointer, salt_length, salt_handle) = salt.native()?;
                let mut info = info.bind(prepaid)?;
                info.as_mut().copy_from_slice(source);
                let p = CK_HKDF_PARAMS {
                    bExtract: *extract,
                    bExpand: *expand,
                    prfHashMechanism: *hash,
                    ulSaltType: salt_type,
                    pSalt: salt_pointer,
                    ulSaltLen: salt_length,
                    hSaltKey: salt_handle,
                    pInfo: pointer(&mut info),
                    ulInfoLen: bounds::ck_length(info.as_slice().len())?,
                };
                Ok(Parameters::Hkdf {
                    p,
                    salt,
                    info,
                    _credit: credit,
                })
            }
            _ => Err(Error::Rejected(crate::RejectionReason::KeyDerivation(
                crate::KeyDerivationRejection::DerivationStorageRecipeMismatch,
            ))),
        }
    }
}

impl Parameters {
    fn mechanism(&mut self) -> CK_MECHANISM {
        match self {
            Self::Ec { p, .. } => CK_MECHANISM {
                mechanism: CKM_ECDH1_DERIVE,
                pParameter: (p as *mut CK_ECDH1_DERIVE_PARAMS).cast(),
                ulParameterLen: std::mem::size_of::<CK_ECDH1_DERIVE_PARAMS>() as _,
            },
            Self::Hkdf { p, .. } => CK_MECHANISM {
                mechanism: CKM_HKDF_DERIVE,
                pParameter: (p as *mut CK_HKDF_PARAMS).cast(),
                ulParameterLen: std::mem::size_of::<CK_HKDF_PARAMS>() as _,
            },
        }
    }
    fn scalars(&self) -> [u64; 10] {
        match self {
            Self::Ec { p, .. } => [
                p.kdf as u64,
                p.ulSharedDataLen as u64,
                p.pSharedData as usize as u64,
                p.ulPublicDataLen as u64,
                p.pPublicData as usize as u64,
                0,
                0,
                0,
                0,
                0,
            ],
            Self::Hkdf { p, .. } => [
                p.bExtract as u64,
                p.bExpand as u64,
                p.prfHashMechanism as u64,
                p.ulSaltType as u64,
                p.pSalt as usize as u64,
                p.ulSaltLen as u64,
                p.hSaltKey as u64,
                p.pInfo as usize as u64,
                p.ulInfoLen as u64,
                0,
            ],
        }
    }
    fn bytes_hash(&self) -> [u8; 32] {
        use sha2::{Digest, Sha256};
        let mut h = Sha256::new();
        match self {
            Self::Ec { point, info, .. } => {
                h.update(point.as_slice());
                h.update(info.as_slice());
            }
            Self::Hkdf { salt, info, .. } => {
                if let SaltInput::Data(bytes) = salt {
                    h.update(bytes.as_slice());
                }
                // A native salt key is witnessed by hSaltKey and its reference
                // context/activity, never by exporting its secret material.
                h.update(info.as_slice());
            }
        }
        h.finalize().into()
    }
}
// Mechanism.pParameter is set only after this representation is in stable
// CallData. Parameters own every native referent; no caller slice escapes.
pub(super) struct DeriveCall {
    parameters: Parameters,
    template: crate::attributes::OwnedTemplate,
    mechanism: CK_MECHANISM,
    created: CK_OBJECT_HANDLE,
    _credit: Credit,
}
// SAFETY: all native pointers refer to owned Buffer/Template allocations or to
// Parameters inside stable CallData. No exposed allocation is resized.
unsafe impl Send for DeriveCall {}

pub(super) enum Output {
    Symmetric(SymmetricKeySpec),
    Hkdf(HkdfKeySpec, CurrentKeyProtection),
}
impl Output {
    fn admission(&self) -> &crate::ObjectAdmission {
        match self {
            Self::Symmetric(v) => &v.admission,
            Self::Hkdf(v, _) => &v.admission,
        }
    }
    fn label(&self) -> &[u8] {
        match self {
            Self::Symmetric(v) => v.label.as_bytes(),
            Self::Hkdf(v, _) => v.label.as_bytes(),
        }
    }
    fn id(&self) -> &[u8] {
        match self {
            Self::Symmetric(v) => &v.id,
            Self::Hkdf(v, _) => &v.id,
        }
    }
    fn validate(&self, _s: &Session) -> Result<()> {
        match self {
            Self::Hkdf(v, _) => identity(&v.id, &v.label),
            Self::Symmetric(v) => {
                v.validate()?;
                Ok(())
            }
        }
    }
    fn template<T: crate::attributes::TemplateSink>(&self) -> Result<T> {
        match self {
            Self::Hkdf(v, current) => BaseSpec::Hkdf(v).template_as(*current),
            Self::Symmetric(v) => crate::symmetric::keys::generation_template_as(v),
        }
    }
}
enum Derived {
    Symmetric(DerivedSymmetricKey),
    Hkdf(DerivedHkdfKey),
}
impl Session {
    /// Derive an opaque AES/HMAC key through exactly one native ECDH1 call.
    /// Shared data is public protocol context; the consumer authenticates the peer.
    pub fn derive_ecdh(
        &self,
        base: &AgreementKey,
        peer: &AgreementPeer,
        kdf: EcdhKdf,
        shared_data: &[u8],
        output: SymmetricKeySpec,
        requirements: DerivationObservationPlan,
    ) -> Result<crate::CreatedObjects<DerivedSymmetricKey>> {
        let mut diagnostics = None;
        if base.spec.curve != peer.curve {
            return Err(Error::Rejected(crate::RejectionReason::KeyDerivation(
                crate::KeyDerivationRejection::AgreementCurveMismatch,
            )));
        }
        let params = ParameterPlan::ec(peer, kdf, shared_data)?;
        Ok(self
            .derive_native(
                &base.managed,
                BaseSpec::Ec(&base.spec),
                DerivationPath::Ecdh(kdf),
                params,
                Output::Symmetric(output),
                requirements,
                &mut diagnostics,
            )?
            .try_map(|result| match result {
                Derived::Symmetric(v) => Ok(v),
                _ => unreachable!(),
            }))
    }
    /// Derive an opaque symmetric key from a Montgomery private key and an
    /// exact-domain public coordinate. The caller authenticates the peer.
    /// The native module decides agreement/KDF support; errors cause no fallback.
    pub fn derive_montgomery(
        &self,
        base: &MontgomeryKey,
        peer: &MontgomeryPublicKey,
        kdf: EcdhKdf,
        shared_data: &[u8],
        output: SymmetricKeySpec,
        requirements: DerivationObservationPlan,
    ) -> Result<crate::CreatedObjects<DerivedSymmetricKey>> {
        let mut diagnostics = None;
        if base.spec.domain != peer.domain() {
            return Err(Error::Rejected(crate::RejectionReason::KeyDerivation(
                crate::KeyDerivationRejection::MontgomeryAgreementDomainMismatch,
            )));
        }
        let params = ParameterPlan::ec_public(peer.native_bytes(), kdf, shared_data)?;
        Ok(self
            .derive_native(
                &base.managed,
                BaseSpec::Montgomery(&base.spec),
                DerivationPath::Ecdh(kdf),
                params,
                Output::Symmetric(output),
                requirements,
                &mut diagnostics,
            )?
            .try_map(|result| match result {
                Derived::Symmetric(value) => Ok(value),
                _ => unreachable!("symmetric derivation requested a symmetric output owner"),
            }))
    }
    /// Native SHA256 HKDF extract+expand, explicit salt and public context.
    pub fn derive_hkdf(
        &self,
        base: &HkdfKey,
        salt: HkdfSalt<'_>,
        info: &[u8],
        output: SymmetricKeySpec,
        requirements: DerivationObservationPlan,
    ) -> Result<crate::CreatedObjects<DerivedSymmetricKey>> {
        let mut diagnostics = None;
        self.derive_hkdf_selected(
            base,
            CKM_SHA256 as u64,
            salt,
            info,
            output,
            requirements,
            &mut diagnostics,
        )
    }
    /// Native HKDF extract+expand with the exact PKCS#11 base hash identifier.
    /// The module decides support and parameter validity; no hash fallback occurs.
    pub fn derive_hkdf_with_hash(
        &self,
        base: &HkdfKey,
        hash: u64,
        salt: HkdfSalt<'_>,
        info: &[u8],
        output: SymmetricKeySpec,
        requirements: DerivationObservationPlan,
    ) -> Result<crate::CreatedObjects<DerivedSymmetricKey>> {
        let mut diagnostics = None;
        self.derive_hkdf_selected(
            base,
            hash,
            salt,
            info,
            output,
            requirements,
            &mut diagnostics,
        )
    }

    fn derive_hkdf_selected(
        &self,
        base: &HkdfKey,
        hash: u64,
        salt: HkdfSalt<'_>,
        info: &[u8],
        output: SymmetricKeySpec,
        requirements: DerivationObservationPlan,
        diagnostics: &mut crate::error::ObjectCreationDiagnostics,
    ) -> Result<crate::CreatedObjects<DerivedSymmetricKey>> {
        let path = if hash == CKM_SHA256 as u64 {
            DerivationPath::HkdfExtractExpand
        } else {
            DerivationPath::HkdfExtractExpandWithHash(hash)
        };
        let params = ParameterPlan::hkdf(path, salt, info)?;
        Ok(self
            .derive_native(
                &base.managed,
                BaseSpec::Hkdf(&base.spec),
                path,
                params,
                Output::Symmetric(output),
                requirements,
                diagnostics,
            )?
            .try_map(|result| match result {
                Derived::Symmetric(v) => Ok(v),
                _ => unreachable!(),
            }))
    }
    /// Native SHA-256 extraction only. The output template remains caller-selected.
    /// Use `extract_hkdf_with_hash` to select a different native base hash.
    pub fn extract_hkdf(
        &self,
        base: &HkdfKey,
        salt: HkdfSalt<'_>,
        output: HkdfKeySpec,
        current: CurrentKeyProtection,
        requirements: DerivationObservationPlan,
    ) -> Result<crate::CreatedObjects<DerivedHkdfKey>> {
        let mut diagnostics = None;
        self.extract_hkdf_selected(
            base,
            CKM_SHA256 as u64,
            salt,
            output,
            current,
            requirements,
            &mut diagnostics,
        )
    }
    /// Extract an opaque PRK using the exact native base hash identifier.
    /// The module checks the selected output template against that mechanism.
    pub fn extract_hkdf_with_hash(
        &self,
        base: &HkdfKey,
        hash: u64,
        salt: HkdfSalt<'_>,
        output: HkdfKeySpec,
        current: CurrentKeyProtection,
        requirements: DerivationObservationPlan,
    ) -> Result<crate::CreatedObjects<DerivedHkdfKey>> {
        let mut diagnostics = None;
        self.extract_hkdf_selected(
            base,
            hash,
            salt,
            output,
            current,
            requirements,
            &mut diagnostics,
        )
    }

    fn extract_hkdf_selected(
        &self,
        base: &HkdfKey,
        hash: u64,
        salt: HkdfSalt<'_>,
        output: HkdfKeySpec,
        current: CurrentKeyProtection,
        requirements: DerivationObservationPlan,
        diagnostics: &mut crate::error::ObjectCreationDiagnostics,
    ) -> Result<crate::CreatedObjects<DerivedHkdfKey>> {
        let path = if hash == CKM_SHA256 as u64 {
            DerivationPath::HkdfExtract
        } else {
            DerivationPath::HkdfExtractWithHash(hash)
        };
        let params = ParameterPlan::hkdf(path, salt, &[])?;
        Ok(self
            .derive_native(
                &base.managed,
                BaseSpec::Hkdf(&base.spec),
                path,
                params,
                Output::Hkdf(output, current),
                requirements,
                diagnostics,
            )?
            .try_map(|result| match result {
                Derived::Hkdf(v) => Ok(v),
                _ => unreachable!(),
            }))
    }
    /// Native SHA-256 expansion only; the consumer supplies an appropriate PRK.
    /// Use `expand_hkdf_with_hash` to select a different native base hash.
    pub fn expand_hkdf(
        &self,
        base: &HkdfKey,
        info: &[u8],
        output: SymmetricKeySpec,
        requirements: DerivationObservationPlan,
    ) -> Result<crate::CreatedObjects<DerivedSymmetricKey>> {
        let mut diagnostics = None;
        self.expand_hkdf_selected(
            base,
            CKM_SHA256 as u64,
            info,
            output,
            requirements,
            &mut diagnostics,
        )
    }
    /// Expand with the exact native base hash identifier and public info string.
    /// The caller supplies a suitable PRK; no extraction or hash substitution occurs.
    pub fn expand_hkdf_with_hash(
        &self,
        base: &HkdfKey,
        hash: u64,
        info: &[u8],
        output: SymmetricKeySpec,
        requirements: DerivationObservationPlan,
    ) -> Result<crate::CreatedObjects<DerivedSymmetricKey>> {
        let mut diagnostics = None;
        self.expand_hkdf_selected(base, hash, info, output, requirements, &mut diagnostics)
    }

    fn expand_hkdf_selected(
        &self,
        base: &HkdfKey,
        hash: u64,
        info: &[u8],
        output: SymmetricKeySpec,
        requirements: DerivationObservationPlan,
        diagnostics: &mut crate::error::ObjectCreationDiagnostics,
    ) -> Result<crate::CreatedObjects<DerivedSymmetricKey>> {
        let path = if hash == CKM_SHA256 as u64 {
            DerivationPath::HkdfExpand
        } else {
            DerivationPath::HkdfExpandWithHash(hash)
        };
        let params = ParameterPlan::hkdf(path, HkdfSalt::Null, info)?;
        Ok(self
            .derive_native(
                &base.managed,
                BaseSpec::Hkdf(&base.spec),
                path,
                params,
                Output::Symmetric(output),
                requirements,
                diagnostics,
            )?
            .try_map(|result| match result {
                Derived::Symmetric(v) => Ok(v),
                _ => unreachable!(),
            }))
    }
}

mod execution;
