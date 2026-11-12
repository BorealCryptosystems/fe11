// SPDX-License-Identifier: Apache-2.0
//! Owned ABI parameters for generic, one-output native derivation.

use crate::{
    attribute_values::InputTemplate,
    bounds,
    error::CompletionDiagnostic,
    managed::RevocationTargets,
    native::{frame::NativeFrame, generation::CompletedGeneration},
    native_return::MutationCall,
    session::SessionAccess,
    symmetric::memory::{Buffer, Credit},
    Error, NativeHkdfSalt, NativeKeyDerivation, Result, Session,
};
use crypto_bigint::subtle::ConstantTimeEq;
use fe11_sys::*;
use std::mem::size_of;

pub(crate) mod input;
mod preparation;
pub(crate) use preparation::DerivationStorage;
mod agreement;
mod encrypt_data;
mod ike;
pub(crate) mod kea;
pub(crate) mod key_material;
mod messaging;
pub(crate) mod prf;
pub(crate) mod sp800;
mod tls;

pub(crate) struct InputBytes {
    value: Buffer,
    witness: Buffer,
}
impl crate::symmetric::memory::RetainedStorage for InputBytes {
    fn retain_credits(&self, retained: &mut crate::symmetric::memory::RetainedBytes) -> Result<()> {
        self.value.retain_credit(retained)?;
        self.witness.retain_credit(retained)
    }
}

/// Unpublished input and witness capacities, measured with their parent graph
/// before caller bytes are copied or either buffer is exposed to native code.
pub(crate) struct InputBytesStorage {
    value: crate::symmetric::memory::UnboundBuffer,
    witness: crate::symmetric::memory::UnboundBuffer,
}
impl InputBytesStorage {
    pub(crate) fn allocate(length: usize) -> Result<Self> {
        bounds::ck_length(length)?;
        Ok(Self {
            value: crate::symmetric::memory::UnboundBuffer::allocate(length)?,
            witness: crate::symmetric::memory::UnboundBuffer::allocate(length)?,
        })
    }

    pub(crate) fn allocated_bytes(&self) -> Result<usize> {
        self.value
            .allocated()
            .checked_add(self.witness.allocated())
            .ok_or(Error::Rejected(crate::RejectionReason::NativeDerivation(
                crate::NativeDerivationRejection::OwnedInputLengthOverflow,
            )))
    }

    pub(crate) fn bind(self, input: &[u8], prepaid: &mut Credit) -> Result<InputBytes> {
        let mut bytes =
            InputBytes::from_buffers(self.value.bind(prepaid)?, self.witness.bind(prepaid)?)?;
        bytes.fill_before_dispatch(input)?;
        Ok(bytes)
    }

    pub(crate) fn bind_parts(self, parts: &[&[u8]], prepaid: &mut Credit) -> Result<InputBytes> {
        let length = parts.iter().try_fold(0usize, |total, part| {
            bounds::ck_length(part.len())?;
            total.checked_add(part.len()).ok_or(Error::Rejected(
                crate::RejectionReason::NativeDerivation(
                    crate::NativeDerivationRejection::OwnedInputLengthOverflow,
                ),
            ))
        })?;
        let mut bytes =
            InputBytes::from_buffers(self.value.bind(prepaid)?, self.witness.bind(prepaid)?)?;
        if bytes.value.as_slice().len() != length {
            return Err(Error::Rejected(crate::RejectionReason::NativeDerivation(
                crate::NativeDerivationRejection::PreparedInputLengthChanged,
            )));
        }
        let mut offset = 0;
        for part in parts {
            let end = offset + part.len(); // bounded by the checked aggregate above
            bytes.value.as_mut()[offset..end].copy_from_slice(part);
            bytes.witness.as_mut()[offset..end].copy_from_slice(part);
            offset = end;
        }
        Ok(bytes)
    }
}

impl InputBytes {
    /// Bind two already credited, equally sized buffers before native dispatch.
    /// No address escapes until the containing mechanism is constructed.
    pub(crate) fn from_buffers(value: Buffer, witness: Buffer) -> Result<Self> {
        bounds::ck_length(value.as_slice().len())?;
        if value.as_slice().len() != witness.as_slice().len() {
            return Err(Error::Rejected(crate::RejectionReason::NativeDerivation(
                crate::NativeDerivationRejection::PreparedInputLengthChanged,
            )));
        }
        Ok(Self { value, witness })
    }
    pub(crate) fn fill_before_dispatch(&mut self, input: &[u8]) -> Result<()> {
        if self.value.as_slice().len() != input.len()
            || self.witness.as_slice().len() != input.len()
        {
            return Err(Error::Rejected(crate::RejectionReason::NativeDerivation(
                crate::NativeDerivationRejection::PreparedInputLengthChanged,
            )));
        }
        self.value.as_mut().copy_from_slice(input);
        self.witness.as_mut().copy_from_slice(input);
        Ok(())
    }
    pub(crate) fn new(input: &[u8], credit: &mut Credit) -> Result<Self> {
        bounds::ck_length(input.len())?;
        let mut value = Buffer::new_prepaid(credit, input.len())?;
        let mut witness = Buffer::new_prepaid(credit, input.len())?;
        value.as_mut().copy_from_slice(input);
        witness.as_mut().copy_from_slice(input);
        Ok(Self { value, witness })
    }
    pub(crate) fn bytes(&self) -> &[u8] {
        self.value.as_slice()
    }
    /// Borrow the native input allocation; the witness remains independent
    /// so the owning operation can detect native writes after memory return.
    pub(crate) fn as_mut(&mut self) -> &mut [u8] {
        self.value.as_mut()
    }
    pub(crate) fn pointer(&mut self) -> CK_BYTE_PTR {
        self.value.as_mut().as_mut_ptr()
    }
    // Address comparison only; native writable provenance comes from pointer().
    pub(crate) fn expected_pointer(&self) -> CK_BYTE_PTR {
        self.value.as_slice().as_ptr().cast_mut()
    }
    pub(crate) fn length(&self) -> CK_ULONG {
        self.value.as_slice().len() as CK_ULONG
    }
    pub(crate) fn unchanged(&self) -> bool {
        bool::from(self.value.as_slice().ct_eq(self.witness.as_slice()))
    }
}

fn optional_pointer(value: &mut Option<InputBytes>) -> CK_BYTE_PTR {
    value
        .as_mut()
        .map_or(std::ptr::null_mut(), InputBytes::pointer)
}
fn optional_expected_pointer(value: &Option<InputBytes>) -> CK_BYTE_PTR {
    value
        .as_ref()
        .map_or(std::ptr::null_mut(), InputBytes::expected_pointer)
}
fn optional_length(value: &Option<InputBytes>) -> CK_ULONG {
    value.as_ref().map_or(0, InputBytes::length)
}
fn optional_unchanged(value: &Option<InputBytes>) -> bool {
    value.as_ref().map_or(true, InputBytes::unchanged)
}

enum Salt {
    Null,
    Data(InputBytes),
    Key(CK_OBJECT_HANDLE),
}
impl Salt {
    fn fields(&mut self) -> (CK_ULONG, CK_BYTE_PTR, CK_ULONG, CK_OBJECT_HANDLE) {
        match self {
            Self::Null => (
                CKF_HKDF_SALT_NULL,
                std::ptr::null_mut(),
                0,
                CK_INVALID_HANDLE,
            ),
            Self::Data(data) => (
                CKF_HKDF_SALT_DATA,
                data.pointer(),
                data.length(),
                CK_INVALID_HANDLE,
            ),
            Self::Key(handle) => (CKF_HKDF_SALT_KEY, std::ptr::null_mut(), 0, *handle),
        }
    }
    fn expected_fields(&self) -> (CK_ULONG, CK_BYTE_PTR, CK_ULONG, CK_OBJECT_HANDLE) {
        match self {
            Self::Null => (
                CKF_HKDF_SALT_NULL,
                std::ptr::null_mut(),
                0,
                CK_INVALID_HANDLE,
            ),
            Self::Data(data) => (
                CKF_HKDF_SALT_DATA,
                data.expected_pointer(),
                data.length(),
                CK_INVALID_HANDLE,
            ),
            Self::Key(handle) => (CKF_HKDF_SALT_KEY, std::ptr::null_mut(), 0, *handle),
        }
    }
    fn unchanged(&self) -> bool {
        match self {
            Self::Data(data) => data.unchanged(),
            _ => true,
        }
    }
}

// Each variant owns exactly the native parameter type and its referents. These
// structs are bound only after the enclosing frame has reached stable storage.
enum Parameters {
    Gost {
        raw: CK_GOSTR3410_DERIVE_PARAMS,
        kdf: CK_ULONG,
        public: InputBytes,
        ukm: Option<InputBytes>,
    },
    Extension(crate::mechanism_extension::OwnedGraph),
    Messaging(messaging::Messaging),
    TlsMaster(tls::Master),
    TlsKdf(tls::Kdf),
    Ike(ike::Ike),
    Agreement(agreement::Agreement),
    EncryptData(encrypt_data::EncryptData),
    None,
    Key {
        handle: CK_OBJECT_HANDLE,
        expected: CK_OBJECT_HANDLE,
    },
    Hkdf {
        raw: CK_HKDF_PARAMS,
        extract: CK_BBOOL,
        expand: CK_BBOOL,
        hash: CK_MECHANISM_TYPE,
        salt: Salt,
        info: Option<InputBytes>,
    },
    Bytes(InputBytes),
    Extract {
        scalar: CK_EXTRACT_PARAMS,
        expected: CK_EXTRACT_PARAMS,
    },
    String {
        raw: CK_KEY_DERIVATION_STRING_DATA,
        data: InputBytes,
    },
    Ec {
        raw: CK_ECDH1_DERIVE_PARAMS,
        kdf: CK_ULONG,
        public: InputBytes,
        shared: Option<InputBytes>,
    },
    Dh942 {
        raw: CK_X9_42_DH1_DERIVE_PARAMS,
        kdf: CK_ULONG,
        public: InputBytes,
        info: Option<InputBytes>,
    },
}
impl Parameters {
    fn payload_bytes(request: &NativeKeyDerivation<'_>) -> Result<usize> {
        let lengths = match request {
            NativeKeyDerivation::GostR3410 {
                kdf,
                peer_public,
                ukm,
            } => {
                native_ulong(*kdf)?;
                [peer_public.len(), ukm.map_or(0, |bytes| bytes.len())]
            }
            NativeKeyDerivation::Extension { request, .. } => {
                return crate::mechanism_extension::OwnedGraph::allocation_bytes(
                    &request.parameters,
                )
            }
            NativeKeyDerivation::Messaging(input) => {
                return messaging::Messaging::payload_bytes(input)
            }
            NativeKeyDerivation::TlsMaster(input) => return tls::Master::payload_bytes(input),
            NativeKeyDerivation::TlsKdf(input) => return tls::Kdf::payload_bytes(input),
            NativeKeyDerivation::Ike(input) => return ike::Ike::payload_bytes(input),
            NativeKeyDerivation::Null { .. } => [0, 0],
            NativeKeyDerivation::Ecmqv { agreement, .. }
            | NativeKeyDerivation::X942Mqv { agreement, .. }
            | NativeKeyDerivation::X942Hybrid(agreement) => {
                return agreement::Agreement::payload_bytes(agreement)
            }
            NativeKeyDerivation::EncryptData(input) => [input.data().len(), 0],
            NativeKeyDerivation::ConcatenateKey(_) => [0, 0],
            NativeKeyDerivation::Hkdf { .. } | NativeKeyDerivation::HkdfParameters(_) => {
                let parameters = request.hkdf_parameters().expect("matched HKDF parameters");
                native_ulong(parameters.hash)?;
                [
                    match parameters.salt {
                        NativeHkdfSalt::Data(bytes) => bytes.len(),
                        _ => 0,
                    },
                    parameters.info.map_or(0, |info| info.len()),
                ]
            }
            NativeKeyDerivation::Hash(_) | NativeKeyDerivation::PublicFromPrivate => [0, 0],
            NativeKeyDerivation::Extract { start_bit } => {
                native_ulong(*start_bit)?;
                [0, 0]
            }
            NativeKeyDerivation::DhPkcs { peer_public } => [peer_public.len(), 0],
            NativeKeyDerivation::ConcatenateData { data, .. }
            | NativeKeyDerivation::XorData { data } => [data.len(), 0],
            NativeKeyDerivation::Ecdh {
                kdf,
                peer_public,
                shared_data,
                ..
            } => {
                native_ulong(*kdf)?;
                [
                    peer_public.len(),
                    shared_data.map_or(0, |bytes| bytes.len()),
                ]
            }
            NativeKeyDerivation::X942Dh {
                kdf,
                peer_public,
                other_info,
            } => {
                native_ulong(*kdf)?;
                [peer_public.len(), other_info.map_or(0, |bytes| bytes.len())]
            }
        };
        lengths.into_iter().try_fold(0usize, |total, length| {
            bounds::ck_length(length)?;
            length
                .checked_mul(2)
                .and_then(|n| total.checked_add(n))
                .ok_or(Error::Rejected(crate::RejectionReason::NativeDerivation(
                    crate::NativeDerivationRejection::DerivationParameterStorageAccounting,
                )))
        })
    }
    fn basic_from_storage(
        request: &NativeKeyDerivation<'_>,
        first: Option<InputBytes>,
        second: Option<InputBytes>,
    ) -> Result<Self> {
        Ok(match request {
            NativeKeyDerivation::GostR3410 {
                kdf,
                peer_public: _,
                ukm: _,
            } => {
                let kdf = native_ulong(*kdf)?;
                let mut public =
                    first.ok_or(Error::Rejected(crate::RejectionReason::NativeDerivation(
                        crate::NativeDerivationRejection::MissingDerivationInputStorage,
                    )))?;
                let mut ukm = second;
                let raw = CK_GOSTR3410_DERIVE_PARAMS {
                    kdf,
                    pPublicData: public.pointer(),
                    ulPublicDataLen: public.length(),
                    pUKM: optional_pointer(&mut ukm),
                    ulUKMLen: optional_length(&ukm),
                };
                Self::Gost {
                    raw,
                    kdf,
                    public,
                    ukm,
                }
            }
            NativeKeyDerivation::ConcatenateKey(key) => Self::Key {
                handle: key.identity.handle,
                expected: key.identity.handle,
            },
            NativeKeyDerivation::Hkdf { .. } | NativeKeyDerivation::HkdfParameters(_) => {
                let parameters = request.hkdf_parameters().expect("matched HKDF parameters");
                let extract = if parameters.extract {
                    CK_TRUE
                } else {
                    CK_FALSE
                };
                let expand = if parameters.expand { CK_TRUE } else { CK_FALSE };
                let hash = native_ulong(parameters.hash)?;
                let mut salt = match parameters.salt {
                    NativeHkdfSalt::Null => Salt::Null,
                    NativeHkdfSalt::Data(_) => Salt::Data(first.ok_or(Error::Rejected(
                        crate::RejectionReason::NativeDerivation(
                            crate::NativeDerivationRejection::MissingDerivationSaltStorage,
                        ),
                    ))?),
                    NativeHkdfSalt::Key(key) => Salt::Key(key.identity.handle),
                };
                let mut info = second;
                if info.is_some() != parameters.info.is_some() {
                    return Err(Error::Rejected(crate::RejectionReason::NativeDerivation(
                        crate::NativeDerivationRejection::DerivationInfoStoragePresence,
                    )));
                }
                let (kind, pointer, length, key) = salt.fields();
                let raw = CK_HKDF_PARAMS {
                    bExtract: extract,
                    bExpand: expand,
                    prfHashMechanism: hash,
                    ulSaltType: kind,
                    pSalt: pointer,
                    ulSaltLen: length,
                    hSaltKey: key,
                    pInfo: optional_pointer(&mut info),
                    ulInfoLen: optional_length(&info),
                };
                Self::Hkdf {
                    raw,
                    extract,
                    expand,
                    hash,
                    salt,
                    info,
                }
            }
            NativeKeyDerivation::Hash(_)
            | NativeKeyDerivation::PublicFromPrivate
            | NativeKeyDerivation::Null { .. } => Self::None,
            NativeKeyDerivation::DhPkcs { .. } => Self::Bytes(first.ok_or(Error::Rejected(
                crate::RejectionReason::NativeDerivation(
                    crate::NativeDerivationRejection::MissingDerivationInputStorage,
                ),
            ))?),
            NativeKeyDerivation::Extract { start_bit } => {
                let value = native_ulong(*start_bit)?;
                Self::Extract {
                    scalar: value,
                    expected: value,
                }
            }
            NativeKeyDerivation::ConcatenateData { .. } | NativeKeyDerivation::XorData { .. } => {
                let mut data =
                    first.ok_or(Error::Rejected(crate::RejectionReason::NativeDerivation(
                        crate::NativeDerivationRejection::MissingDerivationDataStorage,
                    )))?;
                let raw = CK_KEY_DERIVATION_STRING_DATA {
                    pData: data.pointer(),
                    ulLen: data.length(),
                };
                Self::String { raw, data }
            }
            NativeKeyDerivation::Ecdh {
                kdf,
                peer_public: _,
                shared_data: _,
                ..
            } => {
                let kdf = native_ulong(*kdf)?;
                let mut public =
                    first.ok_or(Error::Rejected(crate::RejectionReason::NativeDerivation(
                        crate::NativeDerivationRejection::MissingDerivationInputStorage,
                    )))?;
                let mut shared = second;
                let raw = CK_ECDH1_DERIVE_PARAMS {
                    kdf,
                    ulSharedDataLen: optional_length(&shared),
                    pSharedData: optional_pointer(&mut shared),
                    ulPublicDataLen: public.length(),
                    pPublicData: public.pointer(),
                };
                Self::Ec {
                    raw,
                    kdf,
                    public,
                    shared,
                }
            }
            NativeKeyDerivation::X942Dh {
                kdf,
                peer_public: _,
                other_info: _,
            } => {
                let kdf = native_ulong(*kdf)?;
                let mut public =
                    first.ok_or(Error::Rejected(crate::RejectionReason::NativeDerivation(
                        crate::NativeDerivationRejection::MissingDerivationInputStorage,
                    )))?;
                let mut info = second;
                let raw = CK_X9_42_DH1_DERIVE_PARAMS {
                    kdf,
                    ulOtherInfoLen: optional_length(&info),
                    pOtherInfo: optional_pointer(&mut info),
                    ulPublicDataLen: public.length(),
                    pPublicData: public.pointer(),
                };
                Self::Dh942 {
                    raw,
                    kdf,
                    public,
                    info,
                }
            }
            _ => {
                return Err(Error::Rejected(crate::RejectionReason::NativeDerivation(
                    crate::NativeDerivationRejection::DerivationStorageVariantChanged,
                )))
            }
        })
    }
    fn projection(&mut self) -> (CK_VOID_PTR, CK_ULONG) {
        match self {
            Self::Gost { raw, .. } => (
                (raw as *mut CK_GOSTR3410_DERIVE_PARAMS).cast(),
                size_of::<CK_GOSTR3410_DERIVE_PARAMS>() as CK_ULONG,
            ),
            Self::Extension(owner) => owner.projection(),
            Self::Messaging(owner) => owner.projection(),
            Self::TlsMaster(owner) => owner.projection(),
            Self::TlsKdf(owner) => owner.projection(),
            Self::Ike(owner) => owner.projection(),
            Self::Agreement(owner) => owner.projection(),
            Self::EncryptData(owner) => owner.projection(),
            Self::Key { handle, .. } => (
                (handle as *mut CK_OBJECT_HANDLE).cast(),
                size_of::<CK_OBJECT_HANDLE>() as CK_ULONG,
            ),
            Self::Hkdf { raw, .. } => (
                (raw as *mut CK_HKDF_PARAMS).cast(),
                size_of::<CK_HKDF_PARAMS>() as CK_ULONG,
            ),
            Self::None => (std::ptr::null_mut(), 0),
            Self::Bytes(data) => (data.pointer().cast(), data.length()),
            Self::Extract { scalar, .. } => (
                (scalar as *mut CK_EXTRACT_PARAMS).cast(),
                size_of::<CK_EXTRACT_PARAMS>() as CK_ULONG,
            ),
            Self::String { raw, .. } => (
                (raw as *mut CK_KEY_DERIVATION_STRING_DATA).cast(),
                size_of::<CK_KEY_DERIVATION_STRING_DATA>() as CK_ULONG,
            ),
            Self::Ec { raw, .. } => (
                (raw as *mut CK_ECDH1_DERIVE_PARAMS).cast(),
                size_of::<CK_ECDH1_DERIVE_PARAMS>() as CK_ULONG,
            ),
            Self::Dh942 { raw, .. } => (
                (raw as *mut CK_X9_42_DH1_DERIVE_PARAMS).cast(),
                size_of::<CK_X9_42_DH1_DERIVE_PARAMS>() as CK_ULONG,
            ),
        }
    }
    fn validate_output_bounds(&self) -> Result<()> {
        match self {
            Self::Extension(graph) => graph.validate_output_bounds(),
            _ => Ok(()),
        }
    }

    fn output(&mut self) -> crate::NativeDerivationOutput {
        match self {
            Self::Extension(graph) if graph.read_only() => crate::NativeDerivationOutput::None,
            Self::Extension(graph) => {
                // Capacity was validated before registering the primary object.
                // A later local publication failure must preserve that object
                // and never invite a second DeriveKey.
                if let Err(error) = graph.finish() {
                    return crate::NativeDerivationOutput::Extension(Err(error));
                }
                let Self::Extension(graph) = std::mem::replace(self, Self::None) else {
                    return crate::NativeDerivationOutput::Extension(Err(Error::Rejected(
                        crate::RejectionReason::NativeDerivation(
                            crate::NativeDerivationRejection::DerivationParameterOwnershipChanged,
                        ),
                    )));
                };
                crate::NativeDerivationOutput::Extension(Ok(crate::ExtensionParameterOutputs {
                    graph,
                    provenance: crate::MechanismLayoutProvenance::CallerAssertedLayout,
                }))
            }
            Self::TlsMaster(owner) => owner.output(),
            Self::Gost { .. }
            | Self::Messaging(_)
            | Self::TlsKdf(_)
            | Self::Ike(_)
            | Self::Agreement(_)
            | Self::EncryptData(_)
            | Self::None
            | Self::Key { .. }
            | Self::Hkdf { .. }
            | Self::Bytes(_)
            | Self::Extract { .. }
            | Self::String { .. }
            | Self::Ec { .. }
            | Self::Dh942 { .. } => crate::NativeDerivationOutput::None,
        }
    }
    fn unchanged(&self) -> bool {
        match self {
            Self::Gost {
                raw,
                kdf,
                public,
                ukm,
            } => {
                let bytes = public.unchanged() & optional_unchanged(ukm);
                raw.kdf == *kdf
                    && raw.pPublicData == public.expected_pointer()
                    && raw.ulPublicDataLen == public.length()
                    && raw.pUKM == optional_expected_pointer(ukm)
                    && raw.ulUKMLen == optional_length(ukm)
                    && bytes
            }
            Self::Extension(owner) => owner.unchanged(),
            Self::Messaging(owner) => owner.unchanged(),
            Self::TlsMaster(owner) => owner.unchanged(),
            Self::TlsKdf(owner) => owner.unchanged(),
            Self::Ike(owner) => owner.unchanged(),
            Self::Agreement(owner) => owner.unchanged(),
            Self::EncryptData(owner) => owner.unchanged(),
            Self::None => true,
            Self::Key { handle, expected } => handle == expected,
            Self::Hkdf {
                raw,
                extract,
                expand,
                hash,
                salt,
                info,
            } => {
                let bytes_unchanged = salt.unchanged() & optional_unchanged(info);
                let actual_salt = (raw.ulSaltType, raw.pSalt, raw.ulSaltLen, raw.hSaltKey);
                raw.bExtract == *extract
                    && raw.bExpand == *expand
                    && raw.prfHashMechanism == *hash
                    && actual_salt == salt.expected_fields()
                    && raw.pInfo == optional_expected_pointer(info)
                    && raw.ulInfoLen == optional_length(info)
                    && bytes_unchanged
            }
            Self::Bytes(data) => data.unchanged(),
            Self::Extract { scalar, expected } => scalar == expected,
            Self::String { raw, data } => {
                raw.pData == data.expected_pointer()
                    && raw.ulLen == data.length()
                    && data.unchanged()
            }
            Self::Ec {
                raw,
                kdf,
                public,
                shared,
            } => {
                let bytes_unchanged = public.unchanged() & optional_unchanged(shared);
                raw.kdf == *kdf
                    && raw.ulPublicDataLen == public.length()
                    && raw.pPublicData == public.expected_pointer()
                    && raw.ulSharedDataLen == optional_length(shared)
                    && raw.pSharedData == optional_expected_pointer(shared)
                    && bytes_unchanged
            }
            Self::Dh942 {
                raw,
                kdf,
                public,
                info,
            } => {
                let bytes_unchanged = public.unchanged() & optional_unchanged(info);
                raw.kdf == *kdf
                    && raw.ulPublicDataLen == public.length()
                    && raw.pPublicData == public.expected_pointer()
                    && raw.ulOtherInfoLen == optional_length(info)
                    && raw.pOtherInfo == optional_expected_pointer(info)
                    && bytes_unchanged
            }
        }
    }
}
fn native_ulong(value: u64) -> Result<CK_ULONG> {
    CK_ULONG::try_from(value).map_err(|_| {
        Error::Rejected(crate::RejectionReason::NativeDerivation(
            crate::NativeDerivationRejection::DerivationScalarAbiWidth,
        ))
    })
}

pub(crate) struct Derivation {
    mechanism: CK_MECHANISM,
    parameters: Parameters,
    template: InputTemplate,
    output: CK_OBJECT_HANDLE,
    mutates_base: bool,
    _credit: Credit,
}
// SAFETY: parameter/template pointers address only fixed allocations owned by
// this frame. No pointer to caller input or a stack output is retained. Native
// access and source/destination activities live in the enclosing NativeFrame.
unsafe impl Send for Derivation {}
impl Derivation {
    /// Both stable allocations, excluding separately credited nested owners.
    fn frame_bytes(nested_credit: usize) -> usize {
        size_of::<Self>() + crate::native::frame::SessionFrame::<'_, Self>::allocation_bytes()
            - size_of::<InputTemplate>()
            - nested_credit
    }

    pub(crate) fn allocation_bytes(request: &NativeKeyDerivation<'_>) -> Result<usize> {
        let nested_credit = if matches!(request, NativeKeyDerivation::Extension { .. }) {
            size_of::<crate::mechanism_extension::OwnedGraph>()
        } else {
            0
        };
        Self::frame_bytes(nested_credit)
            .checked_add(Parameters::payload_bytes(request)?)
            .ok_or(Error::Rejected(crate::RejectionReason::NativeDerivation(
                crate::NativeDerivationRejection::DerivationFrameAccounting,
            )))
    }

    pub(crate) fn execute_resident(
        self,
        session: &Session,
        access: &SessionAccess<'_>,
        diagnostic: crate::error::CompletionStorage,
        mut creation: crate::managed::PreparedCreation,
        base: CK_OBJECT_HANDLE,
        base_aliases: RevocationTargets,
        secondary_aliases: [Option<(CK_OBJECT_HANDLE, RevocationTargets)>; 4],
        mutation: Option<RevocationTargets>,
        cleanup: &mut crate::error::CleanupStorage,
    ) -> Result<(CompletedGeneration<1>, crate::NativeDerivationOutput)> {
        self.execute_prepared(
            session,
            access,
            diagnostic,
            || creation.begin(),
            base,
            base_aliases,
            secondary_aliases,
            mutation,
            cleanup,
        )
    }
    fn execute_prepared(
        self,
        session: &Session,
        access: &SessionAccess<'_>,
        diagnostic: crate::error::CompletionStorage,
        begin: impl FnOnce() -> Result<crate::managed::CreationTicket>,
        base: CK_OBJECT_HANDLE,
        base_aliases: RevocationTargets,
        secondary_aliases: [Option<(CK_OBJECT_HANDLE, RevocationTargets)>; 4],
        mutation: Option<RevocationTargets>,
        cleanup: &mut crate::error::CleanupStorage,
    ) -> Result<(CompletedGeneration<1>, crate::NativeDerivationOutput)> {
        let call = MutationCall::Derive;
        let derive = access.native.table.C_DeriveKey.ok_or(Error::Rejected(
            crate::RejectionReason::NativeDerivation(
                crate::NativeDerivationRejection::CDeriveKeyUnavailable,
            ),
        ))?;
        self.template.check_extensions(&session.inner)?;
        let count = self.template.count();
        let diagnostic = diagnostic.bind(call.function());
        let mut frame = NativeFrame::session(access.clone(), self)?;
        let creation = begin()?;
        let (returned, body) = frame.session_parts();
        let state = &body.access;
        let data = &mut *body.data;
        let (pointer, length) = data.parameters.projection();
        data.mechanism.pParameter = pointer;
        data.mechanism.ulParameterLen = length;
        let expected = (data.mechanism.mechanism, pointer, length);
        creation.prepare_dispatch(state, || {
            session.entry(state)?;
            state.native.record(call.function())
        })?;
        if let Some(mutation) = mutation {
            drop(mutation.arm());
        }
        returned.arm();
        // SAFETY: the stable frame owns the complete parameter graph, copied
        // template and output. SessionAccess retains the admitted source activity
        // and creation reservation through normal and uncertain completion.
        let rv = returned.observe(
            unsafe {
                derive(
                    session.entry.handle,
                    &mut data.mechanism,
                    base,
                    data.template.as_mut_ptr(),
                    count,
                    &mut data.output,
                )
            },
            &state.native,
        );
        let inspection = session.inspect_native_inputs(state, call.function(), rv, || {
            (
                data.mechanism.mechanism,
                data.mechanism.pParameter,
                data.mechanism.ulParameterLen,
            ) == expected
                && data.parameters.unchanged()
                && data.template.unchanged()
        });
        let completed = inspection.memory_returned();
        let unchanged = !inspection.violated();
        let output_bounds = if rv == CKR_OK && unchanged {
            data.parameters.validate_output_bounds()
        } else {
            Ok(())
        };
        if !unchanged || output_bounds.is_err() {
            returned.quarantine(&state.native);
        } else if completed {
            returned.terminated();
        } else {
            returned.recoverable();
            session.poison(state);
        }
        let native = inspection.check(!call.definite_object_refusal(rv));
        if native.is_err()
            && inspection.no_objects(crate::native_return::protocol::CreationContract::Function(
                call,
            ))
        {
            creation.refused(state, call, rv);
        }
        if !unchanged {
            return Err(cleanup.mark_remaining(diagnostic.boundary_failure(
                rv,
                Error::Rejected(crate::RejectionReason::NativeDerivation(
                    crate::NativeDerivationRejection::DerivationNativeInputChanged,
                )),
            )));
        }
        if let Err(cause) = output_bounds {
            return Err(cleanup.mark_remaining(diagnostic.boundary_failure(rv, cause)));
        }
        native.map_err(|cause| {
            crate::mechanism_extension::operation::effect(cause, data.mutates_base)
        })?;
        if data.output == base {
            drop(base_aliases.arm());
            return diagnostic.finish(Err(cleanup.mark_remaining(Error::Rejected(
                crate::RejectionReason::NativeDerivation(
                    crate::NativeDerivationRejection::DeriveReturnedBaseHandle,
                ),
            ))));
        }
        for (secondary, aliases) in secondary_aliases.into_iter().flatten() {
            if data.output == secondary {
                drop(aliases.arm());
                return diagnostic.finish(Err(cleanup.mark_remaining(Error::Rejected(
                    crate::RejectionReason::NativeDerivation(
                        crate::NativeDerivationRejection::DeriveReturnedSecondarySourceHandle,
                    ),
                ))));
            }
        }
        if let Err(cause) =
            creation.handles_prepared(state, &[data.output], |cause| cleanup.mark_remaining(cause))
        {
            return diagnostic.finish(Err(cause));
        }
        let output = data.parameters.output();
        Ok((
            CompletedGeneration::registered([data.output], diagnostic, creation),
            output,
        ))
    }
}
