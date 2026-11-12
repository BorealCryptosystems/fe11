// SPDX-License-Identifier: Apache-2.0
//! General PKCS#11 3.2 KEM calls with exact templates and owned parameters.
use crate::mechanism_extension::{transport::CreationInput, OwnedGraph};
use crate::{
    ExtensionParameters, ExtensionRequest, GenerationTemplate, ManagedClass, MechanismExtension,
    MechanismLayoutProvenance, NativeOaepParameters, NativeTransportParameters, Result, Session,
};
use fe11_sys::*;
use std::mem::{align_of, offset_of, size_of};

/// Native KEM mechanism. Key sizes, mathematics, usage and output templates
/// remain application inputs and native decisions, without a local profile.
pub enum NativeKemParameters<'a> {
    /// PKCS #1 v1.5 encapsulation without a mechanism parameter.
    RsaPkcs1v15,
    /// Raw RSA encapsulation; no local padding operation.
    RsaX509,
    /// Exact OAEP hash, MGF and label chosen by the caller.
    RsaOaep(NativeOaepParameters<'a>),
    /// PKCS #3 DH encapsulation; no peer value in the mechanism parameter.
    /// The peer value is produced/consumed by the KEM ciphertext argument.
    DhPkcs3,
    /// X9.42 DH encapsulation with exact KDF and optional other information.
    X942Dh {
        /// Native CK_X9_42_DH_KDF_TYPE; no local KDF selection.
        kdf: u64,
        /// None and a present empty value retain distinct representations.
        other_info: Option<&'a [u8]>,
    },
    /// ECDH encapsulation, including the native key's supported curve family.
    Ecdh {
        /// Native CK_EC_KDF_TYPE.
        kdf: u64,
        /// Exact optional shared information for the KDF.
        shared_data: Option<&'a [u8]>,
    },
    /// ECDH with cofactor; distinct mechanism, without local curve arithmetic.
    EcdhCofactor {
        /// Native CK_EC_KDF_TYPE.
        kdf: u64,
        /// Exact optional shared information for the KDF.
        shared_data: Option<&'a [u8]>,
    },
    /// ML-KEM; the parameter set belongs to the key.
    MlKem,
    /// Native identity transport, providing no confidentiality.
    Null,
    /// Explicit ABI for another native KEM, bound to this module and route.
    Extension(ExtensionRequest<'a>),
}
/// Created key and bounded auxiliary outputs, published together after completion
/// and requested observations. No Debug or Clone exposes or duplicates buffers.
pub struct NativeKemResult {
    /// Managed reference to the native secret key.
    pub object: crate::NativeObjectView,
    pub(crate) parameters: OwnedGraph,
    pub(crate) ciphertext: Option<crate::symmetric::memory::Buffer>,
    pub(crate) provenance: MechanismLayoutProvenance,
}
impl NativeKemResult {
    /// Encapsulation bytes. None means decapsulation, distinct from empty output.
    /// CKM_NULL exposes the secret value here: the caller must protect it.
    /// Library-owned buffers are erased on drop; caller copies are not controlled.
    pub fn ciphertext(&self) -> Option<&[u8]> {
        self.ciphertext.as_ref().map(|bytes| bytes.as_slice())
    }
    /// Explicit auxiliary parameter output.
    pub fn parameter_output(&self, index: usize) -> Option<&[u8]> {
        self.parameters.output(index)
    }
    /// Representation provenance, not a support or security verdict.
    pub fn provenance(&self) -> MechanismLayoutProvenance {
        self.provenance
    }
}
impl Session {
    /// One C_EncapsulateKey call; no sizing probe, replay, KDF or fallback.
    /// None passes CK_INVALID_HANDLE without manufacturing a dummy key object.
    /// Whether a mechanism accepts that argument remains a native decision.
    /// CKR_BUFFER_TOO_SMALL preserves the native required ciphertext length and
    /// supplied capacity in Error::OutputBufferTooSmall, inside ObjectsMayRemain.
    /// With an input-integrity failure, NativeOutputAndLocalFailure preserves
    /// both the size observation and the local cause inside ObjectsMayRemain.
    /// No partial ciphertext or key handle is published on this refusal. The
    /// reported length is not an allocation approval or proof of non-creation;
    /// reconcile the possible effect before deciding whether to call again.
    pub fn encapsulate_native(
        &self,
        key: Option<&crate::NativeObjectRef>,
        parameters: NativeKemParameters<'_>,
        ciphertext_capacity: usize,
        output: GenerationTemplate<'_>,
    ) -> Result<crate::CreatedObjects<NativeKemResult>> {
        let mut diagnostics = crate::error::PreparedCreationDiagnostics::default();
        self.native_kem(
            key,
            parameters,
            CreationInput::Encapsulate {
                capacity: ciphertext_capacity,
            },
            output,
            &mut diagnostics,
        )
    }
    /// One C_DecapsulateKey call with exact ciphertext. ML-KEM implicit rejection
    /// is preserved: success does not authenticate the ciphertext or its sender.
    /// None has the same key semantics as encapsulate_native. Returned aliases
    /// of retained source objects are never destroyed as newly created objects.
    pub fn decapsulate_native(
        &self,
        key: Option<&crate::NativeObjectRef>,
        parameters: NativeKemParameters<'_>,
        ciphertext: &[u8],
        output: GenerationTemplate<'_>,
    ) -> Result<crate::CreatedObjects<NativeKemResult>> {
        let mut diagnostics = crate::error::PreparedCreationDiagnostics::default();
        self.native_kem(
            key,
            parameters,
            CreationInput::Decapsulate(ciphertext),
            output,
            &mut diagnostics,
        )
    }
    fn native_kem(
        &self,
        key: Option<&crate::NativeObjectRef>,
        parameters: NativeKemParameters<'_>,
        input: CreationInput<'_>,
        output: GenerationTemplate<'_>,
        diagnostics: &mut crate::error::PreparedCreationDiagnostics,
    ) -> Result<crate::CreatedObjects<NativeKemResult>> {
        let operation = input.operation();
        let cofactor = matches!(&parameters, NativeKemParameters::EcdhCofactor { .. });
        let mechanism = match parameters {
            NativeKemParameters::RsaOaep(parameters) => {
                return crate::native_transport::with_parameters(
                    self,
                    NativeTransportParameters::RsaOaep(parameters),
                    operation,
                    |request, sources| {
                        self.create_key_transport(
                            key,
                            input,
                            request,
                            ManagedClass::SecretKey,
                            output,
                            sources,
                            diagnostics,
                        )
                    },
                );
            }
            NativeKemParameters::X942Dh { kdf, other_info } => {
                return agreement_parameters(
                    self,
                    CKM_X9_42_DH_DERIVE,
                    kdf,
                    other_info,
                    operation,
                    |request| {
                        self.create_key_transport(
                            key,
                            input,
                            request,
                            ManagedClass::SecretKey,
                            output,
                            [None; 4],
                            diagnostics,
                        )
                    },
                );
            }
            NativeKemParameters::Ecdh { kdf, shared_data }
            | NativeKemParameters::EcdhCofactor { kdf, shared_data } => {
                let kind = if cofactor {
                    CKM_ECDH1_COFACTOR_DERIVE
                } else {
                    CKM_ECDH1_DERIVE
                };
                return agreement_parameters(self, kind, kdf, shared_data, operation, |request| {
                    self.create_key_transport(
                        key,
                        input,
                        request,
                        ManagedClass::SecretKey,
                        output,
                        [None; 4],
                        diagnostics,
                    )
                });
            }
            NativeKemParameters::Extension(request) => {
                return self.create_key_transport(
                    key,
                    input,
                    request,
                    ManagedClass::SecretKey,
                    output,
                    [None; 4],
                    diagnostics,
                );
            }
            NativeKemParameters::RsaPkcs1v15 => CKM_RSA_PKCS,
            NativeKemParameters::RsaX509 => CKM_RSA_X_509,
            // 3.2 section 6.4.10 uses structured public-data member names even
            // though PKCS #3's parameter is a byte string. NULL/0 carries no
            // peer value, without inventing a foreign structure for this CKM.
            NativeKemParameters::DhPkcs3 => CKM_DH_PKCS_DERIVE,
            NativeKemParameters::MlKem => CKM_ML_KEM,
            NativeKemParameters::Null => CKM_NULL,
        };
        let contract = MechanismExtension::standard(&self.inner, mechanism, operation);
        let request = ExtensionRequest {
            contract: &contract,
            parameters: ExtensionParameters {
                blocks: &[],
                pointers: &[],
                root: None,
                outputs: &[],
            },
        };
        self.create_key_transport(
            key,
            input,
            request,
            ManagedClass::SecretKey,
            output,
            [None; 4],
            diagnostics,
        )
    }
}
impl crate::AdvancedSession {
    /// Synchronous encapsulation through the same owner as Session.
    pub fn encapsulate_native(
        &self,
        key: Option<&crate::NativeObjectRef>,
        parameters: NativeKemParameters<'_>,
        ciphertext_capacity: usize,
        output: GenerationTemplate<'_>,
    ) -> Result<crate::CreatedObjects<NativeKemResult>> {
        let mut diagnostics = crate::error::PreparedCreationDiagnostics::default();
        self.session.native_kem(
            key,
            parameters,
            CreationInput::Encapsulate {
                capacity: ciphertext_capacity,
            },
            output,
            &mut diagnostics,
        )
    }
    /// Synchronous decapsulation through the same owner as Session.
    pub fn decapsulate_native(
        &self,
        key: Option<&crate::NativeObjectRef>,
        parameters: NativeKemParameters<'_>,
        ciphertext: &[u8],
        output: GenerationTemplate<'_>,
    ) -> Result<crate::CreatedObjects<NativeKemResult>> {
        let mut diagnostics = crate::error::PreparedCreationDiagnostics::default();
        self.session.native_kem(
            key,
            parameters,
            CreationInput::Decapsulate(ciphertext),
            output,
            &mut diagnostics,
        )
    }
}

/// KEM agreement parameters have no peer public value. The ciphertext is the
/// native ephemeral public value (3.2 sections 6.3.17/18 and 6.4.14). Keep the
/// KDF's other/shared information independent of that NULL public-data field.
fn agreement_parameters<T>(
    session: &Session,
    kind: CK_MECHANISM_TYPE,
    kdf: u64,
    information: Option<&[u8]>,
    operation: crate::ExtensionOperation,
    consume: impl FnOnce(ExtensionRequest<'_>) -> Result<T>,
) -> Result<T> {
    use crate::{ExtensionBlock, ExtensionDirection, ExtensionPointer, ExtensionPointerTarget};
    let (length, alignment, kdf_offset, length_offset, information_offset, public_offset) =
        if kind == CKM_X9_42_DH_DERIVE {
            (
                size_of::<CK_X9_42_DH1_DERIVE_PARAMS>(),
                align_of::<CK_X9_42_DH1_DERIVE_PARAMS>(),
                offset_of!(CK_X9_42_DH1_DERIVE_PARAMS, kdf),
                offset_of!(CK_X9_42_DH1_DERIVE_PARAMS, ulOtherInfoLen),
                offset_of!(CK_X9_42_DH1_DERIVE_PARAMS, pOtherInfo),
                offset_of!(CK_X9_42_DH1_DERIVE_PARAMS, pPublicData),
            )
        } else {
            (
                size_of::<CK_ECDH1_DERIVE_PARAMS>(),
                align_of::<CK_ECDH1_DERIVE_PARAMS>(),
                offset_of!(CK_ECDH1_DERIVE_PARAMS, kdf),
                offset_of!(CK_ECDH1_DERIVE_PARAMS, ulSharedDataLen),
                offset_of!(CK_ECDH1_DERIVE_PARAMS, pSharedData),
                offset_of!(CK_ECDH1_DERIVE_PARAMS, pPublicData),
            )
        };
    // Explicit byte writes avoid reading Rust padding, including packed Windows
    // layouts. OwnedGraph performs the aligned copy and pointer relocation.
    const ROOT_CAPACITY: usize =
        if size_of::<CK_ECDH1_DERIVE_PARAMS>() > size_of::<CK_X9_42_DH1_DERIVE_PARAMS>() {
            size_of::<CK_ECDH1_DERIVE_PARAMS>()
        } else {
            size_of::<CK_X9_42_DH1_DERIVE_PARAMS>()
        };
    let mut root = [0u8; ROOT_CAPACITY];
    let kdf = CK_ULONG::try_from(kdf).map_err(|_| {
        crate::Error::Rejected(crate::RejectionReason::NativeEncapsulation(
            crate::NativeEncapsulationRejection::KemKdfAbiWidth,
        ))
    })?;
    let information_length = crate::bounds::ck_length(information.map_or(0, <[u8]>::len))?;
    root[kdf_offset..kdf_offset + size_of::<CK_ULONG>()].copy_from_slice(&kdf.to_ne_bytes());
    root[length_offset..length_offset + size_of::<CK_ULONG>()]
        .copy_from_slice(&information_length.to_ne_bytes());
    let blocks = [
        ExtensionBlock {
            initial: &root[..length],
            alignment,
            direction: ExtensionDirection::Input,
        },
        ExtensionBlock {
            initial: information.unwrap_or(&[]),
            alignment: 1,
            direction: ExtensionDirection::Input,
        },
    ];
    let pointers = [
        ExtensionPointer {
            block: 0,
            offset: information_offset,
            target: if information.is_some() {
                ExtensionPointerTarget::Block {
                    block: 1,
                    offset: 0,
                }
            } else {
                ExtensionPointerTarget::Null
            },
        },
        ExtensionPointer {
            block: 0,
            offset: public_offset,
            target: ExtensionPointerTarget::Null,
        },
    ];
    let contract = MechanismExtension::standard(&session.inner, kind, operation);
    consume(ExtensionRequest {
        contract: &contract,
        parameters: ExtensionParameters {
            blocks: &blocks[..if information.is_some() { 2 } else { 1 }],
            pointers: &pointers,
            root: Some(0),
            outputs: &[],
        },
    })
}
