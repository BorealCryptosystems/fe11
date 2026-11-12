// SPDX-License-Identifier: Apache-2.0
//! CT-KIP and CMS mechanism composition using the existing typed parameter owners.
use crate::mechanism_extension::parameter_keys::ParameterKeys;
use crate::{
    mechanism_extension::{
        nested::{self, Child},
        operation, transport, MechanismExtension,
    },
    Error, ExtensionBlock, ExtensionDirection, ExtensionInput, ExtensionOperation,
    ExtensionParameters, ExtensionPointer, ExtensionPointerTarget, ExtensionRequest,
    ExtensionResult, GenerationTemplate, InputLimits, ManagedClass, MessageRoute,
    NativeDigestAlgorithm, NativeMacParameters, NativeObjectRef, NativeSignatureParameters,
    NativeTransportParameters, NativeUnwrappedObject, Result, Session,
};
use fe11_sys::*;
use std::{
    ffi::CStr,
    mem::{align_of, offset_of, size_of},
};

/// Standard nested mechanism representation. Its ABI comes from the same typed
/// encoder as a direct operation. The native module decides whether the chosen
/// inner algorithm is meaningful for the enclosing protocol; Fe11 substitutes none.
pub enum NativeNestedMechanism<'a> {
    /// Native MAC parameter layouts, including general/truncated forms.
    Mac(NativeMacParameters<'a>),
    /// Native signature parameter layouts, including PSS and PQC context.
    Signature(NativeSignatureParameters<'a>),
    /// Native encryption/wrapping layouts, including nested OAEP and auxiliary keys.
    Transport(NativeTransportParameters<'a>),
    /// Targetless historical relay layout. Nested meaning is decided by the
    /// module, as for other explicit inner mechanisms; no target is invented.
    SkipjackRelay(crate::NativeSkipjackRelay<'a>),
    /// Digest mechanism, with the explicit SHA-512/t scalar when selected.
    Digest(NativeDigestAlgorithm),
    /// GOST digest with optional exact parameter-set OID.
    GostDigest {
        /// Absent default and present empty values retain distinct pointers.
        oid: Option<&'a [u8]>,
    },
}
impl<'a> NativeNestedMechanism<'a> {
    fn with_parameters<T>(
        self,
        session: &Session,
        route: ExtensionOperation,
        consume: impl FnOnce(ExtensionRequest<'_>, ParameterKeys<'a>) -> Result<T>,
    ) -> Result<T> {
        match self {
            Self::Mac(parameters) => {
                crate::native_mac::with_parameters(session, parameters, route, |request| {
                    consume(request, ParameterKeys::default())
                })
            }
            Self::Signature(parameters) => crate::native_signature::with_parameters(
                session,
                parameters,
                if route == ExtensionOperation::SignRecover {
                    ExtensionOperation::Sign
                } else {
                    route
                },
                |request| consume(request, ParameterKeys::default()),
            ),
            Self::Transport(parameters) => {
                crate::native_transport::with_bound_parameters(session, parameters, route, consume)
            }
            Self::SkipjackRelay(parameters) => crate::native_transport::with_relay_parameters(
                session,
                parameters,
                route,
                |request, _sources| consume(request, ParameterKeys::default()),
            ),
            Self::Digest(algorithm) => {
                let encoded = match algorithm {
                    NativeDigestAlgorithm::Sha512T(t) => Some((t.bits() as CK_ULONG).to_ne_bytes()),
                    _ => None,
                };
                digest_recipe(
                    session,
                    algorithm.mechanism_number() as CK_MECHANISM_TYPE,
                    encoded.as_ref().map(|v| &v[..]),
                    route,
                    consume,
                )
            }
            Self::GostDigest { oid } => digest_recipe(session, CKM_GOSTR3411, oid, route, consume),
        }
    }
}
fn digest_recipe<'a, T>(
    session: &Session,
    kind: CK_MECHANISM_TYPE,
    bytes: Option<&[u8]>,
    route: ExtensionOperation,
    consume: impl FnOnce(ExtensionRequest<'_>, ParameterKeys<'a>) -> Result<T>,
) -> Result<T> {
    let contract = MechanismExtension::standard(&session.inner, kind, route);
    let blocks = [ExtensionBlock {
        initial: bytes.unwrap_or(&[]),
        alignment: align_of::<CK_ULONG>(),
        direction: ExtensionDirection::Input,
    }];
    consume(
        ExtensionRequest {
            contract: &contract,
            parameters: ExtensionParameters {
                blocks: if bytes.is_some() { &blocks } else { &[] },
                pointers: &[],
                root: bytes.map(|_| 0),
                outputs: &[],
            },
        },
        ParameterKeys::default(),
    )
}

/// Exact CK_KIP_PARAMS inputs. hKey is optional for derivation/MAC and ignored
/// natively for wrapping; the seed is ignored natively for MAC. Supplied values
/// remain explicit and owned; absent values are not silently populated.
pub struct NativeKipParameters<'a> {
    /// Desired underlying cryptographic mechanism and exact parameter layout.
    pub mechanism: NativeNestedMechanism<'a>,
    /// Additional key, when the selected native operation uses it.
    pub key: Option<&'a NativeObjectRef>,
    /// Optional seed; None and Some(empty) preserve different pointers.
    pub seed: Option<&'a [u8]>,
}
/// Exact CMS inputs. MIME syntax, DER validity, certificate/key association and
/// attribute acceptance remain native/application decisions. CStr supplies the
/// ABI-required NUL terminator without an unbounded native read of Rust text.
pub struct NativeCmsParameters<'a> {
    /// Optional certificate object; None passes the native zero handle.
    pub certificate: Option<&'a NativeObjectRef>,
    /// Mechanism for signing the constructed CMS attributes.
    pub signing: NativeNestedMechanism<'a>,
    /// None lets the module infer the digest from the signing mechanism.
    pub digest: Option<NativeNestedMechanism<'a>>,
    /// Complete MIME content type, including charset parameters when needed.
    pub content_type: Option<&'a CStr>,
    /// Optional DER-encoded requested CMS attributes.
    pub requested_attributes: Option<&'a [u8]>,
    /// Optional DER-encoded required CMS attributes.
    pub required_attributes: Option<&'a [u8]>,
}
fn put(raw: &mut [u8], offset: usize, value: u64) -> Result<()> {
    let value = CK_ULONG::try_from(value).map_err(|_| {
        Error::Rejected(crate::RejectionReason::NativeProtocols(
            crate::NativeProtocolsRejection::ProtocolScalarAbiWidth,
        ))
    })?;
    raw[offset..offset + size_of::<CK_ULONG>()].copy_from_slice(&value.to_ne_bytes());
    Ok(())
}

pub(crate) fn kip<'a, T>(
    session: &Session,
    parameters: NativeKipParameters<'a>,
    kind: CK_MECHANISM_TYPE,
    route: ExtensionOperation,
    consume: impl FnOnce(
        crate::mechanism_extension::graph::recipe::Request<'_>,
        [Option<&'a NativeObjectRef>; 4],
    ) -> Result<T>,
) -> Result<T> {
    kip_with_bindings(session, parameters, kind, route, |request, keys| {
        consume(request, keys.references()?)
    })
}

pub(crate) fn kip_with_bindings<'a, T>(
    session: &Session,
    parameters: NativeKipParameters<'a>,
    kind: CK_MECHANISM_TYPE,
    route: ExtensionOperation,
    consume: impl FnOnce(
        crate::mechanism_extension::graph::recipe::Request<'_>,
        ParameterKeys<'a>,
    ) -> Result<T>,
) -> Result<T> {
    parameters
        .mechanism
        .with_parameters(session, route, |child, sources| {
            // The parent has one header block and an optional seed block;
            // nested::compose then inserts a CK_MECHANISM before child blocks.
            let parent_blocks = if parameters.seed.is_some() { 2 } else { 1 };
            let mut sources = sources.rebased(parent_blocks + 1)?;
            sources.insert(parameters.key, 0, offset_of!(CK_KIP_PARAMS, hKey))?;
            let contract = MechanismExtension::standard(&session.inner, kind, route)
                .with_nested_contract(child.contract);
            let mut raw = [0; size_of::<CK_KIP_PARAMS>()];
            put(
                &mut raw,
                offset_of!(CK_KIP_PARAMS, hKey),
                parameters.key.map_or(0, |k| k.identity.handle as u64),
            )?;
            put(
                &mut raw,
                offset_of!(CK_KIP_PARAMS, ulSeedLen),
                parameters.seed.map_or(0, |s| s.len()) as u64,
            )?;
            let blocks = [
                ExtensionBlock {
                    initial: &raw,
                    alignment: align_of::<CK_KIP_PARAMS>(),
                    direction: ExtensionDirection::Input,
                },
                ExtensionBlock {
                    initial: parameters.seed.unwrap_or(&[]),
                    alignment: 1,
                    direction: ExtensionDirection::Input,
                },
            ];
            let pointers = [ExtensionPointer {
                block: 0,
                offset: offset_of!(CK_KIP_PARAMS, pSeed),
                target: if parameters.seed.is_some() {
                    ExtensionPointerTarget::Block {
                        block: 1,
                        offset: 0,
                    }
                } else {
                    ExtensionPointerTarget::Null
                },
            }];
            nested::compose(
                session,
                &contract,
                ExtensionParameters {
                    blocks: if parameters.seed.is_some() {
                        &blocks
                    } else {
                        &blocks[..1]
                    },
                    pointers: &pointers,
                    root: Some(0),
                    outputs: &[],
                },
                &[Child {
                    offset: offset_of!(CK_KIP_PARAMS, pMechanism),
                    request: Some(&child),
                }],
                |request| consume(request, sources),
            )
        })
}
pub(crate) fn cms<'a, T>(
    session: &Session,
    parameters: NativeCmsParameters<'a>,
    route: ExtensionOperation,
    consume: impl FnOnce(
        crate::mechanism_extension::graph::recipe::Request<'_>,
        [Option<&'a NativeObjectRef>; 4],
    ) -> Result<T>,
) -> Result<T> {
    cms_with_bindings(session, parameters, route, |request, keys| {
        consume(request, keys.references()?)
    })
}

pub(crate) fn cms_with_bindings<'a, T>(
    session: &Session,
    parameters: NativeCmsParameters<'a>,
    route: ExtensionOperation,
    consume: impl FnOnce(
        crate::mechanism_extension::graph::recipe::Request<'_>,
        ParameterKeys<'a>,
    ) -> Result<T>,
) -> Result<T> {
    parameters
        .signing
        .with_parameters(session, route, |signing, sources| {
            let finish = |digest: Option<&ExtensionRequest<'_>>,
                          digest_sources: ParameterKeys<'a>| {
                let mut contract = MechanismExtension::standard(&session.inner, CKM_CMS_SIG, route)
                    .with_nested_contract(signing.contract);
                if let Some(digest) = digest {
                    contract = contract.with_nested_contract(digest.contract);
                }
                let mut raw = [0; size_of::<CK_CMS_SIG_PARAMS>()];
                put(
                    &mut raw,
                    offset_of!(CK_CMS_SIG_PARAMS, certificateHandle),
                    parameters
                        .certificate
                        .map_or(0, |c| c.identity.handle as u64),
                )?;
                put(
                    &mut raw,
                    offset_of!(CK_CMS_SIG_PARAMS, ulRequestedAttributesLen),
                    parameters.requested_attributes.map_or(0, |b| b.len()) as u64,
                )?;
                put(
                    &mut raw,
                    offset_of!(CK_CMS_SIG_PARAMS, ulRequiredAttributesLen),
                    parameters.required_attributes.map_or(0, |b| b.len()) as u64,
                )?;
                let values = [
                    parameters.content_type.map(CStr::to_bytes_with_nul),
                    parameters.requested_attributes,
                    parameters.required_attributes,
                ];
                let offsets = [
                    offset_of!(CK_CMS_SIG_PARAMS, pContentType),
                    offset_of!(CK_CMS_SIG_PARAMS, pRequestedAttributes),
                    offset_of!(CK_CMS_SIG_PARAMS, pRequiredAttributes),
                ];
                let mut blocks: [ExtensionBlock<'_>; 4] = std::array::from_fn(|_| ExtensionBlock {
                    initial: &[],
                    alignment: 1,
                    direction: ExtensionDirection::Input,
                });
                blocks[0] = ExtensionBlock {
                    initial: &raw,
                    alignment: align_of::<CK_CMS_SIG_PARAMS>(),
                    direction: ExtensionDirection::Input,
                };
                let mut pointers: [ExtensionPointer; 3] =
                    std::array::from_fn(|i| ExtensionPointer {
                        block: 0,
                        offset: offsets[i],
                        target: ExtensionPointerTarget::Null,
                    });
                let mut count = 1;
                for (index, bytes) in values.into_iter().enumerate() {
                    if let Some(bytes) = bytes {
                        blocks[count] = ExtensionBlock {
                            initial: bytes,
                            alignment: 1,
                            direction: ExtensionDirection::Input,
                        };
                        pointers[index].target = ExtensionPointerTarget::Block {
                            block: count,
                            offset: 0,
                        };
                        count += 1;
                    }
                }
                // Preserve child field locations across the exact same
                // block layout used by nested::compose. Alias references
                // may occur in several fields; do not deduplicate fields.
                let mut combined = sources.rebased(count + 1)?;
                combined.insert(
                    parameters.certificate,
                    0,
                    offset_of!(CK_CMS_SIG_PARAMS, certificateHandle),
                )?;
                let digest_base = count
                    .checked_add(1)
                    .and_then(|n| n.checked_add(signing.parameters.blocks.len()))
                    .and_then(|n| n.checked_add(1))
                    .ok_or(Error::Rejected(crate::RejectionReason::NativeProtocols(
                        crate::NativeProtocolsRejection::CmsKeyFieldAccounting,
                    )))?;
                combined.append(digest_sources.rebased(digest_base)?)?;
                nested::compose(
                    session,
                    &contract,
                    ExtensionParameters {
                        blocks: &blocks[..count],
                        pointers: &pointers,
                        root: Some(0),
                        outputs: &[],
                    },
                    &[
                        Child {
                            offset: offset_of!(CK_CMS_SIG_PARAMS, pSigningMechanism),
                            request: Some(&signing),
                        },
                        Child {
                            offset: offset_of!(CK_CMS_SIG_PARAMS, pDigestMechanism),
                            request: digest,
                        },
                    ],
                    |request| consume(request, combined),
                )
            };
            match parameters.digest {
                Some(digest) => digest.with_parameters(session, route, |request, sources| {
                    finish(Some(&request), sources)
                }),
                None => finish(None, ParameterKeys::default()),
            }
        })
}

mod api;
