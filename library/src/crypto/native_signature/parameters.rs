// SPDX-License-Identifier: Apache-2.0
//! Separate immutable parameter selections from the retained native storage.
use crate::{bounds, Error, Result};
use fe11_sys::*;

/// PKCS#11 3.2 §6.3.16 bounds CK_EDDSA_PARAMS context data to 255 octets.
const EDDSA_CONTEXT_MAX: usize = 255;

/// A call-local selection. Construction copies every borrowed context into the
/// native owner; the selection itself is never retained by a NativeFrame.
#[derive(Clone, Copy)]
pub(crate) enum SignatureParameters<'a> {
    None,
    Pss {
        hash: CK_MECHANISM_TYPE,
        mgf: CK_RSA_PKCS_MGF_TYPE,
        salt_length: CK_ULONG,
    },
    Edwards {
        /// Select the native prehashed variant; do not hash the input here.
        prehash: bool,
        /// Exact domain context, copied without reinterpretation or padding.
        context: &'a [u8],
    },
}

impl SignatureParameters<'_> {
    /// Keep only immutable scalar selections; the native owner is built later.
    pub(crate) fn pss(parameters: CK_RSA_PKCS_PSS_PARAMS) -> Self {
        Self::Pss {
            hash: parameters.hashAlg,
            mgf: parameters.mgf,
            salt_length: parameters.sLen,
        }
    }
}

/// Only these layouts may be reached through this owner's CK_MECHANISM.
/// The context is inline so the complete storage is included in size_of and
/// in the advanced operation's metadata credit, without an extra allocation.
enum OwnedParameters {
    None,
    Pss(CK_RSA_PKCS_PSS_PARAMS),
    Edwards {
        native: CK_EDDSA_PARAMS,
        context: [u8; EDDSA_CONTEXT_MAX],
    },
}

pub(crate) struct SignatureMechanism {
    pub(crate) native: CK_MECHANISM,
    parameters: OwnedParameters,
}

// SAFETY: all parameter data is owned, including the Edwards context. Internal
// pointers are bound only in stable retained storage; moving an unbound owner
// transfers no borrowed data. The frame controls access once native calls begin.
unsafe impl Send for SignatureMechanism {}

impl SignatureMechanism {
    pub(crate) fn new(
        kind: CK_MECHANISM_TYPE,
        parameters: SignatureParameters<'_>,
    ) -> Result<Self> {
        let parameters = match parameters {
            SignatureParameters::None => OwnedParameters::None,
            SignatureParameters::Pss {
                hash,
                mgf,
                salt_length,
            } => OwnedParameters::Pss(CK_RSA_PKCS_PSS_PARAMS {
                hashAlg: hash,
                mgf,
                sLen: salt_length,
            }),
            SignatureParameters::Edwards { prehash, context } => {
                if kind != CKM_EDDSA || context.len() > EDDSA_CONTEXT_MAX {
                    return Err(Error::Rejected(
                        crate::RejectionReason::ClassicalSignatures(
                            crate::ClassicalSignaturesRejection::EddsaMechanismOrContextLength,
                        ),
                    ));
                }
                let mut owned = [0; EDDSA_CONTEXT_MAX];
                owned[..context.len()].copy_from_slice(context);
                OwnedParameters::Edwards {
                    native: CK_EDDSA_PARAMS {
                        phFlag: if prehash { CK_TRUE } else { CK_FALSE },
                        ulContextDataLen: bounds::ck_length(context.len())?,
                        pContextData: std::ptr::null_mut(),
                    },
                    context: owned,
                }
            }
        };
        Ok(Self {
            native: CK_MECHANISM {
                mechanism: kind,
                pParameter: std::ptr::null_mut(),
                ulParameterLen: 0,
            },
            parameters,
        })
    }

    /// Bind only after the containing allocation has reached its stable address.
    /// None and a present Edwards structure with an empty context are distinct
    /// scheme selections; the latter must not become a parameterless mechanism.
    pub(crate) fn bind_parameters(&mut self) -> Result<()> {
        let (pointer, length) = match &mut self.parameters {
            OwnedParameters::None => (std::ptr::null_mut(), 0),
            OwnedParameters::Pss(parameters) => (
                (parameters as *mut CK_RSA_PKCS_PSS_PARAMS).cast(),
                bounds::ck_length(std::mem::size_of::<CK_RSA_PKCS_PSS_PARAMS>())?,
            ),
            OwnedParameters::Edwards { native, context } => {
                native.pContextData = if native.ulContextDataLen == 0 {
                    std::ptr::null_mut()
                } else {
                    context.as_mut_ptr()
                };
                (
                    (native as *mut CK_EDDSA_PARAMS).cast(),
                    bounds::ck_length(std::mem::size_of::<CK_EDDSA_PARAMS>())?,
                )
            }
        };
        self.native.pParameter = pointer;
        self.native.ulParameterLen = length;
        Ok(())
    }

    /// Inspect owned storage and compare pointer identities; never follow a
    /// pointer returned by a module to check whether it still denotes our data.
    pub(crate) fn unchanged(
        &self,
        kind: CK_MECHANISM_TYPE,
        expected: SignatureParameters<'_>,
    ) -> bool {
        if self.native.mechanism != kind {
            return false;
        }
        match (&self.parameters, expected) {
            (OwnedParameters::None, SignatureParameters::None) => {
                self.native.pParameter.is_null() && self.native.ulParameterLen == 0
            }
            (
                OwnedParameters::Pss(actual),
                SignatureParameters::Pss {
                    hash,
                    mgf,
                    salt_length,
                },
            ) => {
                self.native.pParameter
                    == (actual as *const CK_RSA_PKCS_PSS_PARAMS).cast_mut().cast()
                    && self.native.ulParameterLen as usize
                        == std::mem::size_of::<CK_RSA_PKCS_PSS_PARAMS>()
                    && actual.hashAlg == hash
                    && actual.mgf == mgf
                    && actual.sLen == salt_length
            }
            (
                OwnedParameters::Edwards { native, context },
                SignatureParameters::Edwards {
                    prehash,
                    context: expected,
                },
            ) => {
                if expected.len() > EDDSA_CONTEXT_MAX {
                    return false;
                }
                let context_pointer = if expected.is_empty() {
                    std::ptr::null_mut()
                } else {
                    context.as_ptr().cast_mut()
                };
                self.native.pParameter == (native as *const CK_EDDSA_PARAMS).cast_mut().cast()
                    && self.native.ulParameterLen as usize == std::mem::size_of::<CK_EDDSA_PARAMS>()
                    && native.phFlag == (if prehash { CK_TRUE } else { CK_FALSE })
                    && native.ulContextDataLen as usize == expected.len()
                    && native.pContextData == context_pointer
                    && &context[..expected.len()] == expected
                    && context[expected.len()..].iter().all(|byte| *byte == 0)
            }
            _ => false,
        }
    }
}
