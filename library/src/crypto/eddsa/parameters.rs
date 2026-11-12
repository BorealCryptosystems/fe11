// SPDX-License-Identifier: Apache-2.0
//! Owned RFC 8032 selections, independent of native pointer layouts.
use super::super::{native_signature::SignatureParameters, public_key::EdwardsCurve};
use crate::{Error, Result};

/// Exact EdDSA instance. Every instance consumes the original message; the
/// prehashed variants ask the PKCS#11 module to perform that instance's hash.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum EdDsaVariant {
    /// Pure Ed25519 without a mechanism parameter or domain context.
    Ed25519,
    /// Ed25519ctx, including its distinct empty-context instance.
    Ed25519Context,
    /// Ed25519ph with its explicit context.
    Ed25519Prehash,
    /// Ed448, with an explicit, possibly empty context.
    Ed448,
    /// Ed448ph with its explicit context.
    Ed448Prehash,
}

/// A complete, immutable EdDSA instance and binary context.
///
/// The inline context uses the normative PKCS#11 maximum of 255 octets.
/// This keeps existing request/profile values Copy without retaining borrowed
/// pointers or allocating shared storage outside their metadata budgets.
/// Context data is public domain separation data; copies are not guaranteed
/// to be erased. Debug deliberately omits its contents.
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct EdDsaParameters {
    variant: EdDsaVariant,
    length: u8,
    context: [u8; 255],
}

impl std::fmt::Debug for EdDsaParameters {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("EdDsaParameters")
            .field("variant", &self.variant)
            .field("context_length", &self.length)
            .finish()
    }
}

impl EdDsaParameters {
    /// Select an exact instance and copy its context. PKCS#11 §6.3.16 allows
    /// up to 255 octets. Pure Ed25519 has no context parameter; use the distinct
    /// Ed25519Context instance for domain separation, even with an empty context.
    pub fn new(variant: EdDsaVariant, context: &[u8]) -> Result<Self> {
        if context.len() > 255 || (variant == EdDsaVariant::Ed25519 && !context.is_empty()) {
            return Err(Error::Rejected(
                crate::RejectionReason::ClassicalSignatures(
                    crate::ClassicalSignaturesRejection::EddsaInstanceOrContextLength,
                ),
            ));
        }
        let mut owned = [0; 255];
        owned[..context.len()].copy_from_slice(context);
        Ok(Self {
            variant,
            length: context.len() as u8,
            context: owned,
        })
    }

    /// Exact requested instance, not an observation of module support.
    pub fn variant(&self) -> EdDsaVariant {
        self.variant
    }

    /// The original binary context, without string conversion or a terminator.
    pub fn context(&self) -> &[u8] {
        &self.context[..usize::from(self.length)]
    }

    pub(crate) fn curve(&self) -> EdwardsCurve {
        match self.variant {
            EdDsaVariant::Ed25519 | EdDsaVariant::Ed25519Context | EdDsaVariant::Ed25519Prehash => {
                EdwardsCurve::Ed25519
            }
            EdDsaVariant::Ed448 | EdDsaVariant::Ed448Prehash => EdwardsCurve::Ed448,
        }
    }

    pub(crate) fn prehash(&self) -> bool {
        matches!(
            self.variant,
            EdDsaVariant::Ed25519Prehash | EdDsaVariant::Ed448Prehash
        )
    }

    pub(crate) fn native(&self) -> SignatureParameters<'_> {
        match self.variant {
            EdDsaVariant::Ed25519 => SignatureParameters::None,
            _ => SignatureParameters::Edwards {
                prehash: self.prehash(),
                context: self.context(),
            },
        }
    }

    pub(crate) fn pure_ed25519(&self) -> bool {
        self.variant == EdDsaVariant::Ed25519
    }
    pub(crate) fn pure_ed448(&self) -> bool {
        self.variant == EdDsaVariant::Ed448 && self.length == 0
    }
}
