// SPDX-License-Identifier: Apache-2.0
//! Binding a historical parameter layout to a module, operation and mechanism.
use crate::{configuration::{Budgets, Configuration}, outcome::Failure};
use fe11::*;

#[derive(Clone, Copy)]
pub(super) enum Layout {
    Gcm,
    GcmWithoutIvBits,
    Ccm,
}

impl Layout {
    pub(super) fn parse(text: &str) -> Option<Self> {
        match text {
            "layout-gcm\n" => Some(Self::Gcm),
            "layout-gcm-short\n" => Some(Self::GcmWithoutIvBits),
            "layout-ccm\n" => Some(Self::Ccm),
            _ => None,
        }
    }

    fn mechanism(self) -> u64 {
        match self {
            Self::Ccm => fe11_sys::CKM_AES_CCM as u64,
            _ => fe11_sys::CKM_AES_GCM as u64,
        }
    }

    fn parameters(self, contract: &MechanismExtension) -> NativeTransportParameters<'_> {
        const NONCE: &[u8] = &[0x42; 12];
        match self {
            Self::Gcm => NativeTransportParameters::GcmClassic {
                contract, iv: NONCE, iv_bits: 96, aad: None, tag_bits: 128,
            },
            Self::GcmWithoutIvBits => NativeTransportParameters::GcmClassicWithoutIvBits {
                contract, iv: NONCE, aad: None, tag_bits: 128,
            },
            Self::Ccm => NativeTransportParameters::CcmClassic {
                contract, data_bytes: 16, nonce: NONCE, aad: None, mac_bytes: 16,
            },
        }
    }

    fn declare(self, module: &Module, operation: ExtensionOperation) -> fe11::Result<MechanismExtension> {
        // SAFETY: the pinned module rejects both GCM and CCM in WrapKey and
        // UnwrapKey before inspecting pParameter. Neither operation reads,
        // writes or retains parameter storage or mutates an input key. Only
        // these two mechanisms and these two operations are used here.
        unsafe { module.declare_mechanism_extension(self.mechanism(), (2, 40), operation, false) }
    }

    pub(super) fn replace_module(self, module: &mut Module, config: &Configuration)
        -> std::result::Result<MechanismExtension, Failure>
    {
        let prior = self.declare(module, ExtensionOperation::WrapKey)?;
        module.close()?;
        *module = config.open(&Budgets::ordinary())?;
        Ok(prior)
    }

    pub(super) fn check(
        self, module: &Module, session: &Session, prior: &MechanismExtension,
        wrapping_key: &NativeObjectRef, target: &NativeObjectRef,
    ) -> std::result::Result<(), Failure> {
        let other = match self { Self::Ccm => Self::Gcm, _ => Self::Ccm };
        let wrong_operation = self.declare(module, ExtensionOperation::UnwrapKey)?;
        let wrong_mechanism = other.declare(module, ExtensionOperation::WrapKey)?;
        let owner_or_operation = RejectionReason::MechanismExtensions(
            MechanismExtensionsRejection::MechanismExtensionModuleFunctionMismatch,
        );
        let number = RejectionReason::NativeTransport(
            NativeTransportRejection::HistoricalTransportMechanismLayoutMismatch,
        );
        let before = module.call_counts()?;
        for (declaration, expected) in [
            (prior, &owner_or_operation),
            (&wrong_operation, &owner_or_operation),
            (&wrong_mechanism, &number),
        ] {
            match session.wrap_native_key(wrapping_key, target, self.parameters(declaration), 64) {
                Err(Error::Rejected(reason)) if &reason == expected => (),
                Err(error) => return Err(error.into()),
                Ok(_) => return Err(Failure::Oracle("layout_mismatch_accepted")),
            }
        }
        if module.call_counts()? != before {
            return Err(Failure::Oracle("layout_mismatch_dispatched"));
        }
        Ok(())
    }
}
