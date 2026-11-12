// SPDX-License-Identifier: Apache-2.0
//! TokenAdministration causes, separate from native result/effect information.

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[non_exhaustive]
/// Causes belonging to token administration.
#[doc = include_str!("../../../docs/diagnostics/rejection-token_administration.md")]
pub enum TokenAdministrationRejection {
    /// C_GetTokenInfo unavailable. [Detection, owner and recovery](#cause-CGetTokenInfoUnavailable).
    CGetTokenInfoUnavailable,
    /// C_InitPIN unavailable. [Detection, owner and recovery](#cause-CInitPINUnavailable).
    CInitPINUnavailable,
    /// C_InitToken unavailable. [Detection, owner and recovery](#cause-CInitTokenUnavailable).
    CInitTokenUnavailable,
    /// C_SetPIN unavailable. [Detection, owner and recovery](#cause-CSetPINUnavailable).
    CSetPINUnavailable,
    /// Administrative generation stale. [Detection, owner and recovery](#cause-AdministrativeGenerationStale).
    AdministrativeGenerationStale,
    /// Administrative target identity or state changed. [Detection, owner and recovery](#cause-AdministrativeTargetIdentityOrStateChanged).
    AdministrativeTargetIdentityOrStateChanged,
    /// Changed token sessions require close. [Detection, owner and recovery](#cause-ChangedTokenSessionsRequireClose).
    ChangedTokenSessionsRequireClose,
    /// Discovery publication report allocation. [Detection, owner and recovery](#cause-DiscoveryPublicationReportAllocation).
    DiscoveryPublicationReportAllocation,
    /// Foreign administrative target. [Detection, owner and recovery](#cause-ForeignAdministrativeTarget).
    ForeignAdministrativeTarget,
    /// Native PIN input changed. [Detection, owner and recovery](#cause-NativePinInputChanged).
    NativePinInputChanged,
    /// Native token initialization input changed. [Detection, owner and recovery](#cause-NativeTokenInitializationInputChanged).
    NativeTokenInitializationInputChanged,
    /// Refreshed token identity changed. [Detection, owner and recovery](#cause-RefreshedTokenIdentityChanged).
    RefreshedTokenIdentityChanged,
    /// Target token sessions active. [Detection, owner and recovery](#cause-TargetTokenSessionsActive).
    TargetTokenSessionsActive,
    /// Token context replaced. [Detection, owner and recovery](#cause-TokenContextReplaced).
    TokenContextReplaced,
    /// Token generation exhausted. [Detection, owner and recovery](#cause-TokenGenerationExhausted).
    TokenGenerationExhausted,
    /// Token label. [Detection, owner and recovery](#cause-TokenLabel).
    TokenLabel,
    /// Token registry allocation. [Detection, owner and recovery](#cause-TokenRegistryAllocation).
    TokenRegistryAllocation,
    /// Token registry capacity. [Detection, owner and recovery](#cause-TokenRegistryCapacity).
    TokenRegistryCapacity,
    /// Token registry changed after discovery. [Detection, owner and recovery](#cause-TokenRegistryChangedAfterDiscovery).
    TokenRegistryChangedAfterDiscovery,
}

impl std::fmt::Display for TokenAdministrationRejection {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::CGetTokenInfoUnavailable => f.write_str("C_GetTokenInfo unavailable"),
            Self::CInitPINUnavailable => f.write_str("C_InitPIN unavailable"),
            Self::CInitTokenUnavailable => f.write_str("C_InitToken unavailable"),
            Self::CSetPINUnavailable => f.write_str("C_SetPIN unavailable"),
            Self::AdministrativeGenerationStale => f.write_str("administrative generation stale"),
            Self::AdministrativeTargetIdentityOrStateChanged => {
                f.write_str("administrative target identity or state changed")
            }
            Self::ChangedTokenSessionsRequireClose => {
                f.write_str("changed token sessions require close")
            }
            Self::DiscoveryPublicationReportAllocation => {
                f.write_str("discovery publication report allocation")
            }
            Self::ForeignAdministrativeTarget => f.write_str("foreign administrative target"),
            Self::NativePinInputChanged => f.write_str("native PIN input changed"),
            Self::NativeTokenInitializationInputChanged => {
                f.write_str("native token initialization input changed")
            }
            Self::RefreshedTokenIdentityChanged => f.write_str("refreshed token identity changed"),
            Self::TargetTokenSessionsActive => f.write_str("target token sessions active"),
            Self::TokenContextReplaced => f.write_str("token context replaced"),
            Self::TokenGenerationExhausted => f.write_str("token generation exhausted"),
            Self::TokenLabel => f.write_str("token label"),
            Self::TokenRegistryAllocation => f.write_str("token registry allocation"),
            Self::TokenRegistryCapacity => f.write_str("token registry capacity"),
            Self::TokenRegistryChangedAfterDiscovery => {
                f.write_str("token registry changed after discovery")
            }
        }
    }
}
