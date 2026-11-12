// SPDX-License-Identifier: Apache-2.0
//! Authentication causes, separate from native result/effect information.

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[non_exhaustive]
/// Causes belonging to authentication.
#[doc = include_str!("../../../docs/diagnostics/rejection-authentication.md")]
pub enum AuthenticationRejection {
    /// PIN frame accounting. [Detection, owner and recovery](#cause-PinFrameAccounting).
    PinFrameAccounting,
    /// Authentication epoch changed. [Detection, owner and recovery](#cause-AuthenticationEpochChanged).
    AuthenticationEpochChanged,
    /// Authentication epoch exhausted. [Detection, owner and recovery](#cause-AuthenticationEpochExhausted).
    AuthenticationEpochExhausted,
    /// Context authentication requires initialized operation. [Detection, owner and recovery](#cause-ContextAuthenticationRequiresInitializedOperation).
    ContextAuthenticationRequiresInitializedOperation,
    /// Foreign authentication session. [Detection, owner and recovery](#cause-ForeignAuthenticationSession).
    ForeignAuthenticationSession,
    /// Foreign or consumed operation ticket. [Detection, owner and recovery](#cause-ForeignOrConsumedOperationTicket).
    ForeignOrConsumedOperationTicket,
    /// Logout requires live session. [Detection, owner and recovery](#cause-LogoutRequiresLiveSession).
    LogoutRequiresLiveSession,
    /// Missing contextual authentication. [Detection, owner and recovery](#cause-MissingContextualAuthentication).
    MissingContextualAuthentication,

}

impl std::fmt::Display for AuthenticationRejection {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {

            Self::PinFrameAccounting => f.write_str("PIN frame accounting"),
            Self::AuthenticationEpochChanged => f.write_str("authentication epoch changed"),
            Self::AuthenticationEpochExhausted => f.write_str("authentication epoch exhausted"),
            Self::ContextAuthenticationRequiresInitializedOperation => {
                f.write_str("context authentication requires initialized operation")
            }
            Self::ForeignAuthenticationSession => f.write_str("foreign authentication session"),
            Self::ForeignOrConsumedOperationTicket => {
                f.write_str("foreign or consumed operation ticket")
            }
            Self::LogoutRequiresLiveSession => f.write_str("logout requires live session"),
            Self::MissingContextualAuthentication => {
                f.write_str("missing contextual authentication")
            }
        }
    }
}
