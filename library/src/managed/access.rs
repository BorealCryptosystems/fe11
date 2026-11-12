// SPDX-License-Identifier: Apache-2.0
//! Object visibility observations and their authentication-context lifetime.

use crate::{
    module::{State, TokenSnapshot},
    AttributeUnavailableCause, Error, Observation, ObservationIssue, Result, Session,
};

#[derive(Clone, Copy)]
pub(super) enum UnknownVisibility {
    NotRequested,
    Unavailable(AttributeUnavailableCause),
    Unusable(ObservationIssue),
}

#[derive(Clone, Copy)]
enum Binding {
    Public,
    Private(u64),
    Unknown {
        observation: UnknownVisibility,
        authentication: u64,
    },
}

/// Constructed only from an actual observation, never from a requested policy.
#[derive(Clone, Copy)]
pub(crate) struct ObjectAccess(Binding);

impl ObjectAccess {
    pub(crate) fn bind(
        snapshot: &TokenSnapshot,
        observation: Observation<bool>,
        authentication: u64,
    ) -> Result<Self> {
        let binding = match observation {
            Observation::Observed(false) => Binding::Public,
            Observation::Observed(true) => Binding::Private(authentication),
            Observation::NotRequested => Binding::Unknown {
                observation: UnknownVisibility::NotRequested,
                authentication,
            },
            Observation::Unavailable(cause) => Binding::Unknown {
                observation: UnknownVisibility::Unavailable(cause),
                authentication,
            },
            Observation::Unusable(issue) => Binding::Unknown {
                observation: UnknownVisibility::Unusable(issue),
                authentication,
            },
            Observation::NativeError {
                function,
                code,
                may_have_effect,
            } => {
                return Err(Error::Native {
                    function,
                    code,
                    may_have_effect,
                })
            }
        };
        let access = Self(binding);
        // This check binds a newly collected report, not native-call authority.
        access.check_observation(snapshot)?;
        Ok(access)
    }

    pub(crate) fn observation(self) -> Observation<bool> {
        match self.0 {
            Binding::Public => Observation::Observed(false),
            Binding::Private(_) => Observation::Observed(true),
            Binding::Unknown { observation, .. } => match observation {
                UnknownVisibility::NotRequested => Observation::NotRequested,
                UnknownVisibility::Unavailable(cause) => Observation::Unavailable(cause),
                UnknownVisibility::Unusable(issue) => Observation::Unusable(issue),
            },
        }
    }

    pub(crate) fn authentication(self) -> Option<u64> {
        match self.0 {
            Binding::Public => None,
            Binding::Private(stamp)
            | Binding::Unknown {
                authentication: stamp,
                ..
            } => Some(stamp),
        }
    }

    pub(crate) fn check(self, snapshot: &TokenSnapshot) -> Result<()> {
        // The reference retains its identity and owners. Past visibility cannot
        // decide whether this handle is usable now; only the native call can.
        snapshot.check()
    }

    fn check_observation(self, snapshot: &TokenSnapshot) -> Result<()> {
        match self.0 {
            Binding::Public => snapshot.check(),
            Binding::Private(stamp) => snapshot.check_authentication(stamp),
            Binding::Unknown { authentication, .. } => {
                snapshot.check_authentication_unchanged(authentication)
            }
        }
    }

    pub(crate) fn result<T>(
        self,
        session: &Session,
        state: &State,
        result: Result<T>,
    ) -> Result<T> {
        match self.0 {
            Binding::Public => session.public_result(state, result),
            Binding::Private(stamp) => session.private_result(state, stamp, result),
            Binding::Unknown { authentication, .. } => {
                session.metadata_result(state, Some(authentication), result)
            }
        }
    }
}
