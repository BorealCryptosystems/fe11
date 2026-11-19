// SPDX-License-Identifier: Apache-2.0
//! Session ownership and explicit cleanup shared by finite and streamed digest cases.
use super::{
    configuration::{select_token, Configuration},
    outcome::Failure,
};
use fe11::*;

pub enum Owner {
    Session(Session),
    Advanced(AdvancedSession),
}

impl Owner {
    pub fn open(
        module: &Module,
        config: &Configuration,
        advanced: bool,
    ) -> std::result::Result<Self, Failure> {
        let identity =
            select_token(module, &config.label).ok_or(Failure::Input("token_not_unique"))?;
        let session = module.select(&identity)?.open_session(false)?;
        if advanced {
            Ok(Self::Advanced(session.into_advanced()?))
        } else {
            Ok(Self::Session(session))
        }
    }

    pub fn begin(&self, algorithm: NativeDigestAlgorithm) -> Result<OperationTicket> {
        match self {
            Self::Session(session) => session.begin_native_digest(algorithm),
            Self::Advanced(session) => session.begin_native_digest(algorithm),
        }
    }

    pub fn update(&self, ticket: &mut OperationTicket, bytes: &[u8]) -> Result<()> {
        let limits = InputLimits {
            maximum_parts: 1,
            maximum_total_bytes: bytes.len(),
        };
        match self {
            Self::Session(session) => session.digest_update(ticket, bytes, limits),
            Self::Advanced(session) => session.digest_update(ticket, bytes, limits),
        }
    }

    pub fn finish(
        &self,
        ticket: &mut OperationTicket,
    ) -> std::result::Result<NativeDigest, Failure> {
        match self {
            Self::Session(session) => Ok(session.finish_native_digest(ticket)?),
            Self::Advanced(session) => match session.finish_native_digest(ticket)? {
                OperationProgress::NativeDigest(digest) => Ok(digest),
                _ => Err(Failure::Oracle("expected_completed_native_digest")),
            },
        }
    }

    pub fn close(&self) -> Vec<Failure> {
        let result = match self {
            Self::Session(session) => session.close().map_err(Failure::from),
            Self::Advanced(session) => match session.close() {
                Ok(AdvancedCloseStatus::Complete) => Ok(()),
                Ok(AdvancedCloseStatus::Pending) => Err(Failure::Oracle("cleanup_pending")),
                Err(error) => Err(error.into()),
            },
        };
        result.err().into_iter().collect()
    }
}
