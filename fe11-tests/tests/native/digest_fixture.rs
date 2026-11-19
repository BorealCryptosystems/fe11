// SPDX-License-Identifier: Apache-2.0
//! Explicit real-session producers for caller-fed digest transition cases.
use super::{
    configuration::{select_token, Configuration},
    credentials::Credentials,
    outcome::Failure,
};
use fe11::*;

#[derive(Clone, Copy, PartialEq, Eq)]
pub enum State {
    Absent,
    Initialized,
    Active,
    LocalRefusal,
    Published,
    TicketDropped,
    Closed,
}

impl State {
    pub fn parse(value: &str) -> std::result::Result<Self, Failure> {
        match value {
            "ABSENT" => Ok(Self::Absent),
            "INITIALIZED" => Ok(Self::Initialized),
            "ACTIVE" => Ok(Self::Active),
            "LOCAL_REFUSAL" => Ok(Self::LocalRefusal),
            "PUBLISHED" => Ok(Self::Published),
            "TICKET_DROPPED" => Ok(Self::TicketDropped),
            "CLOSED" => Ok(Self::Closed),
            _ => Err(Failure::Input("digest_state")),
        }
    }
}

pub struct Fixture {
    pub peer: Option<Session>,
    pub subject: Option<AdvancedSession>,
    pub ticket: Option<OperationTicket>,
    pub published: Option<NativeDigest>,
    pub logged_in: bool,
    pub closed: bool,
}

impl Fixture {
    pub fn empty() -> Self {
        Self {
            peer: None,
            subject: None,
            ticket: None,
            published: None,
            logged_in: false,
            closed: false,
        }
    }

    pub fn subject(&self) -> std::result::Result<&AdvancedSession, Failure> {
        self.subject
            .as_ref()
            .ok_or(Failure::Input("digest_subject"))
    }

    pub fn prepare(
        &mut self,
        module: &Module,
        config: &Configuration,
        pins: &Credentials,
        state: State,
    ) -> std::result::Result<(), Failure> {
        let token =
            select_token(module, &config.label).ok_or(Failure::Input("token_not_unique"))?;
        let selected = module.select(&token)?;
        self.peer = Some(selected.open_session(true)?);
        self.peer
            .as_ref()
            .ok_or(Failure::Input("digest_peer"))?
            .login_as(LoginRole::User, SecretPin::new(pins.user.to_vec()))?;
        self.logged_in = true;
        self.subject = Some(selected.open_session(true)?.into_advanced()?);
        if state != State::Absent {
            self.ticket = Some(
                self.subject()?
                    .begin_native_digest(NativeDigestAlgorithm::Sha256)?,
            );
        }
        if matches!(
            state,
            State::Active | State::Published | State::TicketDropped | State::Closed
        ) {
            for part in [b"a".as_slice(), b"bc".as_slice()] {
                self.update(
                    part,
                    InputLimits {
                        maximum_parts: 3,
                        maximum_total_bytes: 3,
                    },
                )?;
            }
        }
        if state == State::LocalRefusal {
            match self.update(
                b"a",
                InputLimits {
                    maximum_parts: 1,
                    maximum_total_bytes: 0,
                },
            ) {
                Err(Failure::Product(Error::Rejected(RejectionReason::ClassicalSignatures(
                    ClassicalSignaturesRejection::CryptoTotalCeiling,
                )))) => (),
                Err(error) => return Err(error),
                Ok(()) => return Err(Failure::Oracle("expected_local_input_ceiling")),
            }
        }
        if state == State::Published {
            self.finish()?;
        }
        if state == State::TicketDropped {
            drop(self.ticket.take());
        }
        if state == State::Closed {
            self.close_subject()?;
        }
        Ok(())
    }

    pub fn update(
        &mut self,
        bytes: &[u8],
        limits: InputLimits,
    ) -> std::result::Result<(), Failure> {
        let owner = self
            .subject
            .as_ref()
            .ok_or(Failure::Input("digest_subject"))?;
        let ticket = self
            .ticket
            .as_mut()
            .ok_or(Failure::Input("digest_ticket"))?;
        owner
            .digest_update(ticket, bytes, limits)
            .map_err(Failure::from)
    }

    pub fn finish(&mut self) -> std::result::Result<(), Failure> {
        let owner = self
            .subject
            .as_ref()
            .ok_or(Failure::Input("digest_subject"))?;
        let ticket = self
            .ticket
            .as_mut()
            .ok_or(Failure::Input("digest_ticket"))?;
        match owner.finish_native_digest(ticket)? {
            OperationProgress::NativeDigest(value) => {
                self.published = Some(value);
                Ok(())
            }
            _ => Err(Failure::Oracle("expected_completed_digest")),
        }
    }

    pub fn close_subject(&mut self) -> std::result::Result<(), Failure> {
        match self.subject()?.close()? {
            AdvancedCloseStatus::Complete => {
                self.closed = true;
                Ok(())
            }
            AdvancedCloseStatus::Pending => Err(Failure::Oracle("cleanup_pending")),
        }
    }

    pub fn cleanup(&mut self) -> Vec<Failure> {
        let mut errors = Vec::new();
        if self.subject.is_some() && !self.closed {
            if let Err(error) = self.close_subject() {
                errors.push(error);
            }
        }
        if let Some(peer) = &self.peer {
            if self.logged_in {
                match peer.logout() {
                    Ok(()) => self.logged_in = false,
                    Err(error) => errors.push(error.into()),
                }
            }
            if let Err(error) = peer.close() {
                errors.push(error.into());
            }
        }
        errors
    }

    pub fn check_output(&self, expected: &[u8]) -> std::result::Result<(), Failure> {
        let value = self
            .published
            .as_ref()
            .ok_or(Failure::Oracle("digest_not_published"))?;
        if value.algorithm() != NativeDigestAlgorithm::Sha256 || value.as_bytes() != expected {
            return Err(Failure::Oracle("digest_known_answer"));
        }
        Ok(())
    }
}
