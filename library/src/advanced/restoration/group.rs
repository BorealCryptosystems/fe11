// SPDX-License-Identifier: Apache-2.0
//! Correlate native session state with the exact local sources and destinations.
use super::{
    check_restore_target, BoundKeys, OperationTicket, SavedOperationState, StateRestoreKeys,
};
use crate::advanced::{
    ledger, preparation, progress::Stamp, ClassicOperation, Operation, OperationBody,
};
use crate::session::{AdmissionProgress, SessionAccess};
use crate::{Error, RejectionReason, RestorationRejection, Result, Session};
use fe11_sys::{CK_INVALID_HANDLE, CK_OBJECT_HANDLE};
use std::sync::Arc;

fn stale() -> Error {
    Error::Rejected(RejectionReason::Restoration(
        RestorationRejection::StaleReplacementTicket,
    ))
}

fn binding_error() -> Error {
    Error::Rejected(RejectionReason::Restoration(
        RestorationRejection::SavedStateContextMismatch,
    ))
}

pub(super) struct Destination<'a> {
    pub(super) first: Option<&'a OperationTicket>,
    pub(super) peers: &'a [&'a OperationTicket],
}

impl<'a> Destination<'a> {
    pub(super) fn one(first: Option<&'a OperationTicket>) -> Self {
        Self { first, peers: &[] }
    }

    pub(super) fn observe(
        &self,
        session: &Session,
        access: &SessionAccess<'_>,
    ) -> Result<[Option<Stamp>; 5]> {
        let stamps = session.entry.advanced_progress.snapshot()?;
        if stamps.iter().flatten().count() != usize::from(self.first.is_some()) + self.peers.len() {
            return Err(stale());
        }
        let mut seen = [0; 5];
        for (index, ticket) in self
            .first
            .into_iter()
            .chain(self.peers.iter().copied())
            .enumerate()
        {
            if ticket.id == 0
                || ticket.uid != session.uid
                || !Arc::ptr_eq(&ticket.owner, &session.inner)
            {
                return Err(Error::Rejected(RejectionReason::Restoration(
                    RestorationRejection::ForeignOrConsumedReplacementTicket,
                )));
            }
            if seen[..index].contains(&ticket.id) {
                return Err(stale());
            }
            seen[index] = ticket.id;
            let cell = access.operations.get_ticket(ticket.uid, ticket.id)?;
            let member = cell.lock().map_err(|_| Error::Poisoned)?;
            check_restore_target(&member, &session.entry)?;
        }
        Ok(stamps)
    }

    pub(super) fn recheck(
        &self,
        session: &Session,
        access: &SessionAccess<'_>,
        expected: &[Option<Stamp>; 5],
    ) -> Result<()> {
        if self.observe(session, access)? != *expected {
            return Err(stale());
        }
        Ok(())
    }
}

pub(super) enum Bindings<'a> {
    Shared(StateRestoreKeys<'a>),
    Explicit {
        members: &'a [(ClassicOperation, StateRestoreKeys<'a>)],
        native_encryption: Option<ClassicOperation>,
        native_authentication: Option<ClassicOperation>,
    },
}

impl<'a> Bindings<'a> {
    fn member(&self, kind: ClassicOperation) -> Result<StateRestoreKeys<'a>> {
        match self {
            Self::Explicit { members, .. } => kind.select(members),
            Self::Shared(keys) => {
                let mut keys = *keys;
                match kind {
                    ClassicOperation::Digest => {
                        keys.encryption = None;
                        keys.authentication = None;
                    }
                    ClassicOperation::Encrypt | ClassicOperation::Decrypt => {
                        keys.authentication = None;
                    }
                    ClassicOperation::Sign | ClassicOperation::Verify => {
                        keys.encryption = None;
                        keys.extension = None;
                    }
                }
                Ok(keys)
            }
        }
    }

    pub(super) fn primary(&self, saved: &SavedOperationState) -> Result<StateRestoreKeys<'a>> {
        if let Self::Explicit { members, .. } = self {
            if members.len() != 1 + saved.companions.len() {
                return Err(binding_error());
            }
        } else if let Self::Shared(keys) = self {
            if saved.companions.is_empty() {
                return Ok(*keys);
            }
        }
        self.member(ClassicOperation::for_body(&saved.continuation.body)?)
    }

    pub(super) fn native(
        &self,
        saved: &SavedOperationState,
        primary: &BoundKeys,
        group: &RestoreGroup,
    ) -> Result<(CK_OBJECT_HANDLE, CK_OBJECT_HANDLE)> {
        let handle =
            |kind: Option<ClassicOperation>, encryption: bool| -> Result<CK_OBJECT_HANDLE> {
                let Some(kind) = kind else {
                    return Ok(CK_INVALID_HANDLE);
                };
                let bound = if kind == ClassicOperation::for_body(&saved.continuation.body)? {
                    primary
                } else {
                    &group
                        .members
                        .iter()
                        .find(|p| p.kind == kind)
                        .ok_or_else(binding_error)?
                        .keys
                };
                let value = if encryption {
                    bound.native_encryption
                } else {
                    bound.native_authentication
                };
                if value == CK_INVALID_HANDLE {
                    return Err(binding_error());
                }
                Ok(value)
            };
        match self {
            Self::Explicit {
                native_encryption,
                native_authentication,
                ..
            } => Ok((
                handle(*native_encryption, true)?,
                handle(*native_authentication, false)?,
            )),
            Self::Shared(_) => {
                let mut encryption = primary.native_encryption;
                let mut authentication = primary.native_authentication;
                for member in &group.members {
                    merge(&mut encryption, member.keys.native_encryption)?;
                    merge(&mut authentication, member.keys.native_authentication)?;
                }
                Ok((encryption, authentication))
            }
        }
    }
}

fn merge(target: &mut CK_OBJECT_HANDLE, other: CK_OBJECT_HANDLE) -> Result<()> {
    if other != CK_INVALID_HANDLE {
        if *target != CK_INVALID_HANDLE && *target != other {
            return Err(binding_error());
        }
        *target = other;
    }
    Ok(())
}

struct Member {
    kind: ClassicOperation,
    keys: BoundKeys,
    shell: Option<preparation::Shell>,
    cell: Option<ledger::PreparedOperation>,
    installed: Option<Arc<ledger::OperationCell>>,
    id: u64,
    _credit: crate::symmetric::memory::Credit,
}

#[derive(Default)]
pub(in crate::advanced) struct RestoreGroup {
    members: Vec<Member>,
    staged: ledger::StagedOwners,
    registered: bool,
    destination: [Option<Stamp>; 5],
    tickets: Vec<(ClassicOperation, OperationTicket)>,
    retired: DeferredBindings,
}

#[derive(Default)]
pub(super) struct DeferredBindings(
    Vec<(
        BoundKeys,
        crate::symmetric::memory::Credit,
        crate::symmetric::memory::Credit,
    )>,
);

impl RestoreGroup {
    pub(in crate::advanced) fn needs_group_transfer(&self, saved: &SavedOperationState) -> bool {
        !saved.companions.is_empty() || self.destination.iter().flatten().count() > 1
    }

    pub(super) fn take(&mut self) -> Self {
        std::mem::take(self)
    }

    pub(super) fn prepare(
        session: &Session,
        saved: &SavedOperationState,
        bindings: &Bindings<'_>,
        progress: &mut AdmissionProgress,
    ) -> Result<Self> {
        session.entry.advanced_progress.prepare_population(
            1 + saved.companions.len(),
            session,
            progress,
        )?;
        let mut result = Self::default();
        result
            .members
            .try_reserve_exact(saved.companions.len())
            .map_err(|_| binding_error())?;
        result.staged.reserve(saved.companions.len())?;
        result
            .tickets
            .try_reserve_exact(saved.companions.len())
            .map_err(|_| binding_error())?;
        result
            .retired
            .0
            .try_reserve_exact(saved.companions.len())
            .map_err(|_| binding_error())?;
        for peer in &saved.companions {
            let kind = ClassicOperation::for_body(&peer.continuation.body)?;
            let keys = bindings.member(kind)?;
            let mut readers = crate::advanced::keys::restoration::Prepared::captured(
                session,
                &peer.continuation.body,
                keys,
                progress,
                saved.authentication,
            )?;
            let ((shell, cell, credit, footprint), access, mut acquired) =
                readers.prepare_with(session, progress, saved.authentication, |plan| {
                    let bookkeeping = std::mem::size_of::<Member>()
                        + std::mem::size_of::<(ClassicOperation, OperationTicket)>()
                        + std::mem::size_of::<(
                            BoundKeys,
                            crate::symmetric::memory::Credit,
                            crate::symmetric::memory::Credit,
                        )>()
                        + ledger::StagedOwners::member_bytes();
                    let fixed = preparation::Shell::allocation_bytes()
                        .checked_add(ledger::PreparedOperation::allocation_bytes()?)
                        .and_then(|n| n.checked_add(bookkeeping))
                        .ok_or_else(binding_error)?;
                    let mut request = plan.allocation_bytes()?;
                    let (mut prepaid, storage) = loop {
                        let size = fixed.checked_add(request).ok_or_else(binding_error)?;
                        let mut credit =
                            preparation::reserve_new_with_progress(session, size, progress)?;
                        let storage = plan.allocate()?;
                        let actual = storage.allocated_bytes()?;
                        if actual <= request {
                            credit.release(request - actual);
                            break (credit, storage);
                        }
                        request = actual;
                    };
                    let footprint = prepaid.before_split()?;
                    let ready = storage.bind(&mut prepaid)?;
                    let shell = preparation::Shell::from_prepaid(&mut prepaid)?;
                    let cell = ledger::PreparedOperation::from_prepaid(&mut prepaid)?;
                    Ok(((shell, cell, prepaid, footprint), ready))
                })?;
            let mut candidate = None;
            let bound = acquired.bind(keys, |permits| {
                peer.continuation
                    .restore_keys(session, keys, permits, &mut candidate)
            })?;
            let id = access.operations.reserve_ticket()?;
            drop(access);
            progress.retain_additional(&footprint)?;
            result.members.push(Member {
                kind,
                keys: bound,
                shell: Some(shell),
                cell: Some(cell),
                installed: None,
                id,
                _credit: credit,
            });
        }
        Ok(result)
    }

    pub(super) fn remember(&mut self, stamps: [Option<Stamp>; 5]) {
        self.destination = stamps;
    }

    pub(super) fn stage(
        &mut self,
        session: &Session,
        access: &SessionAccess<'_>,
        resident: u64,
    ) -> Result<()> {
        let live = session.entry.advanced_progress.snapshot()?;
        let peers = self
            .destination
            .iter()
            .flatten()
            .filter(|s| s.ticket != resident);
        if live.iter().flatten().count() != 1 + peers.clone().count()
            || !session.entry.advanced_progress.contains(resident)
            || peers
                .into_iter()
                .any(|s| session.entry.advanced_progress.changed(*s))
        {
            return Err(stale());
        }
        if self.registered || self.members.is_empty() {
            return Ok(());
        }
        for member in &mut self.members {
            let (token, cancel) =
                preparation::Shell::bind_retained(&mut member.shell, &access.lease_admission()?)?;
            let mut operation = Operation::new(OperationBody::Control, token, cancel);
            operation.id = member.id;
            let cell = member
                .cell
                .take()
                .expect("unpublished prepared companion cell");
            member.installed = Some(self.staged.add(operation, cell));
        }
        access
            .operations
            .stage_replacement(&session.entry, &mut self.staged)?;
        self.registered = true;
        Ok(())
    }

    pub(super) fn retain_refused_keys(&self, saved: &mut SavedOperationState) {
        for (member, peer) in self.members.iter().zip(&mut saved.companions) {
            match &mut peer.continuation.body {
                OperationBody::Signature(body) => body.retain_refused_binding(&member.keys),
                OperationBody::Cipher(body) => body.retain_refused_binding(&member.keys),
                _ => {}
            }
        }
    }

    pub(super) fn discard(&mut self, session: &Session, access: &SessionAccess<'_>) -> Result<()> {
        if self.registered {
            self.staged = access.operations.discard_staged(&session.entry)?;
            self.registered = false;
        }
        Ok(())
    }

    /// All cells here were constructed privately and no caller has ever had
    /// a ticket for them. The session gate is held through the ledger swap
    /// and these transfers. Every collection was reserved before native Set.
    pub(super) fn finish(
        mut self,
        session: &Session,
        saved: &mut SavedOperationState,
    ) -> (Vec<(ClassicOperation, OperationTicket)>, DeferredBindings) {
        for (member, mut source) in self.members.into_iter().zip(saved.companions.drain(..)) {
            let cell = member
                .installed
                .expect("staged companion after successful Set");
            let mut operation = cell.lock().expect("unexposed staged operation cell");
            let old = source.continuation.bind_restored(member.keys);
            operation.body = source.continuation.body;
            operation.validation = source.continuation.validation;
            operation.provenance = Some(saved.provenance);
            operation._token.authentication = saved.authentication;
            self.retired.0.push((old, source.credit, member._credit));
            self.tickets.push((
                member.kind,
                OperationTicket {
                    owner: session.inner.clone(),
                    uid: session.uid,
                    id: member.id,
                    restored_companions: Vec::new(),
                    validation_report: None,
                    state_provenance: Some(saved.provenance),
                },
            ));
        }
        (self.tickets, self.retired)
    }

    pub(in crate::advanced) fn check_keys(
        &self,
        entry: &crate::module::SessionEntry,
    ) -> Result<()> {
        for member in &self.members {
            member.keys.check(entry)?;
        }
        Ok(())
    }

    pub(in crate::advanced) fn arm_keys(&mut self) {
        for member in &mut self.members {
            member.keys.arm_native_keys();
        }
    }
}
