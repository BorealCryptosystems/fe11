// SPDX-License-Identifier: Apache-2.0
//! Primary writer/read ownership and the auxiliary readers of typed compositions.
use crate::advanced::key_roles::Roles;
use crate::advanced::signature::binding::Binding as Primary;
use crate::managed::NativeIdentity;
use crate::session::activity::AccessMode;
use crate::{Error, NativeObjectRef, Result};
use std::sync::{atomic::Ordering, Arc};

pub(in crate::advanced) struct Binding {
    pub(super) primary: Primary,
    // Selected before Init. A later declared write cannot execute under a
    // reader; admission must request the writer before this process starts.
    pub(super) writer: bool,
    // A restored reader can share an existing writer exclusion. Record the
    // actual permission separately from the declared future effects.
    pub(super) primary_mode: AccessMode,
    // The existing typed composition bound, not a limit on caller message count.
    // Each reference retains its own authority after destination transfer;
    // a primary-only transferred permit cannot stand in for auxiliary readers.
    pub(super) auxiliary: [Option<Auxiliary>; 4],
}

#[derive(Clone)]
pub(super) struct Authority {
    pub(super) roles: Roles,
    pub(super) mode: AccessMode,
    pub(super) own_revocation: bool,
}

#[derive(Clone)]
pub(super) struct Auxiliary {
    pub(super) identity: Arc<NativeIdentity>,
    pub(super) authority: Authority,
}

pub(super) fn same_resource(left: &NativeIdentity, right: &NativeIdentity) -> Result<bool> {
    Ok(left.resource().native() == right.resource().native()
        && Arc::ptr_eq(left.activity()?, right.activity()?))
}

impl Binding {
    /// Initial admission has one role lease covering the whole tuple. Clone
    /// that existing lease per reference; this acquires no additional permit.
    pub(super) fn from_start(
        primary: &mut Option<Primary>,
        writer: bool,
        sources: [Option<&NativeObjectRef>; 4],
    ) -> Result<Self> {
        let candidate =
            primary
                .as_ref()
                .ok_or(Error::Rejected(crate::RejectionReason::NativeMessages(
                    crate::NativeMessagesRejection::MessagePrimaryBindingAbsent,
                )))?;
        let mut auxiliary = std::array::from_fn(|_| None);
        for (index, source) in sources.into_iter().enumerate() {
            if let Some(source) = source {
                let mode = if writer && same_resource(&source.identity, &candidate.key)? {
                    AccessMode::Write
                } else {
                    AccessMode::Read
                };
                auxiliary[index] = Some(Auxiliary {
                    identity: source.identity.clone(),
                    authority: Authority {
                        roles: candidate.roles.clone(),
                        mode,
                        own_revocation: false,
                    },
                });
            }
        }
        Ok(Self {
            primary: primary.take().expect("validated message primary binding"),
            writer,
            primary_mode: if writer {
                AccessMode::Write
            } else {
                AccessMode::Read
            },
            auxiliary,
        })
    }

    pub(in crate::advanced) fn check(&self, entry: &crate::module::SessionEntry) -> Result<()> {
        self.primary.check(entry)?;
        for auxiliary in self.auxiliary.iter().flatten() {
            let key = &auxiliary.identity;
            // A primary stateful operation revokes descriptive aliases before C.
            // An auxiliary reference to that same resource is covered by this
            // owner's writer; unrelated revoked sources are never admitted.
            let own_revocation = auxiliary.authority.own_revocation
                || (self.primary.own_revocation && same_resource(key, &self.primary.key)?);
            if key.revoked.load(Ordering::Acquire) && !own_revocation {
                return Err(Error::Rejected(crate::RejectionReason::NativeMessages(
                    crate::NativeMessagesRejection::RevokedMessageAuxiliaryKey,
                )));
            }
            crate::managed::check_creator(key.creator())?;
            key.access().check(&entry.snapshot)?;
        }
        Ok(())
    }

    /// Borrow only an already held writer for this exact canonical resource.
    /// A source reader never grants an upgrade. The destination still needs
    /// its own session attribution and an explicit matching object reference.
    pub(super) fn writer_for(&self, identity: &NativeIdentity) -> Result<Option<Authority>> {
        if self.primary_mode == AccessMode::Write && same_resource(identity, &self.primary.key)? {
            return Ok(Some(Authority {
                roles: self.primary.roles.clone(),
                mode: AccessMode::Write,
                own_revocation: self.primary.own_revocation,
            }));
        }
        for auxiliary in self.auxiliary.iter().flatten() {
            if auxiliary.authority.mode == AccessMode::Write
                && same_resource(identity, &auxiliary.identity)?
            {
                let mut authority = auxiliary.authority.clone();
                authority.own_revocation |=
                    self.primary.own_revocation && same_resource(identity, &self.primary.key)?;
                return Ok(Some(authority));
            }
        }
        Ok(None)
    }

    pub(in crate::advanced) fn duplicate(&self) -> Result<Self> {
        Ok(Self {
            primary: self.primary.duplicate()?,
            writer: self.writer,
            primary_mode: self.primary_mode,
            auxiliary: self.auxiliary.clone(),
        })
    }

    pub(in crate::advanced) fn arm(&mut self) {
        self.primary.arm();
    }

    pub(in crate::advanced) fn handle(
        &self,
        encoding: crate::advanced::StateKeyEncoding,
    ) -> fe11_sys::CK_OBJECT_HANDLE {
        self.primary.handle(encoding)
    }
}

impl crate::symmetric::memory::RetainedStorage for Binding {
    fn retain_credits(
        &self,
        retained: &mut crate::symmetric::memory::RetainedBytes,
    ) -> crate::Result<()> {
        self.primary.key.retain_identity_credit(retained)?;
        for auxiliary in self.auxiliary.iter().flatten() {
            auxiliary.identity.retain_identity_credit(retained)?;
        }
        // Count the primary's private payload separately from its shared roles:
        // auxiliary authorities may retain that very same permission table.
        self.primary.revocation.retain_credits(retained)?;
        Roles::retain_unique(
            Some(&self.primary.roles),
            self.auxiliary
                .each_ref()
                .map(|auxiliary| auxiliary.as_ref().map(|value| &value.authority.roles)),
            retained,
        )?;
        Ok(())
    }
}
