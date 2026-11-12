// SPDX-License-Identifier: Apache-2.0
//! Prepare local or imported message destinations before native restoration.
//!
//! Capture storage is never an executable binding. Every selected reference is
//! checked in the destination session; native handles are substituted only at
//! encoder-declared input fields. Preparation holds no destination permission
//! while waiting for private storage. Native restoration remains a separate,
//! explicit transaction using the module's opaque state.
use super::{
    binding::{same_resource, Authority, Auxiliary, Binding},
    Execution, NativeMessageOperation,
};
use crate::advanced::{
    key_roles::{PreparedTransfer, Roles},
    key_storage,
};
use crate::mechanism_extension::{
    graph::{recipe, GraphStorage},
    message::initialization::Initialization,
    parameter_keys::{ParameterKeys, ReboundRecipe},
    OwnedGraph,
};
use crate::session::{
    activity::{AccessMode, RolePlan},
    AdmissionProgress, SessionAccess,
};
use crate::symmetric::memory::Credit;
use crate::{Error, NativeObjectRef, ResourceAdmission, Result, Session};
use fe11_sys::CK_INVALID_HANDLE;
use std::{
    mem::size_of,
    sync::{atomic::Ordering, Arc},
};

fn invalid() -> Error {
    Error::Rejected(crate::RejectionReason::NativeMessages(
        crate::NativeMessagesRejection::GenericMessageDestinationBinding,
    ))
}

/// Check the ordinary reference boundary, with only the existing own-writer
/// revocation exception. Canonical resource and Activity were both matched
/// before an inherited authority was selected; handle equality alone is unused.
fn check_reference(
    session: &Session,
    key: &NativeObjectRef,
    authority: Option<&Authority>,
) -> Result<()> {
    if !Arc::ptr_eq(&session.inner, &key.inner)
        || key.identity.handle == CK_INVALID_HANDLE
        || key.identity.session != session.uid
        || key.identity.slot != session.entry.slot
        || key.identity.generation != session.snapshot.generation
        || (key.identity.revoked.load(Ordering::Acquire)
            && !authority.is_some_and(|authority| {
                authority.mode == AccessMode::Write && authority.own_revocation
            }))
    {
        return Err(invalid());
    }
    crate::managed::check_creator(key.identity.creator())?;
    key.identity.access().check(&session.snapshot)
}

/// Imported bytes have no source permission to inherit. Only an actual
/// captured owner can lend its canonical writer authority to the destination.
enum Origin<'a> {
    Captured(&'a NativeMessageOperation),
    Imported {
        contract: crate::MechanismExtension,
        writer: bool,
    },
}
impl Origin<'_> {
    fn contract(&self) -> &crate::MechanismExtension {
        match self {
            Self::Captured(source) => &source.binding.primary.contract,
            Self::Imported { contract, .. } => contract,
        }
    }
    fn writer(&self) -> bool {
        match self {
            Self::Captured(source) => source.binding.writer,
            Self::Imported { writer, .. } => *writer,
        }
    }
    fn check(&self, session: &Session) -> Result<()> {
        if let Self::Captured(source) = self {
            source.check_key(&session.entry)?;
        }
        self.contract()
            .check(&session.inner, self.contract().operation())
    }
    fn inherited(&self, reference: &NativeObjectRef) -> Result<Option<Authority>> {
        match self {
            Self::Captured(source) => source.binding.writer_for(&reference.identity),
            Self::Imported { .. } => Ok(None),
        }
    }
}

pub(in crate::advanced) struct Destination<'a> {
    origin: Origin<'a>,
    references: [Option<&'a NativeObjectRef>; 5],
    inherited: [Option<Authority>; 5],
    transfers: [Option<PreparedTransfer>; 5],
    roles: RolePlan<'a, 5>,
    rebound: ReboundRecipe<'a>,
    storage: key_storage::Ready,
}

/// Retain owned authorities and storage after releasing the source-only
/// references and borrowed graph recipe used to assemble this destination.
pub(in crate::advanced) struct RetiredDestination {
    _contract: Option<crate::MechanismExtension>,
    _inherited: [Option<Authority>; 5],
    _transfers: [Option<PreparedTransfer>; 5],
    _roles: crate::session::activity::RetiredRolePlan<5>,
    _storage: key_storage::Ready,
}
impl<'a> Destination<'a> {
    pub(in crate::advanced) fn retire(self) -> RetiredDestination {
        RetiredDestination {
            _contract: match self.origin {
                Origin::Captured(_) => None,
                Origin::Imported { contract, .. } => Some(contract),
            },
            _inherited: self.inherited,
            _transfers: self.transfers,
            _roles: self.roles.retire(),
            _storage: self.storage,
        }
    }

    pub(in crate::advanced) fn captured(
        session: &Session,
        source: &'a NativeMessageOperation,
        key: &'a NativeObjectRef,
        auxiliary: &[&'a NativeObjectRef],
        extension: Option<&crate::MechanismExtension>,
        destination_parameters: &[Option<&crate::MechanismExtension>],
        progress: &AdmissionProgress,
        authentication: u64,
    ) -> Result<Self> {
        if !matches!(source.execution, Execution::Captured) {
            return Err(invalid());
        }
        source.check_key(&session.entry)?;
        let operation = crate::mechanism_extension::message::operation_kind(
            !source.verify,
            source.route == crate::MessageRoute::Multipart,
        );
        source
            .binding
            .primary
            .contract
            .check(&session.inner, operation)?;
        let declaration = |expected: &crate::MechanismExtension,
                           supplied: &crate::MechanismExtension|
         -> Result<()> {
            supplied.check(&session.inner, operation)?;
            if supplied.native_mechanism() != expected.native_mechanism()
                || supplied.constants_edition() != expected.constants_edition()
                || supplied.mutates_key() != expected.mutates_key()
            {
                return Err(invalid());
            }
            Ok(())
        };
        if let Some(extension) = extension {
            declaration(&source.binding.primary.contract, extension)?;
        }
        let mut parameter_index = 0usize;
        for parameters in source
            .messages
            .iter()
            .flat_map(|row| row.begin.iter().chain(row.parts.iter()))
        {
            if let Some(contract) = &parameters.contract {
                contract.check(&session.inner, operation)?;
            }
            if !destination_parameters.is_empty() {
                match (
                    parameters.contract.as_ref(),
                    destination_parameters
                        .get(parameter_index)
                        .copied()
                        .ok_or_else(invalid)?,
                ) {
                    (Some(expected), Some(supplied)) => declaration(expected, supplied)?,
                    (None, None) => {}
                    _ => return Err(invalid()),
                }
            }
            parameter_index = parameter_index.checked_add(1).ok_or_else(invalid)?;
        }
        if !destination_parameters.is_empty() && parameter_index != destination_parameters.len() {
            return Err(invalid());
        }
        let rebound = source.initialization().rebind(source.expected, auxiliary)?;
        Self::prepare(
            session,
            Origin::Captured(source),
            rebound,
            key,
            progress,
            authentication,
        )
    }

    /// Fresh imported permissions derive exclusively from explicit destination
    /// references. Serialized handles and provenance never create a source role.
    pub(in crate::advanced) fn imported(
        session: &Session,
        record: crate::advanced::record::native_messages::Record<'a>,
        verify: bool,
        key: &'a NativeObjectRef,
        auxiliary: &[&'a NativeObjectRef],
        extension: Option<&crate::MechanismExtension>,
        parameters: &[Option<&crate::MechanismExtension>],
        progress: &AdmissionProgress,
        authentication: u64,
    ) -> Result<Self> {
        let operation = crate::mechanism_extension::message::operation_kind(
            !verify,
            record.header.route == crate::MessageRoute::Multipart,
        );
        let initial = record
            .header
            .initialization
            .declaration
            .ok_or_else(invalid)?;
        let contract = initial.resolve(session, operation, extension, false)?;
        let mut index = 0usize;
        let mut mutates = contract.mutates_key();
        for row in record.iter() {
            let row = row?;
            for parameter in row.begin.into_iter().map(Ok).chain(row.parts.iter()) {
                let parameter = parameter?;
                let supplied = if parameters.is_empty() {
                    None
                } else {
                    parameters.get(index).copied().ok_or_else(invalid)?
                };
                if let Some(declaration) = parameter.declaration {
                    if declaration.mechanism != initial.mechanism {
                        return Err(invalid());
                    }
                    let selected = declaration.resolve(session, operation, supplied, true)?;
                    mutates |= selected.mutates_key();
                } else {
                    use crate::mechanism_extension::graph::recipe::Recipe;
                    let graph =
                        crate::mechanism_extension::graph::snapshot::SnapshotRecipe::decode(
                            parameter.graph.encoded()?,
                        )?;
                    if supplied.is_some()
                        || graph.root().is_some()
                        || graph.block_count() != 0
                        || graph.pointer_count() != 0
                        || graph.output_count() != 0
                    {
                        return Err(invalid());
                    }
                }
                index = index.checked_add(1).ok_or_else(invalid)?;
            }
        }
        if (!parameters.is_empty() && index != parameters.len()) || mutates && !record.header.writer
        {
            return Err(invalid());
        }
        let graph = crate::mechanism_extension::graph::snapshot::SnapshotRecipe::decode(
            record.header.initialization.graph.encoded()?,
        )?;
        let rebound = record.header.locations.rebind_snapshot(graph, auxiliary)?;
        Self::prepare(
            session,
            Origin::Imported {
                contract,
                writer: record.header.writer,
            },
            rebound,
            key,
            progress,
            authentication,
        )
    }

    fn prepare(
        session: &Session,
        origin: Origin<'a>,
        rebound: ReboundRecipe<'a>,
        key: &'a NativeObjectRef,
        progress: &AdmissionProgress,
        authentication: u64,
    ) -> Result<Self> {
        let auxiliary = rebound.keys().references()?;
        let references = [
            Some(key),
            auxiliary[0],
            auxiliary[1],
            auxiliary[2],
            auxiliary[3],
        ];
        let mut inherited = std::array::from_fn(|_| None);
        let mut transfers = std::array::from_fn(|_| None);
        let mut roles = [(None, AccessMode::Read); 5];
        for (index, reference) in references.iter().copied().enumerate() {
            let Some(reference) = reference else { continue };
            inherited[index] = origin.inherited(reference)?;
            check_reference(session, reference, inherited[index].as_ref())?;
            if inherited[index].is_some() {
                // Attribute each shared writer to the destination UID, including
                // aliases used only as auxiliary readers. No read is acquired
                // behind that same retained writer, and no writer is invented.
                transfers[index] = Some(PreparedTransfer::prepare(
                    session,
                    reference.identity.activity()?,
                    progress,
                    authentication,
                )?);
            } else {
                roles[index] = (
                    Some(reference),
                    if index == 0 && origin.writer() {
                        AccessMode::Write
                    } else {
                        AccessMode::Read
                    },
                );
            }
        }
        let roles = RolePlan::prepare_advanced_at_epoch(session, roles, progress, authentication)?;
        Ok(Self {
            origin,
            references,
            inherited,
            transfers,
            roles,
            rebound,
            storage: key_storage::Ready::default(),
        })
    }

    fn needs_revocation(&self) -> bool {
        self.origin.writer()
            && !self.inherited[0]
                .as_ref()
                .is_some_and(|authority| authority.own_revocation)
    }

    pub(in crate::advanced) fn storage_plan(
        &self,
        session: &Session,
        authentication: u64,
    ) -> Result<key_storage::Plan> {
        Ok(key_storage::Plan {
            revocation: self
                .needs_revocation()
                .then(|| {
                    crate::managed::RevocationShape::discover(
                        session,
                        self.references[0].ok_or_else(invalid)?.identity.resource(),
                        authentication,
                    )
                })
                .transpose()?,
            transfers: std::array::from_fn(|index| self.transfers[index].is_some()),
            permissions: 5,
        })
    }

    pub(in crate::advanced) fn attach_storage(&mut self, storage: key_storage::Ready) {
        self.storage = storage;
    }

    pub(in crate::advanced) fn initialization_plan(&self) -> InitializationPlan<'a> {
        InitializationPlan {
            recipe: self.rebound,
            kind: self.origin.contract().native_mechanism(),
        }
    }

    pub(in crate::advanced) fn try_access<'s>(
        &mut self,
        session: &'s Session,
        progress: &AdmissionProgress,
    ) -> Result<(SessionAccess<'s>, Binding)> {
        if self.needs_revocation() != self.storage.revocation.is_some()
            || self.storage.permissions.is_none()
            || (0..5).any(|index| {
                self.transfers[index].is_some() != self.storage.transfers[index].is_some()
            })
        {
            return Err(invalid());
        }
        let permissions = self.storage.permissions.take().ok_or_else(invalid)?;
        // Keep partial role transfers and the bound snapshot until after
        // access leaves on any later binding or provenance refusal.
        let mut authorities: [Option<Authority>; 5] = std::array::from_fn(|_| None);
        let revocation;
        let primary;
        let mut auxiliary;
        let binding;
        let access = self.roles.access_prepared(
            session,
            &ResourceAdmission::Immediate,
            permissions,
            || session.try_advanced_access_progress(progress),
        )?;
        self.origin.check(session)?;
        let primary_key = self.references[0].ok_or_else(invalid)?;
        for (index, reference) in self.references.iter().copied().enumerate() {
            let Some(reference) = reference else { continue };
            check_reference(session, reference, self.inherited[index].as_ref())?;
            let authority = if let Some(source) = &self.inherited[index] {
                let transfer = self.transfers[index].as_ref().ok_or_else(invalid)?;
                Authority {
                    roles: transfer.bind(
                        self.storage.transfers[index].as_ref().ok_or_else(invalid)?,
                        &source.roles,
                    )?,
                    mode: AccessMode::Write,
                    own_revocation: source.own_revocation,
                }
            } else {
                Authority {
                    roles: Roles::Original(access.retain_role_lease()),
                    mode: if self.origin.writer()
                        && same_resource(&reference.identity, &primary_key.identity)?
                    {
                        AccessMode::Write
                    } else {
                        AccessMode::Read
                    },
                    own_revocation: false,
                }
            };
            authorities[index] = Some(authority);
        }
        revocation = self
            .storage
            .revocation
            .as_mut()
            .map(|prepared| {
                prepared
                    .bind(&access)?
                    .ok_or(Error::Busy(crate::BusyReason::NativeMessages(
                        crate::NativeMessagesBusy::MessageDestinationRevocationCapacityChanged,
                    )))
            })
            .transpose()?;
        // Preserve the consumed state only after successful target transfer;
        // failed binding leaves its credited snapshot with the preparation.
        drop(self.storage.revocation.take());
        primary = authorities[0].take().ok_or_else(invalid)?;
        auxiliary = std::array::from_fn(|_| None);
        for (index, reference) in self.references[1..].iter().copied().enumerate() {
            if let Some(reference) = reference {
                auxiliary[index] = Some(Auxiliary {
                    identity: reference.identity.clone(),
                    authority: authorities[index + 1].take().ok_or_else(invalid)?,
                });
            }
        }
        binding = Binding {
            primary: crate::advanced::signature::binding::Binding {
                key: primary_key.identity.clone(),
                authentication: self.roles.authentication(),
                roles: primary.roles,
                contract: self.origin.contract().clone(),
                own_revocation: primary.own_revocation,
                revocation,
            },
            writer: self.origin.writer(),
            primary_mode: primary.mode,
            auxiliary,
        };
        binding.check(&session.entry)?;
        Ok((access, binding))
    }

    pub(in crate::advanced) fn wait_after_contention(
        &mut self,
        session: &Session,
        progress: &AdmissionProgress,
        authentication: u64,
        error: Error,
    ) -> Result<()> {
        // The enclosing caller has already dropped its unpublished frame and
        // buffers. Release every private transfer/permission/revocation credit
        // before waiting, under the original admission context and deadline.
        self.storage = key_storage::Ready::default();
        let policy = crate::admission_wait::current();
        if !matches!(error, Error::Busy(_))
            || (matches!(policy, ResourceAdmission::Immediate)
                && matches!(session.admission(), ResourceAdmission::Immediate))
        {
            return Err(error);
        }
        self.roles.wait_available_in_context(session, &policy, || {
            session.advanced_access_progress_at_epoch(progress, authentication)
        })
    }

    pub(in crate::advanced) fn prepare_with<'s, T>(
        &mut self,
        session: &'s Session,
        progress: &AdmissionProgress,
        authentication: u64,
        mut prepare: impl FnMut(key_storage::Plan) -> Result<(T, key_storage::Ready)>,
    ) -> Result<(T, SessionAccess<'s>, Binding)> {
        loop {
            let (candidate, storage) = prepare(self.storage_plan(session, authentication)?)?;
            self.attach_storage(storage);
            match self.try_access(session, progress) {
                Ok((access, binding)) => return Ok((candidate, access, binding)),
                Err(error @ Error::Busy(_)) => {
                    drop(candidate);
                    self.wait_after_contention(session, progress, authentication, error)?;
                }
                Err(error) => return Err(error),
            }
        }
    }
}

fn initialization_header_bytes() -> Result<usize> {
    size_of::<Initialization>()
        .checked_sub(size_of::<OwnedGraph>())
        .ok_or_else(invalid)
}

pub(in crate::advanced) struct InitializationStorage<'a> {
    graph: GraphStorage<'a>,
    keys: ParameterKeys<'a>,
    kind: fe11_sys::CK_MECHANISM_TYPE,
}
/// Borrowed discovery is independent of mutable role preparation. Its graph
/// and references still belong to the original saved state throughout prepare.
#[derive(Clone, Copy)]
pub(in crate::advanced) struct InitializationPlan<'a> {
    recipe: ReboundRecipe<'a>,
    kind: fe11_sys::CK_MECHANISM_TYPE,
}
impl<'a> InitializationPlan<'a> {
    pub(in crate::advanced) fn allocation_bytes(&self) -> Result<usize> {
        OwnedGraph::recipe_bytes(&self.recipe)?
            .checked_add(initialization_header_bytes()?)
            .ok_or_else(invalid)
    }
    pub(in crate::advanced) fn allocate(&self) -> Result<InitializationStorage<'a>> {
        Ok(InitializationStorage {
            graph: GraphStorage::allocate_input(recipe::Input::Rebound(self.recipe))?,
            keys: self.recipe.keys(),
            kind: self.kind,
        })
    }
}
pub(in crate::advanced) struct PreparedInitialization {
    initialization: Box<Initialization>,
    expected: (
        fe11_sys::CK_MECHANISM_TYPE,
        fe11_sys::CK_VOID_PTR,
        fe11_sys::CK_ULONG,
    ),
    _header: Credit,
}
// SAFETY: every descriptor, graph block and key identity is owned. The graph
// has no native loan; its pointers address stable allocations and this owner
// exposes no concurrent mutation. Once installed, the operation serializes use.
unsafe impl Send for PreparedInitialization {}
impl InitializationStorage<'_> {
    pub(in crate::advanced) fn allocated_bytes(&self) -> Result<usize> {
        self.graph
            .allocated_bytes()?
            .checked_add(initialization_header_bytes()?)
            .ok_or_else(invalid)
    }
    pub(in crate::advanced) fn bind(self, prepaid: &mut Credit) -> Result<PreparedInitialization> {
        let initialization = Box::new(Initialization::new(
            self.kind,
            self.graph.bind(prepaid)?,
            self.keys.retain(),
        ));
        let expected = initialization.expected();
        Ok(PreparedInitialization {
            initialization,
            expected,
            _header: prepaid.split(initialization_header_bytes()?)?,
        })
    }
}
impl PreparedInitialization {
    /// Consume a private prepared graph into a reconstructed owner. Its header
    /// credit joins the parent's metadata before any native/session possession.
    pub(super) fn into_initialization(self, metadata: &mut Credit) -> Result<Box<Initialization>> {
        metadata.merge(self._header)?;
        Ok(self.initialization)
    }

    /// Must succeed before native restoration. It validates representation and
    /// exact retained reference ownership, never mathematical key suitability.
    pub(in crate::advanced) fn check(
        &self,
        body: &NativeMessageOperation,
        binding: &Binding,
    ) -> Result<()> {
        if !matches!(body.execution, Execution::Captured)
            || self.initialization.kind() != body.initialization().kind()
            || binding.primary.contract.native_mechanism() != self.initialization.kind()
            || binding.writer != body.binding.writer
            || !body.unchanged()
            || !self.initialization.unchanged(self.expected)
            || !self
                .initialization
                .snapshot_parts()
                .1
                .matches_references(std::array::from_fn(|index| {
                    binding.auxiliary[index].as_ref().map(|key| &key.identity)
                }))?
        {
            return Err(invalid());
        }
        Ok(())
    }

    /// Infallible after check and successful SetOperationState. Return the
    /// displaced graph with the temporary header credit for destruction after
    /// possession ends; the original state was untouched on every refusal.
    fn exchange_after_success(mut self, body: &mut NativeMessageOperation) -> Self {
        std::mem::swap(
            body.initialization
                .as_mut()
                .expect("validated message initialization"),
            &mut self.initialization,
        );
        body.expected = body.initialization().expected();
        self.expected = self.initialization.expected();
        self
    }
}

/// Replaced native binding retained until guards are released.
pub(in crate::advanced) struct RetiredBinding {
    _binding: Binding,
    _initialization: PreparedInitialization,
}
impl NativeMessageOperation {
    pub(in crate::advanced) fn commit_restoration(
        &mut self,
        mut keys: crate::advanced::restoration_keys::BoundKeys,
        initialization: PreparedInitialization,
    ) -> RetiredBinding {
        let binding = keys
            .take_native_messages()
            .expect("validated generic message destination");
        let initialization = initialization.exchange_after_success(self);
        let binding = std::mem::replace(&mut self.binding, binding);
        self.execution = Execution::Running;
        RetiredBinding {
            _binding: binding,
            _initialization: initialization,
        }
    }

    pub(in crate::advanced) fn retain_refused_binding(
        &mut self,
        keys: &crate::advanced::restoration_keys::BoundKeys,
    ) {
        let Some(destination) = keys.native_messages() else {
            return;
        };
        if !destination.primary.own_revocation {
            return;
        }
        if self.binding.primary_mode == AccessMode::Write
            && matches!(
                same_resource(&self.binding.primary.key, &destination.primary.key),
                Ok(true)
            )
        {
            self.binding.primary.own_revocation = true;
        }
        for key in self.binding.auxiliary.iter_mut().flatten() {
            if key.authority.mode == AccessMode::Write
                && matches!(
                    same_resource(&key.identity, &destination.primary.key),
                    Ok(true)
                )
            {
                key.authority.own_revocation = true;
            }
        }
    }
}
