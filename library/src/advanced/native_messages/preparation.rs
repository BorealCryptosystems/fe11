// SPDX-License-Identifier: Apache-2.0
//! Empty-parent storage for aggregate admission before session/key possession.
use super::{
    binding::Binding, Execution, InputState, NativeActivity, NativeMessageOperation, Phase,
    ReleasedInput,
};
use crate::mechanism_extension::{
    graph::{recipe, GraphStorage},
    message::initialization::Initialization,
    parameter_keys::ParameterKeys,
    OwnedGraph,
};
use crate::symmetric::memory::Credit;
use crate::{Error, MessageRoute, Result};
use std::mem::size_of;

fn accounting() -> Error {
    Error::Rejected(crate::RejectionReason::NativeMessages(
        crate::NativeMessagesRejection::GenericMessageOwnerAccounting,
    ))
}

pub(super) fn fixed_bytes() -> Result<usize> {
    // The graph accounts for its inline OwnedGraph; its enclosing box must not
    // charge that part a second time. NativeMessageOperation contains the Box
    // pointer, fixed auxiliary identities, and empty (unallocated) vector header.
    size_of::<NativeMessageOperation>()
        .checked_add(super::DIAGNOSTIC_BYTES)
        .and_then(|bytes| bytes.checked_add(size_of::<Initialization>()))
        .and_then(|bytes| bytes.checked_sub(size_of::<OwnedGraph>()))
        .ok_or_else(accounting)
}

pub(super) struct OwnerStorage<'a> {
    request: recipe::Request<'a>,
    keys: ParameterKeys<'a>,
    graph: GraphStorage<'a>,
}

pub(super) struct PreparedOwner {
    initialization: Box<Initialization>,
    diagnostic: Box<Error>,
    metadata: Credit,
}

impl<'a> OwnerStorage<'a> {
    pub(super) fn required_bytes(request: recipe::Request<'_>) -> Result<usize> {
        OwnedGraph::recipe_bytes(request.parameters.recipe())?
            .checked_add(fixed_bytes()?)
            .ok_or_else(accounting)
    }

    /// Called only after aggregate reservation, together with the operation
    /// shell, optional observations, role storage and any revocation candidate.
    pub(super) fn allocate(request: recipe::Request<'a>, keys: ParameterKeys<'a>) -> Result<Self> {
        keys.validate(request.parameters.recipe())?;
        Ok(Self {
            request,
            keys,
            graph: GraphStorage::allocate_input(request.parameters)?,
        })
    }

    pub(super) fn allocated_bytes(&self) -> Result<usize> {
        self.graph
            .allocated_bytes()?
            .checked_add(fixed_bytes()?)
            .ok_or_else(accounting)
    }

    /// The enclosing preparation loop has reconciled actual capacities. No
    /// additional reserve/wait occurs while this partial candidate owns credit.
    pub(super) fn bind(self, prepaid: &mut Credit) -> Result<PreparedOwner> {
        let metadata = prepaid.split(fixed_bytes()?)?;
        let graph = self.graph.bind(prepaid)?;
        Ok(PreparedOwner {
            diagnostic: super::prepared_diagnostic(),
            initialization: Box::new(Initialization::new(
                self.request.contract.native_mechanism(),
                graph,
                self.keys.retain(),
            )),
            metadata,
        })
    }
}

impl PreparedOwner {
    /// Install only after the enclosing transaction rechecks the source module,
    /// route, authentication stamp and every primary/auxiliary native reference.
    /// Binding owns the already acquired roles; this commit allocates nothing.
    pub(super) fn check_binding(
        &self,
        binding: &Binding,
        route: MessageRoute,
        verify: bool,
    ) -> Result<()> {
        let operation = crate::mechanism_extension::message::operation_kind(
            !verify,
            route == MessageRoute::Multipart,
        );
        if self.initialization.kind() != binding.primary.contract.native_mechanism()
            || binding.primary.contract.operation() != operation
            || binding.primary.contract.mutates_key() && !binding.writer
        {
            return Err(Error::Rejected(crate::RejectionReason::NativeMessages(
                crate::NativeMessagesRejection::GenericMessageInitializationBinding,
            )));
        }
        Ok(())
    }

    /// Pure ownership transfer after check_binding under the same possession.
    /// No fallible work or destructor can release a rejected candidate here.
    pub(super) fn finish(
        self,
        binding: Binding,
        route: MessageRoute,
        verify: bool,
    ) -> NativeMessageOperation {
        let expected = self.initialization.expected();
        NativeMessageOperation {
            observer: super::Observer::Ticket,
            binding,
            initialization: Some(self.initialization),
            expected,
            route,
            verify,
            phase: Phase::Init,
            execution: Execution::Running,
            activity: NativeActivity::Inactive,
            input: InputState::open(),
            invalid_seen: false,
            messages: Vec::new(),
            released: ReleasedInput::default(),
            diagnostic: Some(self.diagnostic),
            _metadata: self.metadata,
        }
    }
}
