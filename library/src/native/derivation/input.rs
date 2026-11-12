// SPDX-License-Identifier: Apache-2.0
//! Private recipe bridge; both inputs use the same derivation/creation lifecycle.
use super::{Derivation, DerivationStorage, Parameters};
use crate::{
    attribute_values::InputTemplate,
    mechanism_extension::{
        graph::{recipe::Request, GraphStorage},
        OwnedGraph,
    },
    symmetric::memory::Credit,
    Error, ManagedClass, MechanismLayoutProvenance, NativeKeyDerivation, NativeObjectRef, Result,
};
use fe11_sys::{CK_INVALID_HANDLE, CK_MECHANISM};
use std::{mem::size_of, sync::Arc};

pub(crate) enum Input<'r, 'a> {
    Native(&'r NativeKeyDerivation<'a>),
    Recipe {
        request: Request<'a>,
        class: ManagedClass,
    },
}
pub(crate) enum Storage<'r, 'a> {
    Native(DerivationStorage<'r, 'a>),
    Recipe {
        graph: GraphStorage<'a>,
        request: Request<'a>,
    },
}
fn frame_bytes() -> usize {
    Derivation::frame_bytes(size_of::<OwnedGraph>())
}
impl<'r, 'a> Input<'r, 'a> {
    pub(crate) fn check_extension(&self, inner: &Arc<crate::module::Inner>) -> Result<()> {
        match self {
            Self::Native(input) => input.check_extension(inner),
            Self::Recipe { request, .. } => request
                .contract
                .check(inner, crate::ExtensionOperation::DeriveKey),
        }
    }
    pub(crate) fn layout_provenance(&self) -> MechanismLayoutProvenance {
        match self {
            Self::Native(input) => input.layout_provenance(),
            Self::Recipe { request, .. } => request.contract.provenance(),
        }
    }
    pub(crate) fn mutates_base(&self) -> bool {
        match self {
            Self::Native(input) => input.mutates_base(),
            Self::Recipe { request, .. } => request.contract.mutates_key(),
        }
    }
    pub(crate) fn output_class(&self) -> ManagedClass {
        match self {
            Self::Native(input) => input.output_class(),
            Self::Recipe { class, .. } => *class,
        }
    }
    pub(crate) fn secondary_keys(&self) -> [Option<&'a NativeObjectRef>; 4] {
        match self {
            Self::Native(input) => input.secondary_keys(),
            Self::Recipe { .. } => [None; 4],
        }
    }
    pub(crate) fn allocation_bytes(&self) -> Result<usize> {
        match self {
            Self::Native(input) => Derivation::allocation_bytes(input),
            Self::Recipe { request, .. } => OwnedGraph::recipe_bytes(request.parameters.recipe())?
                .checked_add(frame_bytes())
                .ok_or(Error::Rejected(crate::RejectionReason::NativeDerivation(
                    crate::NativeDerivationRejection::DerivationFrameAccounting,
                ))),
        }
    }
    pub(crate) fn allocate(&self) -> Result<Storage<'r, 'a>> {
        Ok(match self {
            Self::Native(input) => Storage::Native(DerivationStorage::allocate(input)?),
            Self::Recipe { request, .. } => Storage::Recipe {
                graph: GraphStorage::allocate_input(request.parameters)?,
                request: *request,
            },
        })
    }
}
impl Storage<'_, '_> {
    pub(crate) fn allocated_bytes(&self) -> Result<usize> {
        match self {
            Self::Native(storage) => storage.allocated_bytes(),
            Self::Recipe { graph, .. } => graph
                .allocated_bytes()?
                .checked_add(frame_bytes())
                .ok_or(Error::Rejected(crate::RejectionReason::NativeDerivation(
                    crate::NativeDerivationRejection::DerivationFrameAccounting,
                ))),
        }
    }
    pub(crate) fn bind(self, template: InputTemplate, credit: &mut Credit) -> Result<Derivation> {
        match self {
            Self::Native(storage) => storage.bind(template, credit),
            Self::Recipe { graph, request } => {
                let graph = graph.bind(credit)?;
                Ok(Derivation {
                    mechanism: CK_MECHANISM {
                        mechanism: super::native_ulong(request.contract.mechanism_number())?,
                        pParameter: std::ptr::null_mut(),
                        ulParameterLen: 0,
                    },
                    parameters: Parameters::Extension(graph),
                    template,
                    output: CK_INVALID_HANDLE,
                    mutates_base: request.contract.mutates_key(),
                    _credit: credit.split(frame_bytes())?,
                })
            }
        }
    }
}
