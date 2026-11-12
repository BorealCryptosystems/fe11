// SPDX-License-Identifier: Apache-2.0
//! Arbitrary parameter storage for the existing classic cipher transitions.
//!
//! Archive metadata describes an ABI but grants no permission to call it. A
//! reconstructed frame remains unpublished until its destination declaration is
//! checked and bound. The opaque native state is restored separately, without Init.
use crate::mechanism_extension::graph::{recipe, GraphStorage, OwnedGraph};
use crate::symmetric::memory::{Buffer, Credit};
use crate::{Error, ExtensionOperation, ExtensionResult, MechanismExtension, Result};
use fe11_sys::{CK_MECHANISM, CK_MECHANISM_TYPE, CK_ULONG};

#[derive(Clone, Copy, PartialEq, Eq)]
pub(in crate::advanced) struct Metadata {
    pub(super) mechanism: CK_MECHANISM_TYPE,
    pub(super) edition: (u8, u8),
    pub(super) caller_asserted: bool,
    pub(super) mutates_key: bool,
    pub(super) operation: ExtensionOperation,
}
impl Metadata {
    fn from_contract(contract: &MechanismExtension) -> Self {
        Self {
            mechanism: contract.native_mechanism(),
            edition: contract.constants_edition(),
            caller_asserted: contract.provenance()
                == crate::MechanismLayoutProvenance::CallerAssertedLayout,
            mutates_key: contract.mutates_key(),
            operation: contract.operation(),
        }
    }
}

/// The two origins remain distinct throughout preparation. An archive cannot
/// manufacture a safe or caller-asserted declaration by selecting a provenance bit.
#[derive(Clone, Copy)]
pub(in crate::advanced) enum Source<'a> {
    Declared(recipe::Request<'a>),
    Archived {
        metadata: Metadata,
        parameters: recipe::Input<'a>,
    },
}
impl<'a> Source<'a> {
    pub(super) fn from_record(
        descriptor: crate::advanced::record::Descriptor,
        extension: crate::advanced::record::cipher_extension::CipherExtension<'a>,
    ) -> Result<Self> {
        use crate::advanced::record::Family;
        let operation = match descriptor.family {
            Family::CipherEncrypt => ExtensionOperation::Encrypt,
            Family::CipherDecrypt => ExtensionOperation::Decrypt,
            _ => {
                return Err(Error::Rejected(crate::RejectionReason::CipherContinuation(
                    crate::CipherContinuationRejection::CipherGraphRecordFamily,
                )))
            }
        };
        Ok(Self::Archived {
            metadata: Metadata {
                mechanism: CK_MECHANISM_TYPE::try_from(descriptor.mechanism).map_err(|_| {
                    Error::Rejected(crate::RejectionReason::CipherContinuation(
                        crate::CipherContinuationRejection::CipherExtensionMechanismWidth,
                    ))
                })?,
                edition: extension.edition,
                caller_asserted: extension.caller_asserted,
                mutates_key: extension.mutates_key,
                operation,
            },
            parameters: recipe::Input::Snapshot(
                crate::mechanism_extension::graph::snapshot::SnapshotRecipe::decode(
                    extension.graph.encoded()?,
                )?,
            ),
        })
    }
    pub(super) fn record_route(self, route: crate::MessageRoute) -> Result<Self> {
        let Self::Archived {
            mut metadata,
            parameters,
        } = self
        else {
            return Err(Error::Rejected(crate::RejectionReason::CipherContinuation(
                crate::CipherContinuationRejection::RecordRouteRequiresArchivedCipherGraph,
            )));
        };
        metadata.operation = match (metadata.operation, route) {
            (ExtensionOperation::Encrypt, crate::MessageRoute::Multipart) => {
                ExtensionOperation::EncryptMultipart
            }
            (ExtensionOperation::Decrypt, crate::MessageRoute::Multipart) => {
                ExtensionOperation::DecryptMultipart
            }
            (operation, crate::MessageRoute::Single) => operation,
            _ => {
                return Err(Error::Rejected(crate::RejectionReason::CipherContinuation(
                    crate::CipherContinuationRejection::CipherGraphRecordRoute,
                )))
            }
        };
        Ok(Self::Archived {
            metadata,
            parameters,
        })
    }
    pub(super) fn metadata(self) -> Metadata {
        match self {
            Self::Declared(request) => Metadata::from_contract(request.contract),
            Self::Archived { metadata, .. } => metadata,
        }
    }
    pub(super) fn parameters(self) -> recipe::Input<'a> {
        match self {
            Self::Declared(request) => request.parameters,
            Self::Archived { parameters, .. } => parameters,
        }
    }
    pub(super) fn allocation_bytes(self) -> Result<usize> {
        OwnedGraph::recipe_bytes(self.parameters().recipe())
    }
    pub(super) fn check_route(self, route: crate::MessageRoute) -> Result<()> {
        let matches = match route {
            crate::MessageRoute::Single => matches!(
                self.metadata().operation,
                ExtensionOperation::Encrypt | ExtensionOperation::Decrypt
            ),
            crate::MessageRoute::Multipart => matches!(
                self.metadata().operation,
                ExtensionOperation::EncryptMultipart | ExtensionOperation::DecryptMultipart
            ),
        };
        if !matches {
            return Err(Error::Rejected(crate::RejectionReason::CipherContinuation(
                crate::CipherContinuationRejection::ExtensionCipherRouteDeclaration,
            )));
        }
        Ok(())
    }
    pub(super) fn check_start(
        self,
        session: &crate::Session,
        decrypt: bool,
        route: crate::MessageRoute,
    ) -> Result<()> {
        let Self::Declared(request) = self else {
            return Err(Error::Rejected(crate::RejectionReason::CipherContinuation(
                crate::CipherContinuationRejection::ArchivedCipherParametersCannotAuthorizeInit,
            )));
        };
        let operation = match (decrypt, route) {
            (false, crate::MessageRoute::Single) => ExtensionOperation::Encrypt,
            (false, crate::MessageRoute::Multipart) => ExtensionOperation::EncryptMultipart,
            (true, crate::MessageRoute::Single) => ExtensionOperation::Decrypt,
            (true, crate::MessageRoute::Multipart) => ExtensionOperation::DecryptMultipart,
        };
        request.contract.check(&session.inner, operation)
    }
}

pub(in crate::advanced) struct Storage<'a> {
    source: Source<'a>,
    graph: GraphStorage<'a>,
}
impl<'a> Storage<'a> {
    pub(super) fn allocate(source: Source<'a>) -> Result<Self> {
        Ok(Self {
            graph: GraphStorage::allocate_input(source.parameters())?,
            source,
        })
    }
    pub(super) fn allocated_bytes(&self) -> Result<usize> {
        self.graph.allocated_bytes()
    }
    /// The enclosing cipher admits the graph and all input/output storage together.
    /// Binding occurs before native possession and retains every actual capacity.
    pub(super) fn bind(self, prepaid: &mut Credit) -> Result<Frame> {
        let metadata = self.source.metadata();
        let declaration = match self.source {
            Source::Declared(request) => Declaration::Bound(request.contract.clone()),
            Source::Archived { .. } => Declaration::Unbound,
        };
        let mut graph = self.graph.bind(prepaid)?;
        let (pointer, length) = graph.projection();
        Ok(Frame {
            metadata,
            declaration,
            graph: Some(graph),
            pointer: pointer as usize,
            length,
            mechanism: Box::new(CK_MECHANISM {
                mechanism: metadata.mechanism,
                pParameter: pointer,
                ulParameterLen: length,
            }),
        })
    }
}

enum Declaration {
    Unbound,
    Bound(MechanismExtension),
}
pub(super) struct Frame {
    pub(super) metadata: Metadata,
    declaration: Declaration,
    // None only after terminal publication transfers this graph and its credit.
    graph: Option<OwnedGraph>,
    pub(super) mechanism: Box<CK_MECHANISM>,
    pointer: usize,
    length: CK_ULONG,
}
// SAFETY: every native pointer targets a stable allocation owned by this frame.
// Access and native memory loans are governed by the containing CipherOperation.
unsafe impl Send for Frame {}
impl Frame {
    pub(super) fn record(
        &self,
    ) -> Result<crate::advanced::record::cipher_extension::CipherExtension<'_>> {
        self.validate_for_call()?;
        Ok(crate::advanced::record::cipher_extension::CipherExtension {
            graph: crate::advanced::record::signature::Graph::Live(self.graph()?),
            edition: self.metadata.edition,
            caller_asserted: self.metadata.caller_asserted,
            mutates_key: self.metadata.mutates_key,
        })
    }
    pub(super) fn graph(&self) -> Result<&OwnedGraph> {
        self.graph
            .as_ref()
            .ok_or(Error::Rejected(crate::RejectionReason::CipherContinuation(
                crate::CipherContinuationRejection::CipherExtensionGraphAlreadyPublished,
            )))
    }
    pub(super) fn source(&self) -> Result<Source<'_>> {
        let parameters = recipe::Input::Generated(self.graph()?);
        Ok(match &self.declaration {
            Declaration::Bound(contract) => Source::Declared(recipe::Request {
                contract,
                parameters,
            }),
            Declaration::Unbound => Source::Archived {
                metadata: self.metadata,
                parameters,
            },
        })
    }
    pub(super) fn validate(&self) -> Result<()> {
        if self.mechanism.mechanism != self.metadata.mechanism
            || self.mechanism.pParameter as usize != self.pointer
            || self.mechanism.ulParameterLen != self.length
            || !self.graph()?.unchanged()
        {
            return Err(Error::Rejected(crate::RejectionReason::CipherContinuation(
                crate::CipherContinuationRejection::CipherExtensionParameterIdentity,
            )));
        }
        Ok(())
    }
    pub(super) fn validate_for_call(&self) -> Result<()> {
        self.contract()?;
        self.validate()
    }
    pub(super) fn fill_request(&mut self, source: Source<'_>) -> Result<()> {
        if source.metadata() != self.metadata {
            return Err(Error::Rejected(crate::RejectionReason::CipherContinuation(
                crate::CipherContinuationRejection::CipherExtensionPreparationChanged,
            )));
        }
        // GraphStorage already copied and relocated the exact immutable recipe.
        self.validate()
    }
    pub(super) fn contract(&self) -> Result<&MechanismExtension> {
        match &self.declaration {
            Declaration::Bound(contract) => Ok(contract),
            Declaration::Unbound => {
                Err(Error::Rejected(crate::RejectionReason::CipherContinuation(
                    crate::CipherContinuationRejection::CipherDestinationAbiDeclarationAbsent,
                )))
            }
        }
    }
    pub(super) fn bind_contract(&mut self, contract: MechanismExtension) -> Result<()> {
        self.check_contract(&contract)?;
        self.bind_checked_contract(contract);
        Ok(())
    }
    pub(super) fn check_contract(&self, contract: &MechanismExtension) -> Result<()> {
        if Metadata::from_contract(contract) != self.metadata {
            return Err(Error::Rejected(crate::RejectionReason::CipherContinuation(
                crate::CipherContinuationRejection::CipherDestinationAbiDeclarationMismatch,
            )));
        }
        Ok(())
    }
    /// Install only after check_contract succeeds for this frame and contract.
    pub(super) fn bind_checked_contract(&mut self, contract: MechanismExtension) {
        self.declaration = Declaration::Bound(contract);
    }
    pub(super) fn finish(&mut self) -> Result<()> {
        self.validate()?;
        self.graph
            .as_mut()
            .ok_or(Error::Rejected(crate::RejectionReason::CipherContinuation(
                crate::CipherContinuationRejection::CipherGraphAbsent,
            )))?
            .finish()
    }
    pub(super) fn publish(&mut self, mut bytes: Buffer) -> Result<ExtensionResult> {
        let provenance = self.contract()?.provenance();
        let native_output_origin = bytes.as_mut().as_mut_ptr() as usize;
        let parameters = self.graph.take().ok_or(Error::Rejected(
            crate::RejectionReason::CipherContinuation(
                crate::CipherContinuationRejection::CipherGraphAlreadyPublished,
            ),
        ))?;
        Ok(ExtensionResult {
            bytes,
            native_output_origin,
            parameters,
            provenance,
        })
    }
}

impl crate::symmetric::memory::RetainedStorage for Frame {
    fn retain_credits(
        &self,
        retained: &mut crate::symmetric::memory::RetainedBytes,
    ) -> crate::Result<()> {
        self.graph.retain_credits(retained)?;
        Ok(())
    }
}
