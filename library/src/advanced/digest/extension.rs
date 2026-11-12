// SPDX-License-Identifier: Apache-2.0
//! Extension graphs belong to the existing digest frame and native transitions.
use crate::mechanism_extension::{MechanismExtension, OwnedGraph};
use crate::symmetric::memory::Buffer;
use crate::{ExtensionResult, Result};
use fe11_sys::{CK_MECHANISM, CK_ULONG};

fn operation(route: crate::MessageRoute) -> crate::ExtensionOperation {
    match route {
        crate::MessageRoute::Single => crate::ExtensionOperation::Digest,
        crate::MessageRoute::Multipart => crate::ExtensionOperation::DigestMultipart,
    }
}

/// A local capture already owns its module-bound declaration. An explicit
/// destination declaration must agree; it cannot change the retained ABI.
pub(in crate::advanced) fn captured_contract(
    session: &crate::Session,
    source: &super::DigestOperation,
    supplied: Option<&MechanismExtension>,
) -> Result<Option<MechanismExtension>> {
    let Some(parameters) = &source.frame.extension else {
        return if supplied.is_none() {
            Ok(None)
        } else {
            Err(crate::Error::Rejected(
                crate::RejectionReason::DigestContinuation(
                    crate::DigestContinuationRejection::DeclarationOnATypedDigest,
                ),
            ))
        };
    };
    let original = &parameters.contract;
    let native = operation(source.frame.selection.route());
    original.check(&session.inner, native)?;
    if let Some(supplied) = supplied {
        check_declaration(
            session,
            supplied,
            native,
            original.mechanism_number(),
            original.constants_edition(),
        )?;
    }
    Ok(Some(original.clone()))
}

/// Archive bytes describe storage, not permission to invoke a caller-defined
/// ABI. Only a destination declaration supplied by the caller can grant that.
pub(in crate::advanced) fn import_contract(
    session: &crate::Session,
    descriptor: super::record::Descriptor,
    messages: &super::record::Messages<'_>,
    supplied: Option<&MechanismExtension>,
) -> Result<Option<MechanismExtension>> {
    // Other families own their representation and have already validated it.
    // In particular an AEAD stream is not a sequence of typed digest records.
    if descriptor.family != super::record::Family::Digest {
        return if supplied.is_none() {
            Ok(None)
        } else {
            Err(crate::Error::Rejected(
                crate::RejectionReason::DigestContinuation(
                    crate::DigestContinuationRejection::DigestDeclarationFamily,
                ),
            ))
        };
    }
    let first = messages.iter().next().transpose()?;
    let parameters = first.and_then(|message| message.params.digest_extension);
    let Some(parameters) = parameters else {
        return if supplied.is_none() {
            Ok(None)
        } else {
            Err(crate::Error::Rejected(
                crate::RejectionReason::DigestContinuation(
                    crate::DigestContinuationRejection::DeclarationWithoutDigestExtension,
                ),
            ))
        };
    };
    let selection = super::DigestSelection::from_descriptor(descriptor)?;
    let native = operation(selection.route());
    let contract = if parameters.caller_asserted {
        supplied
            .ok_or(crate::Error::Rejected(
                crate::RejectionReason::DigestContinuation(crate::DigestContinuationRejection::DigestImportRequiresADestinationAbiDeclaration),
            ))?
            .clone()
    } else {
        // Restoration never replays Init from this graph. The module receives
        // its opaque C_GetOperationState bytes through C_SetOperationState.
        MechanismExtension::standard(&session.inner, selection.mechanism(), native)
    };
    check_declaration(
        session,
        &contract,
        native,
        descriptor.mechanism,
        parameters.edition,
    )?;
    if let Some(supplied) = supplied {
        check_declaration(
            session,
            supplied,
            native,
            descriptor.mechanism,
            parameters.edition,
        )?;
    }
    Ok(Some(contract))
}

fn check_declaration(
    session: &crate::Session,
    contract: &MechanismExtension,
    native: crate::ExtensionOperation,
    mechanism: u64,
    edition: (u8, u8),
) -> Result<()> {
    contract.check(&session.inner, native)?;
    if contract.mechanism_number() != mechanism
        || contract.constants_edition() != edition
        || contract.mutates_key()
    {
        return Err(crate::Error::Rejected(
            crate::RejectionReason::DigestContinuation(
                crate::DigestContinuationRejection::DigestDestinationDeclarationMismatch,
            ),
        ));
    }
    Ok(())
}

impl super::DigestOperation {
    pub(in crate::advanced) fn digest_output_preparation(
        &self,
        capacity: usize,
    ) -> Result<(usize, usize)> {
        let super::Step::OutputRequired { required, .. } = self.step else {
            return Err(crate::Error::Rejected(
                crate::RejectionReason::DigestContinuation(
                    crate::DigestContinuationRejection::DigestOutputIsNotAwaitingStorage,
                ),
            ));
        };
        if self.activity.pending() {
            return Err(crate::Error::Rejected(
                crate::RejectionReason::DigestContinuation(
                    crate::DigestContinuationRejection::DigestPendingOutputOwner,
                ),
            ));
        }
        crate::bounds::ck_length(capacity)?;
        // The reported size is an observation. The caller may deliberately
        // provide less storage and receive another unchanged native refusal.
        Ok((required, self.frame.output.capacity()))
    }

    pub(in crate::advanced) fn attach_digest_output(
        &mut self,
        capacity: usize,
        output: Buffer,
    ) -> Result<Option<Buffer>> {
        self.digest_output_preparation(capacity)?;
        let super::Step::OutputRequired { single, .. } = self.step else {
            unreachable!("validated digest output wait")
        };
        if output.capacity() < capacity {
            return Err(crate::Error::Rejected(
                crate::RejectionReason::DigestContinuation(
                    crate::DigestContinuationRejection::DigestReplacementStorage,
                ),
            ));
        }
        *self.frame.length = crate::bounds::ck_length(capacity)?;
        use super::DigestSelection;
        self.frame.selection = match self.frame.selection {
            DigestSelection::Extension {
                mechanism, route, ..
            } => DigestSelection::Extension {
                mechanism,
                route,
                capacity,
            },
            DigestSelection::Native(crate::NativeDigestAlgorithm::Null(_)) => {
                DigestSelection::Native(crate::NativeDigestAlgorithm::Null(
                    crate::NativeNullDigestCapacity::new(capacity)?,
                ))
            }
            DigestSelection::NativeSingle(crate::NativeDigestAlgorithm::Null(_)) => {
                DigestSelection::NativeSingle(crate::NativeDigestAlgorithm::Null(
                    crate::NativeNullDigestCapacity::new(capacity)?,
                ))
            }
            selection => selection,
        };
        self.step = if single {
            super::Step::Single
        } else {
            super::Step::Final
        };
        Ok(Some(std::mem::replace(&mut self.frame.output, output)))
    }
}

pub(in crate::advanced) struct Parameters {
    pub(super) contract: MechanismExtension,
    pub(super) graph: OwnedGraph,
    pointer: usize,
    length: CK_ULONG,
}
impl Parameters {
    pub(super) fn new(contract: MechanismExtension, graph: OwnedGraph) -> Self {
        Self {
            contract,
            graph,
            pointer: 0,
            length: 0,
        }
    }
    pub(super) fn attach(&mut self, mechanism: &mut CK_MECHANISM) {
        let (pointer, length) = self.graph.projection();
        self.pointer = pointer as usize;
        self.length = length;
        mechanism.mechanism = self.contract.native_mechanism();
        mechanism.pParameter = pointer;
        mechanism.ulParameterLen = length;
    }
    pub(super) fn unchanged(&self, mechanism: &CK_MECHANISM) -> bool {
        mechanism.mechanism == self.contract.native_mechanism()
            && mechanism.pParameter as usize == self.pointer
            && mechanism.ulParameterLen == self.length
            && self.graph.unchanged()
    }
    pub(in crate::advanced) fn record(
        &self,
        _step: super::Step,
    ) -> super::record::digest_extension::DigestExtension<'_> {
        super::record::digest_extension::DigestExtension {
            graph: super::record::signature::Graph::Live(&self.graph),
            edition: self.contract.constants_edition(),
            caller_asserted: self.contract.provenance()
                == crate::MechanismLayoutProvenance::CallerAssertedLayout,
        }
    }
    pub(super) fn finish(&mut self) -> Result<()> {
        self.graph.finish()
    }
    pub(in crate::advanced) fn result(self, bytes: &mut Buffer) -> ExtensionResult {
        let origin = bytes.as_mut().as_mut_ptr() as usize;
        ExtensionResult {
            bytes: bytes.take(),
            native_output_origin: origin,
            parameters: self.graph,
            provenance: self.contract.provenance(),
        }
    }
}

impl crate::symmetric::memory::RetainedStorage for Parameters {
    fn retain_credits(&self, retained: &mut crate::symmetric::memory::RetainedBytes) -> Result<()> {
        self.graph.retain_credits(retained)?;
        Ok(())
    }
}
