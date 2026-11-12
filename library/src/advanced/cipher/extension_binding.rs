// SPDX-License-Identifier: Apache-2.0
//! A captured graph never grants permission to invoke an ABI in another module.
use super::{
    extension::{Metadata, Source},
    CipherFrame, CipherOperation,
};
use crate::advanced::record;
use crate::{Error, MechanismExtension, Result, Session};

fn check(session: &Session, contract: &MechanismExtension, expected: Metadata) -> Result<()> {
    contract.check(&session.inner, expected.operation)?;
    if contract.native_mechanism() != expected.mechanism
        || contract.constants_edition() != expected.edition
        || contract.mutates_key() != expected.mutates_key
    {
        return Err(Error::Rejected(crate::RejectionReason::CipherContinuation(
            crate::CipherContinuationRejection::CipherDestinationDeclarationMismatch,
        )));
    }
    Ok(())
}
pub(in crate::advanced) fn captured_contract(
    session: &Session,
    source: &CipherOperation,
    supplied: Option<&MechanismExtension>,
) -> Result<Option<MechanismExtension>> {
    let CipherFrame::Extension(frame) = &source.frame.parameters else {
        return if supplied.is_none() {
            Ok(None)
        } else {
            Err(Error::Rejected(crate::RejectionReason::CipherContinuation(
                crate::CipherContinuationRejection::DeclarationWithoutCipherExtension,
            )))
        };
    };
    let original = frame.contract()?;
    let metadata = frame.source()?.metadata();
    check(session, original, metadata)?;
    if let Some(supplied) = supplied {
        check(session, supplied, metadata)?;
    }
    Ok(Some(original.clone()))
}
pub(in crate::advanced) fn import_contract(
    session: &Session,
    descriptor: record::Descriptor,
    messages: &record::Messages<'_>,
    supplied: Option<&MechanismExtension>,
) -> Result<Option<MechanismExtension>> {
    let message = messages.iter().next().transpose()?;
    let Some((message, extension)) = message.and_then(|message| {
        message
            .params
            .cipher_extension
            .map(|extension| (message, extension))
    }) else {
        return if supplied.is_none() {
            Ok(None)
        } else {
            Err(Error::Rejected(crate::RejectionReason::CipherContinuation(
                crate::CipherContinuationRejection::DeclarationWithoutCipherExtension,
            )))
        };
    };
    let metadata = Source::from_record(descriptor, extension)?
        .record_route(message.route)?
        .metadata();
    let contract = if extension.caller_asserted {
        supplied
            .ok_or(Error::Rejected(crate::RejectionReason::CipherContinuation(
                crate::CipherContinuationRejection::CipherImportRequiresADestinationAbiDeclaration,
            )))?
            .clone()
    } else {
        // C_SetOperationState restores opaque module bytes. This declaration
        // binds metadata only; no Init is reconstructed from the parameter graph.
        MechanismExtension::standard(&session.inner, metadata.mechanism, metadata.operation)
    };
    check(session, &contract, metadata)?;
    if let Some(supplied) = supplied {
        check(session, supplied, metadata)?;
    }
    Ok(Some(contract))
}

impl CipherOperation {
    pub(in crate::advanced) fn requires_writer_destination(&self) -> bool {
        self.extension_mutates_key() && self.key.lease().is_some()
    }
    pub(in crate::advanced) fn writer_binding_source(
        &self,
    ) -> Result<&crate::advanced::keys::KeyLease> {
        let key =
            self.key
                .lease()
                .ok_or(Error::Rejected(crate::RejectionReason::CipherContinuation(
                    crate::CipherContinuationRejection::CipherWriterKeyAbsent,
                )))?;
        if !self.extension_mutates_key() || key.writer_roles().is_none() {
            return Err(Error::Rejected(crate::RejectionReason::CipherContinuation(
                crate::CipherContinuationRejection::CipherWriterPermissionAbsent,
            )));
        }
        Ok(key)
    }
    pub(in crate::advanced) fn extension_mutates_key(&self) -> bool {
        matches!(&self.frame.parameters, CipherFrame::Extension(frame)
            if frame.source().is_ok_and(|source| source.metadata().mutates_key))
    }
}
