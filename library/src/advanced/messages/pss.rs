// SPDX-License-Identifier: Apache-2.0
//! Exact message PSS parameters, independent of mutable native storage.
use super::{record, Family};
use crate::advanced::record::profile;
use crate::{Error, Result};
use fe11_sys::CK_RSA_PKCS_PSS_PARAMS;

pub(super) struct PssFrame {
    pub(super) selection: crate::RsaPssParameters,
    native: Box<CK_RSA_PKCS_PSS_PARAMS>,
}
impl PssFrame {
    pub(super) fn new(native: CK_RSA_PKCS_PSS_PARAMS) -> Result<Self> {
        Ok(Self {
            selection: crate::RsaPssParameters::from_native(&native)?,
            native: Box::new(native),
        })
    }
    pub(super) fn unchanged(&self) -> Result<bool> {
        let expected = self.selection.checked()?;
        Ok(self.native.hashAlg == expected.hashAlg
            && self.native.mgf == expected.mgf
            && self.native.sLen == expected.sLen)
    }
    pub(super) fn checkpoint_profile(&self) -> u8 {
        if self.selection == super::pss_profile() {
            profile::RSA_PSS_SHA256
        } else {
            profile::RSA_PSS_SELECTED
        }
    }
}
// The allocation behind the native pointer stays stable when the owner moves.
// Mutating native fields never mutates the caller's immutable selection.
impl std::ops::Deref for PssFrame {
    type Target = CK_RSA_PKCS_PSS_PARAMS;
    fn deref(&self) -> &Self::Target {
        &self.native
    }
}
impl std::ops::DerefMut for PssFrame {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.native
    }
}

pub(in crate::advanced) fn record_parameters(
    descriptor: record::Descriptor,
    parameters: &record::Parameters<'_>,
) -> Result<crate::RsaPssParameters> {
    if !matches!(
        descriptor.profile,
        profile::RSA_PSS_SHA256 | profile::RSA_PSS_SELECTED
    ) {
        return Err(Error::Rejected(crate::RejectionReason::SignatureMessages(
            crate::SignatureMessagesRejection::RecordPssProfile,
        )));
    }
    let native = CK_RSA_PKCS_PSS_PARAMS {
        hashAlg: parameters
            .hash
            .ok_or(Error::Rejected(crate::RejectionReason::SignatureMessages(
                crate::SignatureMessagesRejection::RecordPssHashAbsent,
            )))?
            .try_into()
            .map_err(|_| {
                Error::Rejected(crate::RejectionReason::SignatureMessages(
                    crate::SignatureMessagesRejection::RecordPssHashWidth,
                ))
            })?,
        mgf: parameters
            .mgf
            .ok_or(Error::Rejected(crate::RejectionReason::SignatureMessages(
                crate::SignatureMessagesRejection::RecordPssMgfAbsent,
            )))?
            .try_into()
            .map_err(|_| {
                Error::Rejected(crate::RejectionReason::SignatureMessages(
                    crate::SignatureMessagesRejection::RecordPssMgfWidth,
                ))
            })?,
        sLen: parameters
            .salt
            .ok_or(Error::Rejected(crate::RejectionReason::SignatureMessages(
                crate::SignatureMessagesRejection::RecordPssSaltAbsent,
            )))?
            .try_into()
            .map_err(|_| {
                Error::Rejected(crate::RejectionReason::SignatureMessages(
                    crate::SignatureMessagesRejection::RecordPssSaltWidth,
                ))
            })?,
    };
    let selected = crate::RsaPssParameters::from_native(&native)?;
    if selected.mechanism(crate::HashExecution::Pkcs11Combined)? as u64 != descriptor.mechanism
        || descriptor.profile == profile::RSA_PSS_SHA256 && selected != super::pss_profile()
    {
        return Err(Error::Rejected(crate::RejectionReason::SignatureMessages(
            crate::SignatureMessagesRejection::RecordPssParameters,
        )));
    }
    Ok(selected)
}

pub(in crate::advanced) fn record_selection(
    descriptor: record::Descriptor,
    messages: &record::Messages<'_>,
) -> Result<Option<crate::RsaPssParameters>> {
    if !matches!(
        descriptor.family,
        Family::MessageSign | Family::MessageVerify
    ) || !matches!(
        descriptor.profile,
        profile::RSA_PSS_SHA256 | profile::RSA_PSS_SELECTED
    ) {
        return Ok(None);
    }
    let mut selected = messages
        .stream()
        .map(|stream| record_parameters(descriptor, &stream.parameters))
        .transpose()?;
    for message in messages.iter() {
        let current = record_parameters(descriptor, &message?.params)?;
        if selected.is_some_and(|prior| prior != current) {
            return Err(Error::Rejected(crate::RejectionReason::SignatureMessages(
                crate::SignatureMessagesRejection::RecordMixedPssParameters,
            )));
        }
        selected = Some(current);
    }
    selected
        .map(Some)
        .ok_or(Error::Rejected(crate::RejectionReason::SignatureMessages(
            crate::SignatureMessagesRejection::RecordPssMessagesAbsent,
        )))
}
