// SPDX-License-Identifier: Apache-2.0
//! Explicit Init followed by one monobloc Sign/Verify on the retained ticket.
//! No second Init, Update/Final substitution or implicit terminal call occurs.
use super::{
    api::{change, initial_limits, Change},
    preparation, Kind, SignatureOutputPlan,
};
use crate::advanced::{OperationPacing, OperationProgress, OperationTicket};
use crate::{
    AdvancedSession, Error, ExtensionOperation, ExtensionRequest, InputLimits, MessageRoute,
    NativeObjectRef, NativeSignatureParameters, Result, Session,
};

impl Session {
    /// Initialize signing only. Submit data later with finish_signature_single. The output plan and ceiling remain caller-selected.
    pub fn begin_native_sign_single(
        &self,
        key: &NativeObjectRef,
        parameters: NativeSignatureParameters<'_>,
        output: SignatureOutputPlan,
        maximum_output: usize,
    ) -> Result<OperationTicket> {
        let mut retirement = crate::advanced::PollDiagnostics::default();
        crate::native_signature::with_parameters(
            self,
            parameters,
            ExtensionOperation::Sign,
            |request| {
                preparation::start(
                    self,
                    key,
                    request.into(),
                    Kind::Sign,
                    MessageRoute::Single,
                    None,
                    None,
                    initial_limits(self),
                    output,
                    maximum_output,
                    false,
                    &mut 1,
                    &mut retirement,
                )
            },
        )
    }
    /// Initialize verification only. Submit data and the expected signature together with finish_signature_single.
    pub fn begin_native_verify_single(
        &self,
        key: &NativeObjectRef,
        parameters: NativeSignatureParameters<'_>,
    ) -> Result<OperationTicket> {
        let mut retirement = crate::advanced::PollDiagnostics::default();
        crate::native_signature::with_parameters(
            self,
            parameters,
            ExtensionOperation::Verify,
            |request| {
                preparation::start(
                    self,
                    key,
                    request.into(),
                    Kind::Verify,
                    MessageRoute::Single,
                    None,
                    None,
                    initial_limits(self),
                    SignatureOutputPlan::Buffer { capacity: 0 },
                    0,
                    false,
                    &mut 1,
                    &mut retirement,
                )
            },
        )
    }
    /// Initialize native MAC signing only, retaining its parameter layout and provenance.
    pub fn begin_native_mac_single(
        &self,
        key: &NativeObjectRef,
        parameters: crate::NativeMacParameters<'_>,
        output: SignatureOutputPlan,
        maximum_output: usize,
    ) -> Result<OperationTicket> {
        let mut retirement = crate::advanced::PollDiagnostics::default();
        crate::native_mac::with_parameters(self, parameters, ExtensionOperation::Sign, |request| {
            preparation::start(
                self,
                key,
                request.into(),
                Kind::Sign,
                MessageRoute::Single,
                None,
                None,
                initial_limits(self),
                output,
                maximum_output,
                false,
                &mut 1,
                &mut retirement,
            )
        })
    }
    /// Initialize native MAC verification only; supply the expected MAC with the data.
    pub fn begin_native_mac_verify_single(
        &self,
        key: &NativeObjectRef,
        parameters: crate::NativeMacParameters<'_>,
    ) -> Result<OperationTicket> {
        let mut retirement = crate::advanced::PollDiagnostics::default();
        crate::native_mac::with_parameters(
            self,
            parameters,
            ExtensionOperation::Verify,
            |request| {
                preparation::start(
                    self,
                    key,
                    request.into(),
                    Kind::Verify,
                    MessageRoute::Single,
                    None,
                    None,
                    initial_limits(self),
                    SignatureOutputPlan::Buffer { capacity: 0 },
                    0,
                    false,
                    &mut 1,
                    &mut retirement,
                )
            },
        )
    }
    /// Initialize an asserted single-part signature operation. VerifySignature requires its expected signature at Init; Verify takes it with the data.
    pub fn begin_extension_signature_single(
        &self,
        key: &NativeObjectRef,
        request: ExtensionRequest<'_>,
        signature: Option<&[u8]>,
        limits: InputLimits,
        output: SignatureOutputPlan,
        maximum_output: usize,
    ) -> Result<OperationTicket> {
        let mut retirement = crate::advanced::PollDiagnostics::default();
        let kind = match request.contract.operation() {
            ExtensionOperation::Sign => Kind::Sign,
            ExtensionOperation::Verify => Kind::Verify,
            ExtensionOperation::VerifySignature => Kind::VerifySignature,
            _ => {
                return Err(Error::Rejected(
                    crate::RejectionReason::SignatureContinuation(
                        crate::SignatureContinuationRejection::SingleSignatureExtensionRoute,
                    ),
                ))
            }
        };
        preparation::start(
            self,
            key,
            request.into(),
            kind,
            MessageRoute::Single,
            None,
            signature,
            limits,
            output,
            maximum_output,
            false,
            &mut 1,
            &mut retirement,
        )
    }
    /// Issue C_Sign, C_Verify or C_VerifySignature after its explicit Init.
    /// Ordinary Verify requires Some(signature); Sign and VerifySignature require
    /// None. Data and signature are owned before dispatch. A size query or short
    /// buffer retains the exact call: provide_signature_output_capacity and
    /// poll_signature resume it without another Init or input submission.
    /// Update and finish_signature_stream cannot consume this single-part ticket.
    pub fn finish_signature_single(
        &self,
        ticket: &mut OperationTicket,
        data: &[u8],
        signature: Option<&[u8]>,
        limits: InputLimits,
    ) -> Result<OperationProgress> {
        let mut diagnostics = None;
        let mut poll_diagnostics = crate::advanced::PollDiagnostics::default();
        change(
            self,
            ticket,
            Change::Single { data, signature },
            limits,
            OperationPacing::Eager,
            &mut diagnostics,
            &mut poll_diagnostics,
        )
    }
}

impl AdvancedSession {
    /// Initialize signing only. Submit data later with finish_signature_single. The output plan and ceiling remain caller-selected.
    pub fn begin_native_sign_single(
        &self,
        key: &NativeObjectRef,
        parameters: NativeSignatureParameters<'_>,
        output: SignatureOutputPlan,
        maximum_output: usize,
    ) -> Result<OperationTicket> {
        let mut retirement = crate::advanced::PollDiagnostics::default();
        crate::native_signature::with_parameters(
            &self.session,
            parameters,
            ExtensionOperation::Sign,
            |request| {
                preparation::start(
                    &self.session,
                    key,
                    request.into(),
                    Kind::Sign,
                    MessageRoute::Single,
                    None,
                    None,
                    initial_limits(&self.session),
                    output,
                    maximum_output,
                    self.validation_capture == crate::advanced::ValidationCaptureMode::Capture,
                    &mut 1,
                    &mut retirement,
                )
            },
        )
    }
    /// Initialize verification only. Submit data and the expected signature together with finish_signature_single.
    pub fn begin_native_verify_single(
        &self,
        key: &NativeObjectRef,
        parameters: NativeSignatureParameters<'_>,
    ) -> Result<OperationTicket> {
        let mut retirement = crate::advanced::PollDiagnostics::default();
        crate::native_signature::with_parameters(
            &self.session,
            parameters,
            ExtensionOperation::Verify,
            |request| {
                preparation::start(
                    &self.session,
                    key,
                    request.into(),
                    Kind::Verify,
                    MessageRoute::Single,
                    None,
                    None,
                    initial_limits(&self.session),
                    SignatureOutputPlan::Buffer { capacity: 0 },
                    0,
                    self.validation_capture == crate::advanced::ValidationCaptureMode::Capture,
                    &mut 1,
                    &mut retirement,
                )
            },
        )
    }
    /// Initialize native MAC signing only, retaining its parameter layout and provenance.
    pub fn begin_native_mac_single(
        &self,
        key: &NativeObjectRef,
        parameters: crate::NativeMacParameters<'_>,
        output: SignatureOutputPlan,
        maximum_output: usize,
    ) -> Result<OperationTicket> {
        let mut retirement = crate::advanced::PollDiagnostics::default();
        crate::native_mac::with_parameters(
            &self.session,
            parameters,
            ExtensionOperation::Sign,
            |request| {
                preparation::start(
                    &self.session,
                    key,
                    request.into(),
                    Kind::Sign,
                    MessageRoute::Single,
                    None,
                    None,
                    initial_limits(&self.session),
                    output,
                    maximum_output,
                    self.validation_capture == crate::advanced::ValidationCaptureMode::Capture,
                    &mut 1,
                    &mut retirement,
                )
            },
        )
    }
    /// Initialize native MAC verification only; supply the expected MAC with the data.
    pub fn begin_native_mac_verify_single(
        &self,
        key: &NativeObjectRef,
        parameters: crate::NativeMacParameters<'_>,
    ) -> Result<OperationTicket> {
        let mut retirement = crate::advanced::PollDiagnostics::default();
        crate::native_mac::with_parameters(
            &self.session,
            parameters,
            ExtensionOperation::Verify,
            |request| {
                preparation::start(
                    &self.session,
                    key,
                    request.into(),
                    Kind::Verify,
                    MessageRoute::Single,
                    None,
                    None,
                    initial_limits(&self.session),
                    SignatureOutputPlan::Buffer { capacity: 0 },
                    0,
                    self.validation_capture == crate::advanced::ValidationCaptureMode::Capture,
                    &mut 1,
                    &mut retirement,
                )
            },
        )
    }
    /// Initialize an asserted single-part signature operation. VerifySignature requires its expected signature at Init; Verify takes it with the data.
    pub fn begin_extension_signature_single(
        &self,
        key: &NativeObjectRef,
        request: ExtensionRequest<'_>,
        signature: Option<&[u8]>,
        limits: InputLimits,
        output: SignatureOutputPlan,
        maximum_output: usize,
    ) -> Result<OperationTicket> {
        let mut retirement = crate::advanced::PollDiagnostics::default();
        let kind = match request.contract.operation() {
            ExtensionOperation::Sign => Kind::Sign,
            ExtensionOperation::Verify => Kind::Verify,
            ExtensionOperation::VerifySignature => Kind::VerifySignature,
            _ => {
                return Err(Error::Rejected(
                    crate::RejectionReason::SignatureContinuation(
                        crate::SignatureContinuationRejection::SingleSignatureExtensionRoute,
                    ),
                ))
            }
        };
        preparation::start(
            &self.session,
            key,
            request.into(),
            kind,
            MessageRoute::Single,
            None,
            signature,
            limits,
            output,
            maximum_output,
            self.validation_capture == crate::advanced::ValidationCaptureMode::Capture,
            &mut 1,
            &mut retirement,
        )
    }
    /// Issue C_Sign, C_Verify or C_VerifySignature after its explicit Init.
    /// Ordinary Verify requires Some(signature); Sign and VerifySignature require
    /// None. Data and signature are owned before dispatch. A size query or short
    /// buffer retains the exact call: provide_signature_output_capacity and
    /// poll_signature resume it without another Init or input submission.
    /// Update and finish_signature_stream cannot consume this single-part ticket.
    pub fn finish_signature_single(
        &self,
        ticket: &mut OperationTicket,
        data: &[u8],
        signature: Option<&[u8]>,
        limits: InputLimits,
    ) -> Result<OperationProgress> {
        let mut diagnostics = None;
        let mut poll_diagnostics = crate::advanced::PollDiagnostics::default();
        change(
            &self.session,
            ticket,
            Change::Single { data, signature },
            limits,
            self.pacing,
            &mut diagnostics,
            &mut poll_diagnostics,
        )
    }
}
