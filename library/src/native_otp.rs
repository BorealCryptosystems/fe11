// SPDX-License-Identifier: Apache-2.0
//! Owned OTP parameter arrays and bounded decoding of contiguous native results.
use crate::{
    bounds,
    mechanism_extension::{operation, MechanismExtension},
    Error, ExtensionInput, ExtensionOperation, ExtensionResult, InputLimits, MessageRoute,
    NativeObjectRef, Result, Session,
};
use fe11_sys::*;
use std::mem::{align_of, offset_of, size_of};
mod recipe;

/// Standard OTP mechanism, without local OTP computation or counter management.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum NativeOtpAlgorithm {
    /// CKM_SECURID.
    SecurId,
    /// CKM_HOTP.
    Hotp,
    /// CKM_ACTI.
    Acti,
}
impl NativeOtpAlgorithm {
    /// Exact native mechanism identifier.
    pub fn mechanism_number(self) -> u64 {
        (match self {
            Self::SecurId => CKM_SECURID,
            Self::Hotp => CKM_HOTP,
            Self::Acti => CKM_ACTI,
        }) as u64
    }
}
/// Native parameter type determines its byte or CK_ULONG representation.
/// Values and order are passed verbatim; the module enforces OTP policy.
pub enum NativeOtpParameter<'a> {
    /// CK_OTP_VALUE.
    Value(&'a [u8]),
    /// CK_OTP_PIN; copied into erased storage before dispatch.
    Pin(&'a [u8]),
    /// CK_OTP_CHALLENGE.
    Challenge(&'a [u8]),
    /// CK_OTP_TIME, exact UTC text bytes in YYYYMMDDhhmmss form.
    /// Calendar validity is checked by the module.
    Time(&'a [u8]),
    /// CK_OTP_COUNTER; not incremented by Fe11.
    Counter(&'a [u8]),
    /// CK_OTP_FLAGS, including explicit caller choices for next OTP/exclusions.
    Flags(u64),
    /// CK_OTP_OUTPUT_LENGTH, in the mechanism's output-format units.
    OutputLength(u64),
    /// CK_OTP_OUTPUT_FORMAT identifier.
    OutputFormat(u64),
}
impl NativeOtpParameter<'_> {
    fn parts(&self) -> (CK_OTP_PARAM_TYPE, Option<&[u8]>, Option<u64>) {
        match self {
            Self::Value(v) => (CK_OTP_VALUE, Some(v), None),
            Self::Pin(v) => (CK_OTP_PIN, Some(v), None),
            Self::Challenge(v) => (CK_OTP_CHALLENGE, Some(v), None),
            Self::Time(v) => (CK_OTP_TIME, Some(v), None),
            Self::Counter(v) => (CK_OTP_COUNTER, Some(v), None),
            Self::Flags(v) => (CK_OTP_FLAGS, None, Some(*v)),
            Self::OutputLength(v) => (CK_OTP_OUTPUT_LENGTH, None, Some(*v)),
            Self::OutputFormat(v) => (CK_OTP_OUTPUT_FORMAT, None, Some(*v)),
        }
    }
}
/// Explicit bounds for the complete OTP input array. Output is separately bounded
/// by the caller's signature capacity; no hidden parameter-count limit is added.
#[derive(Clone, Copy, Debug)]
pub struct NativeOtpLimits {
    /// Maximum number of input descriptors, including duplicates.
    pub maximum_parameters: usize,
    /// Sum of all input value bytes, counting scalars at native CK_ULONG width.
    pub maximum_value_bytes: usize,
}

/// A parameter borrowed from a fully validated contiguous result. Addresses are
/// converted to offsets; no native pointer is dereferenced or exposed here.
pub struct NativeOtpValue<'a> {
    /// Exact native parameter tag; unknown future tags are preserved.
    pub kind: u64,
    /// Exact value bytes, bounded by the successful returned block length.
    pub bytes: &'a [u8],
}
impl NativeOtpValue<'_> {
    /// Decode a native CK_ULONG-sized value without assuming its semantic type.
    pub fn native_unsigned(&self) -> Option<u64> {
        Some(CK_ULONG::from_ne_bytes(self.bytes.try_into().ok()?) as u64)
    }
}
/// Owned OTP result, including informational parameters returned by the module.
/// It is deliberately neither Debug nor Clone. All native bytes are erased when
/// the last owner is dropped; caller copies remain outside this guarantee.
pub struct NativeOtpResult {
    output: ExtensionResult,
    descriptors: usize,
    count: usize,
}
impl NativeOtpResult {
    /// Number of validated native parameters, preserving their native order.
    pub fn parameter_count(&self) -> usize {
        self.count
    }
    /// Inspect an exact parameter by index, without following a native pointer.
    pub fn parameter(&self, index: usize) -> Option<NativeOtpValue<'_>> {
        if index >= self.count {
            return None;
        }
        // The result owns immutable bytes and was fully validated before creation.
        parameter(
            self.output.as_bytes(),
            self.output.native_output_origin,
            self.descriptors + index * size_of::<CK_OTP_PARAM>(),
        )
        .ok()
    }
    /// First CK_OTP_VALUE component. Additional informational tags remain accessible.
    pub fn value(&self) -> &[u8] {
        (0..self.count)
            .filter_map(|i| self.parameter(i))
            .find(|p| p.kind == CK_OTP_VALUE as u64)
            .expect("validated OTP value component")
            .bytes
    }
    fn new(output: ExtensionResult) -> Result<Self> {
        let (descriptors, count) = validate(output.as_bytes(), output.native_output_origin)?;
        Ok(Self {
            output,
            descriptors,
            count,
        })
    }
}
fn invalid() -> Error {
    Error::Rejected(crate::RejectionReason::NativeOtp(
        crate::NativeOtpRejection::OtpOutputIsNotABoundedContiguousNativeGraph,
    ))
}
fn unsigned(bytes: &[u8], offset: usize) -> Result<CK_ULONG> {
    let end = offset
        .checked_add(size_of::<CK_ULONG>())
        .ok_or_else(invalid)?;
    Ok(CK_ULONG::from_ne_bytes(
        bytes
            .get(offset..end)
            .ok_or_else(invalid)?
            .try_into()
            .map_err(|_| invalid())?,
    ))
}
fn address(bytes: &[u8], offset: usize) -> Result<usize> {
    let end = offset.checked_add(size_of::<usize>()).ok_or_else(invalid)?;
    Ok(usize::from_ne_bytes(
        bytes
            .get(offset..end)
            .ok_or_else(invalid)?
            .try_into()
            .map_err(|_| invalid())?,
    ))
}
fn region(bytes: &[u8], origin: usize, pointer: usize, length: usize) -> Result<usize> {
    if length == 0 {
        return Ok(0);
    }
    let offset = pointer.checked_sub(origin).ok_or_else(invalid)?;
    let end = offset.checked_add(length).ok_or_else(invalid)?;
    if end > bytes.len() {
        return Err(invalid());
    }
    Ok(offset)
}
fn parameter(bytes: &[u8], origin: usize, offset: usize) -> Result<NativeOtpValue<'_>> {
    let end = offset
        .checked_add(size_of::<CK_OTP_PARAM>())
        .ok_or_else(invalid)?;
    let descriptor = bytes.get(offset..end).ok_or_else(invalid)?;
    let kind = unsigned(descriptor, offset_of!(CK_OTP_PARAM, r#type))?;
    let pointer = address(descriptor, offset_of!(CK_OTP_PARAM, pValue))?;
    let length = usize::try_from(unsigned(descriptor, offset_of!(CK_OTP_PARAM, ulValueLen))?)
        .map_err(|_| invalid())?;
    let start = region(bytes, origin, pointer, length)?;
    Ok(NativeOtpValue {
        kind: kind as u64,
        bytes: &bytes[start..start + length],
    })
}
fn validate(bytes: &[u8], origin: usize) -> Result<(usize, usize)> {
    if bytes.len() < size_of::<CK_OTP_SIGNATURE_INFO>() {
        return Err(invalid());
    }
    let pointer = address(bytes, offset_of!(CK_OTP_SIGNATURE_INFO, pParams))?;
    let count = usize::try_from(unsigned(bytes, offset_of!(CK_OTP_SIGNATURE_INFO, ulCount))?)
        .map_err(|_| invalid())?;
    let length = count
        .checked_mul(size_of::<CK_OTP_PARAM>())
        .ok_or_else(invalid)?;
    let descriptors = region(bytes, origin, pointer, length)?;
    let mut has_value = false;
    for index in 0..count {
        let p = parameter(
            bytes,
            origin,
            descriptors + index * size_of::<CK_OTP_PARAM>(),
        )?;
        has_value |= p.kind == CK_OTP_VALUE as u64;
    }
    if !has_value {
        return Err(invalid());
    }
    Ok((descriptors, count))
}
fn write(raw: &mut [u8], offset: usize, value: u64) -> Result<()> {
    let value = CK_ULONG::try_from(value).map_err(|_| {
        Error::Rejected(crate::RejectionReason::NativeOtp(
            crate::NativeOtpRejection::OtpScalarAbiWidth,
        ))
    })?;
    raw[offset..offset + size_of::<CK_ULONG>()].copy_from_slice(&value.to_ne_bytes());
    Ok(())
}
pub(crate) fn perform(
    session: &Session,
    algorithm: NativeOtpAlgorithm,
    parameters: &[NativeOtpParameter<'_>],
    parameter_limits: NativeOtpLimits,
    input: ExtensionInput<'_>,
    operation_kind: ExtensionOperation,
    limits: InputLimits,
    authentication: Option<crate::ContextAuthentication>,
    extension_diagnostics: &mut crate::mechanism_extension::operation::Invocation,
) -> Result<ExtensionResult> {
    with_parameters(
        session,
        algorithm,
        parameters,
        parameter_limits,
        operation_kind,
        |request| {
            operation::execute_with_sources(
                session,
                request,
                input,
                limits,
                authentication,
                align_of::<CK_OTP_SIGNATURE_INFO>(),
                [None; 4],
                extension_diagnostics,
            )
        },
    )
}

fn with_parameters<T>(
    session: &Session,
    algorithm: NativeOtpAlgorithm,
    parameters: &[NativeOtpParameter<'_>],
    parameter_limits: NativeOtpLimits,
    operation_kind: ExtensionOperation,
    consume: impl FnOnce(crate::mechanism_extension::graph::recipe::Request<'_>) -> Result<T>,
) -> Result<T> {
    if parameters.len() > parameter_limits.maximum_parameters {
        return Err(Error::Rejected(crate::RejectionReason::NativeOtp(
            crate::NativeOtpRejection::CallerOtpParameterCountBound,
        )));
    }
    let values = parameters.iter().try_fold(0usize, |sum, p| {
        let (_, bytes, value) = p.parts();
        if let Some(value) = value {
            CK_ULONG::try_from(value).map_err(|_| {
                Error::Rejected(crate::RejectionReason::NativeOtp(
                    crate::NativeOtpRejection::OtpScalarAbiWidth,
                ))
            })?;
        }
        let length = bytes.map_or(size_of::<CK_ULONG>(), |b| b.len());
        bounds::ck_length(length)?;
        sum.checked_add(length)
            .ok_or(Error::Rejected(crate::RejectionReason::NativeOtp(
                crate::NativeOtpRejection::OtpValueAccounting,
            )))
    })?;
    if values > parameter_limits.maximum_value_bytes {
        return Err(Error::Rejected(crate::RejectionReason::NativeOtp(
            crate::NativeOtpRejection::CallerOtpValueByteBound,
        )));
    }
    let graph = recipe::Parameters::new(parameters)?;
    let contract = MechanismExtension::standard(
        &session.inner,
        algorithm.mechanism_number() as CK_MECHANISM_TYPE,
        operation_kind,
    );
    consume(crate::mechanism_extension::graph::recipe::Request {
        contract: &contract,
        parameters: crate::mechanism_extension::graph::recipe::Input::Generated(&graph),
    })
}

impl Session {
    /// Produce an OTP through native Sign or SignFinal. The module owns all
    /// counter/time/PIN policy. No sizing probe or automatic replay is performed.
    /// Observations of stateful OTP keys are invalidated before initialization.
    pub fn sign_native_otp(
        &self,
        key: &NativeObjectRef,
        algorithm: NativeOtpAlgorithm,
        parameters: &[NativeOtpParameter<'_>],
        parameter_limits: NativeOtpLimits,
        route: MessageRoute,
        limits: InputLimits,
        output_capacity: usize,
        authentication: Option<crate::ContextAuthentication>,
    ) -> Result<NativeOtpResult> {
        let mut extension_diagnostics =
            crate::mechanism_extension::operation::Invocation::default();
        self.sign_native_otp_with_diagnostics(
            key,
            algorithm,
            parameters,
            parameter_limits,
            route,
            limits,
            output_capacity,
            authentication,
            &mut extension_diagnostics,
        )
    }

    // Internal callers supply their outer publication owner; no helper
    // return may release the credit of an error still being projected.
    pub(crate) fn sign_native_otp_with_diagnostics(
        &self,
        key: &NativeObjectRef,
        algorithm: NativeOtpAlgorithm,
        parameters: &[NativeOtpParameter<'_>],
        parameter_limits: NativeOtpLimits,
        route: MessageRoute,
        limits: InputLimits,
        output_capacity: usize,
        authentication: Option<crate::ContextAuthentication>,
        extension_diagnostics: &mut crate::mechanism_extension::operation::Invocation,
    ) -> Result<NativeOtpResult> {
        let (input, kind) = match route {
            MessageRoute::Single => (
                ExtensionInput::Sign {
                    key,
                    input: &[],
                    output_capacity,
                },
                ExtensionOperation::Sign,
            ),
            MessageRoute::Multipart => (
                ExtensionInput::SignMultipart {
                    key,
                    parts: &[],
                    output_capacity,
                },
                ExtensionOperation::SignMultipart,
            ),
        };
        // Validate the successful result inside the admitted publication owner.
        // A decoding error remains OperationCompleted and never repeats signing.
        with_parameters(
            self,
            algorithm,
            parameters,
            parameter_limits,
            kind,
            |request| {
                operation::execute_with_sources_and_publish(
                    self,
                    request,
                    input,
                    limits,
                    authentication,
                    align_of::<CK_OTP_SIGNATURE_INFO>(),
                    [None; 4],
                    NativeOtpResult::new,
                    extension_diagnostics,
                )
            },
        )
    }
    /// Verify the actual OTP value bytes, never a CK_OTP_SIGNATURE_INFO blob.
    /// Native verification refusals retain their exact codes. Unlike generation,
    /// success has no fallible result decoding: discarding the empty result cannot
    /// create a post-completion diagnostic or justify repeating verification.
    pub fn verify_native_otp(
        &self,
        key: &NativeObjectRef,
        algorithm: NativeOtpAlgorithm,
        parameters: &[NativeOtpParameter<'_>],
        parameter_limits: NativeOtpLimits,
        value: &[u8],
        route: MessageRoute,
        limits: InputLimits,
        authentication: Option<crate::ContextAuthentication>,
    ) -> Result<()> {
        let mut extension_diagnostics =
            crate::mechanism_extension::operation::Invocation::default();
        self.verify_native_otp_with_diagnostics(
            key,
            algorithm,
            parameters,
            parameter_limits,
            value,
            route,
            limits,
            authentication,
            &mut extension_diagnostics,
        )
    }

    // Internal callers supply their outer publication owner; no helper
    // return may release the credit of an error still being projected.
    pub(crate) fn verify_native_otp_with_diagnostics(
        &self,
        key: &NativeObjectRef,
        algorithm: NativeOtpAlgorithm,
        parameters: &[NativeOtpParameter<'_>],
        parameter_limits: NativeOtpLimits,
        value: &[u8],
        route: MessageRoute,
        limits: InputLimits,
        authentication: Option<crate::ContextAuthentication>,
        extension_diagnostics: &mut crate::mechanism_extension::operation::Invocation,
    ) -> Result<()> {
        let (input, kind) = match route {
            MessageRoute::Single => (
                ExtensionInput::Verify {
                    key,
                    input: &[],
                    signature: value,
                },
                ExtensionOperation::Verify,
            ),
            MessageRoute::Multipart => (
                ExtensionInput::VerifyMultipart {
                    key,
                    parts: &[],
                    signature: value,
                },
                ExtensionOperation::VerifyMultipart,
            ),
        };
        perform(
            self,
            algorithm,
            parameters,
            parameter_limits,
            input,
            kind,
            limits,
            authentication,
            extension_diagnostics,
        )
        .map(|_| ())
    }
}
impl crate::AdvancedSession {
    /// Synchronous OTP generation through the same owner and bounded decoder.
    pub fn sign_native_otp(
        &self,
        key: &NativeObjectRef,
        algorithm: NativeOtpAlgorithm,
        parameters: &[NativeOtpParameter<'_>],
        parameter_limits: NativeOtpLimits,
        route: MessageRoute,
        limits: InputLimits,
        output_capacity: usize,
        authentication: Option<crate::ContextAuthentication>,
    ) -> Result<NativeOtpResult> {
        let mut extension_diagnostics =
            crate::mechanism_extension::operation::Invocation::default();
        self.session.sign_native_otp_with_diagnostics(
            key,
            algorithm,
            parameters,
            parameter_limits,
            route,
            limits,
            output_capacity,
            authentication,
            &mut extension_diagnostics,
        )
    }
    /// Synchronous OTP verification preserving native refusal codes.
    pub fn verify_native_otp(
        &self,
        key: &NativeObjectRef,
        algorithm: NativeOtpAlgorithm,
        parameters: &[NativeOtpParameter<'_>],
        parameter_limits: NativeOtpLimits,
        value: &[u8],
        route: MessageRoute,
        limits: InputLimits,
        authentication: Option<crate::ContextAuthentication>,
    ) -> Result<()> {
        let mut extension_diagnostics =
            crate::mechanism_extension::operation::Invocation::default();
        self.session.verify_native_otp_with_diagnostics(
            key,
            algorithm,
            parameters,
            parameter_limits,
            value,
            route,
            limits,
            authentication,
            &mut extension_diagnostics,
        )
    }
}
