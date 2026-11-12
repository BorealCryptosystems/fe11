// SPDX-License-Identifier: Apache-2.0
//! Generic message signatures sharing the typed native mechanism encoders.
use crate::mechanism_extension::message::{self, *};
use crate::mechanism_extension::parameter_keys::ParameterKeys;
use crate::{
    ContextAuthentication, ExtensionRequest, InputLimits, NativeCmsParameters, NativeKipParameters,
    NativeMacParameters, NativeObjectRef, NativeSignatureParameters, Result, Session,
};

/// Initialization parameters for message signatures. Selection never claims
/// CKF_MESSAGE_SIGN/VERIFY support; the module's native refusal is preserved.
pub enum NativeMessageParameters<'a> {
    /// Classical, stateful and PQC signatures, with the exact caller parameters.
    Signature(NativeSignatureParameters<'a>),
    /// Standard MAC parameters, including general/truncated variants.
    Mac(NativeMacParameters<'a>),
    /// CMS composition; nested managed keys remain retained through Final.
    Cms(NativeCmsParameters<'a>),
    /// CT-KIP MAC composition with its exact nested mechanism.
    Kip(NativeKipParameters<'a>),
    /// Explicit initialization ABI for other mechanisms. Each per-message ABI
    /// is asserted separately in NativeMessagePart/NativeMessageRoute.
    Extension(ExtensionRequest<'a>),
}
impl Session {
    /// Execute one complete message process, including its Final. This method
    /// preserves single/Begin-Next selection and individual parameter graphs.
    /// It never probes output sizes, replays an operation, prehashes input, or
    /// translates a verification refusal into success. All buffers remain owned
    /// on uncertain native completion; no result escapes before parent closure.
    /// If a refusal leaves native work retained, `take_native_message_ticket`
    /// transfers its continuation once. A capacity refusal performs no automatic
    /// retry or Final: supply capacity explicitly, poll, then finish the parent,
    /// or choose explicit cancellation/closure.
    pub fn execute_native_message(
        &self,
        key: &NativeObjectRef,
        parameters: NativeMessageParameters<'_>,
        route: NativeMessageRoute<'_>,
        action: NativeMessageAction<'_>,
        limits: InputLimits,
        authentication: Option<ContextAuthentication>,
    ) -> Result<NativeMessageResult> {
        let mut diagnostics = crate::advanced::NativeMessageInvocation::default();
        let function = message::operation_kind(
            matches!(&action, NativeMessageAction::Sign { .. }),
            matches!(&route, NativeMessageRoute::Multipart { .. }),
        );
        with_parameters(self, parameters, function, |request, sources| {
            message::execute(
                self,
                request,
                key,
                route,
                action,
                limits,
                authentication,
                sources,
                &mut diagnostics,
            )
        })
    }
}
impl crate::AdvancedSession {
    /// Synchronous message process using the same owner as Session.
    pub fn execute_native_message(
        &self,
        key: &NativeObjectRef,
        parameters: NativeMessageParameters<'_>,
        route: NativeMessageRoute<'_>,
        action: NativeMessageAction<'_>,
        limits: InputLimits,
        authentication: Option<ContextAuthentication>,
    ) -> Result<NativeMessageResult> {
        self.session
            .execute_native_message(key, parameters, route, action, limits, authentication)
    }
}

/// Encode initialization once for both the whole-process facade and caller-fed
/// owners. Auxiliary references accompany their exact declared ABI locations.
pub(crate) fn with_parameters<'a, T>(
    session: &Session,
    parameters: NativeMessageParameters<'a>,
    operation: crate::ExtensionOperation,
    consume: impl FnOnce(
        crate::mechanism_extension::graph::recipe::Request<'_>,
        ParameterKeys<'a>,
    ) -> Result<T>,
) -> Result<T> {
    match parameters {
        NativeMessageParameters::Signature(parameters) => {
            crate::native_signature::with_parameters(session, parameters, operation, |request| {
                consume(request.into(), ParameterKeys::default())
            })
        }
        NativeMessageParameters::Mac(parameters) => {
            crate::native_mac::with_parameters(session, parameters, operation, |request| {
                consume(request.into(), ParameterKeys::default())
            })
        }
        NativeMessageParameters::Cms(parameters) => {
            crate::native_protocol::cms_with_bindings(session, parameters, operation, consume)
        }
        NativeMessageParameters::Kip(parameters) => crate::native_protocol::kip_with_bindings(
            session,
            parameters,
            fe11_sys::CKM_KIP_MAC,
            operation,
            consume,
        ),
        NativeMessageParameters::Extension(request) => {
            consume(request.into(), ParameterKeys::default())
        }
    }
}
