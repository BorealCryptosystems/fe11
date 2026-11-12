// SPDX-License-Identifier: Apache-2.0
//! Native observation values and precise reasons an attribute was unavailable.
//! These types do not compare expectations or attest a security profile.

/// Why an attribute value could not be observed. Unknown causes stay unknown.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum AttributeUnavailableCause {
    /// An individual read returned CKR_ATTRIBUTE_SENSITIVE.
    Sensitive,
    /// An individual read returned CKR_ATTRIBUTE_TYPE_INVALID.
    Unsupported,
    /// The native response did not identify the cause for this attribute.
    Unspecified,
}

/// A requested observation cannot be interpreted or lacks a required operand.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ObservationIssue {
    /// A selected destination template field has no supplied operand; no query was sent.
    DestinationOperandAbsent(crate::IdentityAttribute),
    /// Requested content interpretation could not be established.
    ContentInterpretation(crate::ContentIssue),
    /// Not exactly one native CK_TRUE or CK_FALSE byte.
    BooleanEncoding,
    /// Not exactly the native CK_ULONG width.
    IntegerEncoding,
    /// Not a whole array of native CK_MECHANISM_TYPE values.
    MechanismListEncoding,
}

/// An observation is independent of any expected value or control selection.
/// Native failure metadata contains no attribute contents. A native operation
/// error is preserved independently of the requested observation.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Observation<T> {
    /// The observation was not requested or is absent from this snapshot.
    NotRequested,
    /// The actual observed value, without substitution from an expectation.
    Observed(T),
    /// No usable value was returned; the known cause is retained.
    Unavailable(AttributeUnavailableCause),
    /// Interpretation failed, or a required operand was absent before any query.
    Unusable(ObservationIssue),
    /// Exact native operation failure, without reinterpretation as a missing value.
    NativeError {
        /// The function actually called.
        function: &'static str,
        /// Exact native return code.
        code: u64,
        /// Whether the operation may already have had an effect.
        may_have_effect: bool,
    },
}

impl<T> Observation<T> {
    pub(crate) fn interpret<U>(self, convert: impl FnOnce(T) -> Observation<U>) -> Observation<U> {
        match self {
            Self::NotRequested => Observation::NotRequested,
            Self::Observed(value) => convert(value),
            Self::Unavailable(cause) => Observation::Unavailable(cause),
            Self::Unusable(issue) => Observation::Unusable(issue),
            Self::NativeError {
                function,
                code,
                may_have_effect,
            } => Observation::NativeError {
                function,
                code,
                may_have_effect,
            },
        }
    }
}
