// SPDX-License-Identifier: Apache-2.0
//! Closed JSON Lines vocabulary: public identities, assertion facts and status codes.
//!
//! No method accepts a PIN, key, input buffer or arbitrary diagnostic text. Errors
//! are represented by fixed categories and native codes; assertions match typed
//! errors in the operation family before reporting their public boolean outcome.
use std::io::{self, Write};

#[derive(Clone, Copy)]
pub enum Phase {
    Setup,
    Body,
    Cleanup,
}

impl Phase {
    fn name(self) -> &'static str {
        match self {
            Self::Setup => "setup",
            Self::Body => "body",
            Self::Cleanup => "cleanup",
        }
    }
}

#[derive(Clone, Copy)]
pub enum Producer {
    Fe11Local,
    Native,
    PublishedVector,
    TestOracle,
    IndependentReference,
    Supervisor,
}

impl Producer {
    fn name(self) -> &'static str {
        match self {
            Self::Fe11Local => "fe11_local",
            Self::Native => "native",
            Self::PublishedVector => "published_vector",
            Self::TestOracle => "test_oracle",
            Self::IndependentReference => "independent_reference",
            Self::Supervisor => "supervisor",
        }
    }
}

pub enum Observation {
    Boolean(bool),
    Number(u64),
    Busy(fe11::BusyReason),
    Rejected(fe11::RejectionReason),
    Native {
        function: &'static str,
        code: u64,
        may_have_effect: bool,
    },
}

// Only public typed diagnostic causes enter this path, never Error's arbitrary
// text, a PIN, native payload or panic value. The current cause enums carry only
// variant names; reject any future formatting outside this bounded vocabulary.
fn typed_cause(category: &str, cause: String) -> io::Result<String> {
    if cause.is_empty()
        || cause.len() > 256
        || !cause
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b"_(): ".contains(&b))
    {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "invalid typed diagnostic name",
        ));
    }
    Ok(format!(
        "{{\"category\":\"{category}\",\"cause\":\"{cause}\"}}"
    ))
}

fn rejection_name(reason: fe11::RejectionReason) -> String {
    // These three variants also carry values. Report only their typed name,
    // preserving the closed diagnostic vocabulary without accepting caller text.
    match reason {
        fe11::RejectionReason::NativeInterfaces(
            fe11::NativeInterfacesRejection::InterfaceNameLimit { .. },
        ) => "NativeInterfaces(InterfaceNameLimit)".into(),
        fe11::RejectionReason::NativeInterfaces(
            fe11::NativeInterfacesRejection::InterfaceNamesTotalLimit { .. },
        ) => "NativeInterfaces(InterfaceNamesTotalLimit)".into(),
        fe11::RejectionReason::NativeLoading(
            fe11::NativeLoadingRejection::RequiredFunctionMissing { .. },
        ) => "NativeLoading(RequiredFunctionMissing)".into(),
        _ => format!("{reason:?}"),
    }
}

#[derive(Clone, Copy, Eq, PartialEq)]
pub enum PhaseResult {
    Passed,
    Failed,
    NotExecuted,
}

impl PhaseResult {
    fn name(self) -> &'static str {
        match self {
            Self::Passed => "PASS",
            Self::Failed => "FAIL",
            Self::NotExecuted => "NOT_EXECUTED",
        }
    }
}

pub struct Report<W: Write> {
    output: W,
    identity: String,
    sequence: u64,
    finished: bool,
}

fn identifier(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 512
        && value
            .bytes()
            .all(|c| c.is_ascii_alphanumeric() || b"._-:@/".contains(&c))
}

fn digest(value: &str) -> bool {
    value.len() == 64 && value.bytes().all(|c| c.is_ascii_hexdigit())
}

impl<W: Write> Report<W> {
    /// All three digests are frozen public provenance, not secret key hashes.
    pub fn new(
        output: W,
        case: &str,
        source: &str,
        recipe: &str,
        module: &str,
    ) -> io::Result<Self> {
        if !identifier(case) || !digest(source) || !digest(recipe) || !digest(module) {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "invalid report identity",
            ));
        }
        // Each interpolated value was validated against an alphabet requiring no
        // JSON escaping. No arbitrary text can reach this string construction.
        let identity = format!(
            "\"schema\":1,\"case\":\"{case}\",\"source_sha256\":\"{source}\",\"recipe_sha256\":\"{recipe}\",\"module_sha256\":\"{module}\""
        );
        Ok(Self {
            output,
            identity,
            sequence: 0,
            finished: false,
        })
    }

    pub fn observation(
        &mut self,
        phase: Phase,
        assertion: &'static str,
        producer: Producer,
        value: Observation,
    ) -> io::Result<()> {
        if !identifier(assertion) || self.finished {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "invalid assertion state",
            ));
        }
        let value = match value {
            Observation::Boolean(value) => value.to_string(),
            Observation::Number(value) => value.to_string(),
            Observation::Busy(reason) => typed_cause("busy", format!("{reason:?}"))?,
            Observation::Rejected(reason) => typed_cause("rejected", rejection_name(reason))?,
            Observation::Native {
                function,
                code,
                may_have_effect,
            } => {
                if !identifier(function) {
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidInput,
                        "invalid function identity",
                    ));
                }
                format!("{{\"function\":\"{function}\",\"code\":{code},\"may_have_effect\":{may_have_effect}}}")
            }
        };
        self.sequence = self
            .sequence
            .checked_add(1)
            .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "event count overflow"))?;
        writeln!(self.output,
            "{{{},\"kind\":\"assertion\",\"sequence\":{},\"phase\":\"{}\",\"assertion\":\"{}\",\"producer\":\"{}\",\"value\":{}}}",
            self.identity, self.sequence, phase.name(), assertion, producer.name(), value)?;
        self.output.flush()
    }

    /// Consuming the writer prevents a second terminal record from this owner.
    /// PASS/FAIL is the raw worker outcome, not a product/module attribution.
    /// A failure remains UNKNOWN until its classified verdict is reviewed.
    pub fn finish(
        mut self,
        setup: PhaseResult,
        body: PhaseResult,
        cleanup: PhaseResult,
    ) -> io::Result<bool> {
        self.finished = true;
        let success = setup == PhaseResult::Passed
            && body == PhaseResult::Passed
            && cleanup == PhaseResult::Passed;
        writeln!(self.output,
            "{{{},\"kind\":\"terminal\",\"assertions\":{},\"setup\":\"{}\",\"body\":\"{}\",\"cleanup\":\"{}\",\"status\":\"{}\",\"attribution\":\"{}\"}}",
            self.identity, self.sequence, setup.name(), body.name(), cleanup.name(),
            if success { "PASS" } else { "FAIL" }, if success { "NONE" } else { "UNKNOWN" })?;
        self.output.flush()?;
        Ok(success)
    }

    /// A prerequisite has its own terminal kind and cannot be counted as a case.
    pub fn finish_preparation(
        mut self,
        setup: PhaseResult,
        cleanup: PhaseResult,
    ) -> io::Result<bool> {
        self.finished = true;
        let success = setup == PhaseResult::Passed && cleanup == PhaseResult::Passed;
        writeln!(self.output,
            "{{{},\"kind\":\"preparation_terminal\",\"assertions\":{},\"setup\":\"{}\",\"body\":\"NOT_EXECUTED\",\"cleanup\":\"{}\",\"status\":\"{}\"}}",
            self.identity, self.sequence, setup.name(), cleanup.name(),
            if success { "PASS" } else { "PREREQUISITE_MISSING" })?;
        self.output.flush()?;
        Ok(success)
    }
}
