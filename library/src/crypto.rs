// SPDX-License-Identifier: Apache-2.0
//! Caller-bounded input contracts and native digest sequences.
use crate::{bounds, session::Sequence, Error, Result, SecretBytes, Session};
use fe11_sys::*;

/// Borrowed description used to size the initial key-admission graph.
/// Implementations expose the caller's choices and structural field lists only;
/// they must not allocate, reserve resources, read native state or grant access.
/// Both an unbound family plan and its installed owner can supply this view.
pub(crate) trait KeyAdmissionDescription {
    fn is_pair(&self) -> bool;
    fn admission_id(&self) -> &[u8];
    fn admission_class(&self) -> crate::ManagedClass;
    fn object_observation(&self, private: bool) -> &crate::ObjectAdmission;
    fn history_observation(&self, private: bool) -> Option<crate::HistoryObservationPlan>;
    fn mechanism_observation(&self, private: bool) -> &crate::MechanismObservationPlan;
    fn visit_required(&self, private: bool, field: &mut dyn FnMut(CK_ATTRIBUTE_TYPE));
    fn visit_material(&self, private: bool, field: &mut dyn FnMut(CK_ATTRIBUTE_TYPE));

    /// A pair keeps both destination requests, regardless of the observation
    /// phase currently active in its installed owner.
    fn generation_search_required(&self) -> Result<bool> {
        if self.is_pair() {
            Ok(self
                .object_observation(false)
                .destination
                .key_search_required(crate::ManagedClass::PublicKey)?
                | self
                    .object_observation(true)
                    .destination
                    .key_search_required(crate::ManagedClass::PrivateKey)?)
        } else {
            self.object_observation(false)
                .destination
                .key_search_required(self.admission_class())
        }
    }

    /// Account for the input policy and the two published evidence owners.
    /// These are retained caller-selected predicates, not admission decisions.
    fn retained_object_observation_bytes(&self) -> Result<usize> {
        let bytes = |admission: &crate::ObjectAdmission| {
            let controls = admission
                .public_attribute_retained_bytes()?
                .checked_add(
                    admission
                        .destination
                        .retained_bytes()?
                        .checked_mul(2)
                        .ok_or(Error::Rejected(
                            crate::RejectionReason::ClassicalSignatures(
                                crate::ClassicalSignaturesRejection::DestinationSelectionSize,
                            ),
                        ))?,
                )
                .ok_or(Error::Rejected(
                    crate::RejectionReason::ClassicalSignatures(
                        crate::ClassicalSignaturesRejection::DestinationSelectionSize,
                    ),
                ))?;
            admission
                .selection
                .retained_bytes()?
                .checked_mul(3)
                .and_then(|selection| controls.checked_add(selection))
                .ok_or(Error::Rejected(
                    crate::RejectionReason::ClassicalSignatures(
                        crate::ClassicalSignaturesRejection::ObjectControlByteCount,
                    ),
                ))
        };
        if self.is_pair() {
            bytes(self.object_observation(false))?
                .checked_add(bytes(self.object_observation(true))?)
                .ok_or(Error::Rejected(
                    crate::RejectionReason::ClassicalSignatures(
                        crate::ClassicalSignaturesRejection::PairObjectControlByteCount,
                    ),
                ))
        } else {
            bytes(self.object_observation(false))
        }
    }
}

/// Caller-selected generation identity, borrowed until final ownership transfer.
pub(crate) struct GenerationIdentity<'a> {
    pub(crate) id: &'a [u8],
    pub(crate) label: &'a str,
}

/// Pure template recipe shared by initial plans and the existing installed
/// policy adapter. TemplateSize measures; Template materializes after admission.
/// Implementations do not acquire quotas, guards or native handles.
pub(crate) trait KeyGenerationDescription: KeyAdmissionDescription {
    fn generation_identity(&self) -> Result<GenerationIdentity<'_>>;
    fn generation_mechanism(&self) -> Result<CK_MECHANISM_TYPE>;
    fn generation_templates_as<T: crate::attributes::TemplateSink>(&self)
        -> Result<(T, Option<T>)>;
}

mod canonical;
mod public_key;
mod software;
pub use public_key::EdwardsCurve;
mod curves;
mod ecdsa;
mod native_signature;
pub(crate) mod rsa_evidence;
pub(crate) mod rsa_observation;
mod signature_encoding;
mod signing;
pub(crate) use native_signature::SignatureParameters;
pub(crate) use signing::{
    ClassicalPairOwnerStorage, ClassicalPairPlan, ClassicalPairStorage, PreparedClassicalPair,
    PreparedSigningRestore,
};
mod dsa;
mod historical;
pub(crate) mod integer_key;
pub(crate) mod private_material;
mod public_binding;
pub use public_binding::PrivateEncodingReport;
mod public_verifier;
pub use historical::{
    DsaVerificationDigest, DsaVerificationHash, HistoricalClassification, HistoricalDigest,
    HistoricalHash, HistoricalProfile, HistoricalPssParameters, HistoricalVerificationResult,
};
mod rsa;
pub use rsa::RsaPssParameters;
mod eddsa;
pub use curves::WeierstrassCurve as EcCurve;
pub use ecdsa::{HashProvenance, VerificationResult};
pub use eddsa::{EdDsaParameters, EdDsaVariant};
pub use integer_key::RsaExponentClass;
pub use signing::{
    ClassicalKeyAlgorithm, ClassicalKeyPair, ClassicalKeySpec, ClassicalSignature,
    RsaSignatureProfile, SignatureHashProvenance, SignatureProfile, SigningKey, SigningRequest,
};
pub mod pqc;
mod pqc_material;

pub(crate) use pqc_material::PqcExportOwner;
pub use pqc_material::{
    PqcImportedPrivateKey, PqcPrivateEncoding, PqcPrivateExport, PqcPrivateImportSpec,
    PqcPrivateInput, PqcPrivateKeyAlgorithm,
};
pub(crate) mod key_evidence;
pub(crate) mod public_import;
mod verification;
pub(crate) use verification::{
    PreparedVerification, VerificationOwnerStorage, VerificationPlan, VerificationStorage,
};
pub use verification::{VerificationKey, VerificationProfile};
pub(crate) use verification::{
    VerificationPublication, VerificationPublicationPlan, VerificationPublicationStorage,
};

/// Modern digest catalogue. Historical hashes are not admitted by this type.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum HashAlgorithm {
    /// SHA-224, FIPS 180-4.
    Sha224,
    /// SHA-256, FIPS 180-4.
    Sha256,
    /// SHA-384, FIPS 180-4.
    Sha384,
    /// SHA-512, FIPS 180-4.
    Sha512,
    /// SHA3-224, FIPS 202.
    Sha3_224,
    /// SHA3-256, FIPS 202.
    Sha3_256,
    /// SHA3-384, FIPS 202.
    Sha3_384,
    /// SHA3-512, FIPS 202.
    Sha3_512,
}
impl HashAlgorithm {
    /// Complete catalogue represented by this type, in algorithm-family order.
    /// Presence here does not imply support by a particular PKCS#11 module.
    pub const ALL: [Self; 8] = [
        Self::Sha224,
        Self::Sha256,
        Self::Sha384,
        Self::Sha512,
        Self::Sha3_224,
        Self::Sha3_256,
        Self::Sha3_384,
        Self::Sha3_512,
    ];

    pub(crate) fn from_mechanism(mechanism: u64) -> Option<Self> {
        Self::ALL
            .into_iter()
            .find(|hash| hash.mechanism_number() == mechanism)
    }

    /// Exact PKCS#11 digest mechanism identifier, for APIs selecting a native hash.
    /// This is an identifier, not a claim that the current module supports it.
    pub fn mechanism_number(self) -> u64 {
        self.mechanism() as u64
    }
    /// Exact output length, in bytes.
    pub fn output_length(self) -> usize {
        match self {
            Self::Sha224 | Self::Sha3_224 => 28,
            Self::Sha256 | Self::Sha3_256 => 32,
            Self::Sha384 | Self::Sha3_384 => 48,
            Self::Sha512 | Self::Sha3_512 => 64,
        }
    }
    pub(crate) fn mechanism(self) -> CK_MECHANISM_TYPE {
        match self {
            Self::Sha224 => CKM_SHA224,
            Self::Sha256 => CKM_SHA256,
            Self::Sha384 => CKM_SHA384,
            Self::Sha512 => CKM_SHA512,
            Self::Sha3_224 => CKM_SHA3_224,
            Self::Sha3_256 => CKM_SHA3_256,
            Self::Sha3_384 => CKM_SHA3_384,
            Self::Sha3_512 => CKM_SHA3_512,
        }
    }
}

/// Mandatory hash origin and route for each RSA/ECDSA/DSA message request.
/// There is deliberately no Default implementation or module-wide selection.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum HashExecution {
    /// Compute in Rust before taking the session/lifecycle guards.
    RustSoftware,
    /// Use the explicitly requested provider signature-with-hash mechanism.
    Pkcs11Combined,
    /// Digest on the provider, followed by its signature primitive.
    Pkcs11DigestThenPrimitive,
}

/// Explicit module ceilings; no library-defined maximum or nonzero minimum.
#[derive(Clone, Copy, Debug)]
pub struct CryptoLimits {
    /// Maximum number of input pieces; zero permits no pieces.
    pub maximum_parts: usize,
    /// Maximum total input bytes; zero permits only empty data. For PKCS#8
    /// private-key imports, this bounds private DER plus the expected public SPKI.
    pub maximum_total_bytes: usize,
}
impl CryptoLimits {
    pub(crate) fn validate(self) -> Result<()> {
        // These are policy budgets, not allocation requests or ABI lengths.
        // Validate actual inputs at their conversion/allocation boundary.
        Ok(())
    }
}
/// Mandatory per-call input budgets, bounded by immutable module ceilings.
#[derive(Clone, Copy, Debug)]
pub struct InputLimits {
    /// Maximum number of already available pieces; zero permits no pieces.
    pub maximum_parts: usize,
    /// Maximum sum of their lengths; zero permits only empty data.
    pub maximum_total_bytes: usize,
}
impl InputLimits {
    pub(crate) fn validate(self, module: CryptoLimits, parts: &[&[u8]]) -> Result<()> {
        self.validate_lengths(module, parts.len(), parts.iter().map(|part| Ok(part.len())))
            .map(|_| ())
    }
    /// Count a borrowed or decoded input without allocating a temporary slice
    /// table. The same caller/module ceilings govern both representations.
    pub(crate) fn validate_lengths(
        self,
        module: CryptoLimits,
        count: usize,
        lengths: impl Iterator<Item = Result<usize>>,
    ) -> Result<usize> {
        module.validate()?;
        if self.maximum_parts > module.maximum_parts
            || self.maximum_total_bytes > module.maximum_total_bytes
            || count > self.maximum_parts
        {
            return Err(Error::Rejected(
                crate::RejectionReason::ClassicalSignatures(
                    crate::ClassicalSignaturesRejection::CryptoInputCeilings,
                ),
            ));
        }
        let mut total = 0usize;
        let mut observed = 0usize;
        for length in lengths {
            let length = length?;
            if observed == count {
                return Err(Error::Rejected(
                    crate::RejectionReason::ClassicalSignatures(
                        crate::ClassicalSignaturesRejection::CryptoInputCountChanged,
                    ),
                ));
            }
            observed += 1;
            bounds::ck_length(length)?;
            total = total.checked_add(length).ok_or(Error::Rejected(
                crate::RejectionReason::ClassicalSignatures(
                    crate::ClassicalSignaturesRejection::CryptoTotalOverflow,
                ),
            ))?;
            if total > self.maximum_total_bytes {
                return Err(Error::Rejected(
                    crate::RejectionReason::ClassicalSignatures(
                        crate::ClassicalSignaturesRejection::CryptoTotalCeiling,
                    ),
                ));
            }
        }
        if observed != count {
            return Err(Error::Rejected(
                crate::RejectionReason::ClassicalSignatures(
                    crate::ClassicalSignaturesRejection::CryptoInputCountChanged,
                ),
            ));
        }
        Ok(total)
    }
}

mod edwards_options;
pub use edwards_options::{
    EdwardsEncodingReport, EdwardsKeySizeUnits, EdwardsOptions, EdwardsParameterEncoding,
    EdwardsPointEncoding,
};
/// Module crypto limits and representation only; never a global hashing choice.
#[derive(Clone, Copy, Debug)]
pub struct CryptoOptions {
    /// Explicit module ceilings; per-call choices are bounded by these values.
    pub limits: CryptoLimits,
    /// Explicit representation semantics.
    pub edwards: EdwardsOptions,
}

/// Owned typed digest. No formatter, implicit copy, or arbitrary RSA block.
pub struct PreparedDigest {
    pub(crate) algorithm: HashAlgorithm,
    bytes: DigestBytes,
}
// Keep the native output owner and its reservation alive when publishing an
// advanced result. Both variants erase their full allocation when dropped.
enum DigestBytes {
    Owned(SecretBytes),
    Budgeted(crate::symmetric::memory::Buffer),
}
impl PreparedDigest {
    /// Cryptographic provenance does not imply memory provenance. An autonomous
    /// digest contributes no credit; a native result retains its real allocation.
    pub(super) fn retained_bytes(
        &self,
        budget: &std::sync::Arc<crate::symmetric::memory::Budget>,
    ) -> Result<crate::symmetric::memory::RetainedBytes> {
        use crate::symmetric::memory::RetainedStorage;
        crate::symmetric::memory::RetainedBytes::measure(budget, |retained| {
            match &self.bytes {
                DigestBytes::Owned(bytes) => bytes.retain_credits(retained)?,
                DigestBytes::Budgeted(bytes) => bytes.retain_credits(retained)?,
            }
            Ok(())
        })
    }

    pub(crate) fn from_owned(algorithm: HashAlgorithm, bytes: SecretBytes) -> Self {
        Self {
            algorithm,
            bytes: DigestBytes::Owned(bytes),
        }
    }
    pub(crate) fn take_budgeted(
        algorithm: HashAlgorithm,
        bytes: &mut crate::symmetric::memory::Buffer,
    ) -> Result<Self> {
        if bytes.as_slice().len() != algorithm.output_length() {
            return Err(Error::Rejected(
                crate::RejectionReason::ClassicalSignatures(
                    crate::ClassicalSignaturesRejection::DigestOutputLength,
                ),
            ));
        }
        Ok(Self {
            algorithm,
            bytes: DigestBytes::Budgeted(bytes.take()),
        })
    }
    /// Accept exact digest length. This does not attest how the caller computed it.
    pub fn from_bytes(algorithm: HashAlgorithm, bytes: &[u8]) -> Result<Self> {
        if bytes.len() != algorithm.output_length() {
            return Err(Error::Rejected(
                crate::RejectionReason::ClassicalSignatures(
                    crate::ClassicalSignaturesRejection::DigestLength,
                ),
            ));
        }
        let mut owned = SecretBytes::new(bytes.len())?;
        owned.as_mut_slice().copy_from_slice(bytes);
        Ok(Self {
            algorithm,
            bytes: DigestBytes::Owned(owned),
        })
    }
    /// Declared algorithm; caller-created values do not establish provenance.
    pub fn algorithm(&self) -> HashAlgorithm {
        self.algorithm
    }
    /// Borrow digest bytes; caller copies remain the caller's responsibility.
    pub fn as_bytes(&self) -> &[u8] {
        match &self.bytes {
            DigestBytes::Owned(bytes) => bytes.as_slice(),
            DigestBytes::Budgeted(bytes) => bytes.as_slice(),
        }
    }
}

struct NativeDigestCall {
    mechanism: CK_MECHANISM,
    input: SecretBytes,
    output: SecretBytes,
    length: CK_ULONG,
    // The result carries its own allocation credit; this remainder belongs to
    // the retained call frame and leaves only after its input and output.
    _credit: crate::symmetric::memory::Credit,
}
mod native_digest;
mod native_route;

/// Diagnostic owners at the public boundary of a synchronous classical call.
/// A native prehash and its following primitive have separate prepared leaves;
/// contextual login retains its own native/local error composition.
#[derive(Default)]
pub(crate) struct ClassicalDiagnostics {
    prehash: Option<crate::error::PreparedCompletionCell>,
    primitive: Option<crate::error::PreparedCompletionCell>,
    authentication: Option<crate::session::ContextDiagnostics>,
}
// SAFETY: the parameterless mechanism and both buffers are exclusively owned;
// native addresses are used only from the stable, retained session frame.
unsafe impl Send for NativeDigestCall {}
impl NativeDigestCall {
    fn mechanism_unchanged(&self, expected: CK_MECHANISM_TYPE) -> bool {
        self.mechanism.mechanism == expected
            && self.mechanism.pParameter.is_null()
            && self.mechanism.ulParameterLen == 0
    }
}

impl Session {
    /// Native one-part digest, without software/provider/algorithm fallback.
    /// The explicit algorithm is submitted to C_DigestInit even when discovery
    /// did not announce it; discovery observations remain available separately.
    pub fn digest(
        &self,
        algorithm: HashAlgorithm,
        message: &[u8],
        limits: InputLimits,
    ) -> Result<PreparedDigest> {
        let mut invocation_diagnostics = crate::crypto::ClassicalDiagnostics::default();
        let diagnostics = &mut invocation_diagnostics;
        self.digest_parts(algorithm, &[message], limits, false, diagnostics)
    }
    /// Real native Init/Update/Final over a bounded, already available list.
    /// Empty lists issue one zero-length Update to hash the empty message.
    /// No input concatenation, sizing retry or alternate path is performed.
    pub fn digest_multipart(
        &self,
        algorithm: HashAlgorithm,
        parts: &[&[u8]],
        limits: InputLimits,
    ) -> Result<PreparedDigest> {
        let mut invocation_diagnostics = crate::crypto::ClassicalDiagnostics::default();
        let diagnostics = &mut invocation_diagnostics;
        self.digest_parts(algorithm, parts, limits, true, diagnostics)
    }
    fn digest_parts(
        &self,
        algorithm: HashAlgorithm,
        parts: &[&[u8]],
        limits: InputLimits,
        multipart: bool,
        diagnostics: &mut crate::crypto::ClassicalDiagnostics,
    ) -> Result<PreparedDigest> {
        limits.validate(self.inner.crypto_options.limits, parts)?;
        let native = NativeHash::Modern(algorithm);
        let plan = native_digest::Plan::new(&native, parts, multipart)?;
        let epoch = self.snapshot.authentication_stamp();
        let progress = crate::session::AdmissionProgress::default();
        let (prepared, state) =
            self.prepare_with_roles_prepaid_at_epoch([], false, epoch, &progress, |overhead| {
                plan.prepare(self, overhead, &progress, epoch)
            })?;
        Ok(PreparedDigest::from_owned(
            algorithm,
            self.native_digest_guarded(&state, native, parts, multipart, prepared, diagnostics)?,
        ))
    }
    // Caller has validated input budgets. Retain its existing guard owner for
    // nested native frames; never reacquire or release the outer locks here.
    fn digest_guarded(
        &self,
        state: &crate::session::SessionAccess<'_>,
        algorithm: HashAlgorithm,
        parts: &[&[u8]],
        multipart: bool,
        prepared: native_digest::Prepared,
        diagnostics: &mut crate::crypto::ClassicalDiagnostics,
    ) -> Result<PreparedDigest> {
        Ok(PreparedDigest::from_owned(
            algorithm,
            self.native_digest_guarded(
                state,
                NativeHash::Modern(algorithm),
                parts,
                multipart,
                prepared,
                diagnostics,
            )?,
        ))
    }
    fn native_digest_guarded(
        &self,
        state: &crate::session::SessionAccess<'_>,
        algorithm: NativeHash,
        parts: &[&[u8]],
        multipart: bool,
        prepared: native_digest::Prepared,
        diagnostics: &mut crate::crypto::ClassicalDiagnostics,
    ) -> Result<SecretBytes> {
        let native_digest::Prepared {
            call: prepared,
            diagnostic,
        } = prepared;
        let diagnostic = diagnostics.prehash.insert(diagnostic).cell();
        if !multipart && parts.len() != 1 {
            return Err(Error::Rejected(
                crate::RejectionReason::ClassicalSignatures(
                    crate::ClassicalSignaturesRejection::SinglePartDigestRequiresOneInput,
                ),
            ));
        }
        let handle = self.entry(state)?.handle;
        let kind = algorithm.mechanism();
        let capacity = algorithm.output_length();
        let init = state.native.table.C_DigestInit.ok_or(Error::Rejected(
            crate::RejectionReason::ClassicalSignatures(
                crate::ClassicalSignaturesRejection::CDigestInitUnavailable,
            ),
        ))?;
        // Retain one complete route before Init. A native return cannot change
        // the selected tuple or turn a later Update/Final into an absent entry.
        let route = if multipart {
            crate::crypto::native_route::Route::Multipart {
                update: state.native.table.C_DigestUpdate.ok_or(Error::Rejected(
                    crate::RejectionReason::ClassicalSignatures(
                        crate::ClassicalSignaturesRejection::CDigestUpdateUnavailable,
                    ),
                ))?,
                finish: state.native.table.C_DigestFinal.ok_or(Error::Rejected(
                    crate::RejectionReason::ClassicalSignatures(
                        crate::ClassicalSignaturesRejection::CDigestFinalUnavailable,
                    ),
                ))?,
            }
        } else {
            crate::crypto::native_route::Route::Single(state.native.table.C_Digest.ok_or(
                Error::Rejected(crate::RejectionReason::ClassicalSignatures(
                    crate::ClassicalSignaturesRejection::CDigestUnavailable,
                )),
            )?)
        };
        let empty: &[&[u8]] = &[&[]];
        let pieces = if parts.is_empty() { empty } else { parts };
        // One stable scratch allocation precedes Init. A successful synchronous
        // Update consumes its input; only then may the next piece reuse storage.
        // An uncompleted Update retains this exact allocation and all guards.
        // Memory scales with the largest piece, not with the complete message.
        let input_capacity = pieces.iter().map(|piece| piece.len()).max().unwrap_or(0);
        if !prepared.mechanism_unchanged(kind)
            || prepared.input.len() != input_capacity
            || prepared.output.len() != capacity
            || prepared.length != bounds::ck_length(capacity)?
        {
            return Err(Error::Rejected(
                crate::RejectionReason::ClassicalSignatures(
                    crate::ClassicalSignaturesRejection::NativeDigestPreparationChanged,
                ),
            ));
        }
        let mut frame = crate::native::frame::NativeFrame::session(state.clone(), prepared)?;
        {
            let (returned, body) = frame.session_parts();
            let state = &body.access;
            let call = &mut *body.data;
            state.native.record("C_DigestInit")?;
            let mut sequence = Sequence::for_frame_prepared(state, self, returned, diagnostic);
            // SAFETY: the stable frame and shared guard owner cover the entire
            // digest, even when it is nested inside a signing/key-proof owner.
            let rv = returned.observe(unsafe { init(handle, &mut call.mechanism) }, &state.native);
            let inspected_return = sequence.inspect_return(
                rv,
                "C_DigestInit",
                crate::native_return::protocol::SequencePhase::Initialize,
                || {
                    if !call.mechanism_unchanged(kind) {
                        return Err(Error::Rejected(
                            crate::RejectionReason::ClassicalSignatures(
                                crate::ClassicalSignaturesRejection::DigestMechanismChanged,
                            ),
                        ));
                    }

                    Ok(())
                },
            )?;

            inspected_return.check(false)?;
            match route {
                crate::crypto::native_route::Route::Multipart { update, finish } => {
                    for expected in pieces {
                        let length = bounds::ck_length(expected.len())?;
                        zeroize::Zeroize::zeroize(call.input.as_mut_slice());
                        call.input.as_mut_slice()[..expected.len()].copy_from_slice(expected);
                        sequence.record_next("C_DigestUpdate")?;
                        // SAFETY: writable protected copy retained by the frame;
                        // lengths were checked before Init and are never resized.
                        let rv = returned.observe(
                            unsafe {
                                update(handle, call.input.as_mut_slice().as_mut_ptr(), length)
                            },
                            &state.native,
                        );
                        let inspected_return = sequence.inspect_return(
                            rv,
                            "C_DigestUpdate",
                            crate::native_return::protocol::SequencePhase::Continue(
                                crate::native_return::sequence::OutputRequest::Unspecified,
                            ),
                            || {
                                if !call.mechanism_unchanged(kind)
                                    || &call.input.as_slice()[..expected.len()] != *expected
                                    || call.input.as_slice()[expected.len()..]
                                        .iter()
                                        .any(|byte| *byte != 0)
                                {
                                    return Err(Error::Rejected(
                                        crate::RejectionReason::ClassicalSignatures(
                                            crate::ClassicalSignaturesRejection::DigestInputChanged,
                                        ),
                                    ));
                                }

                                Ok(())
                            },
                        )?;

                        inspected_return.check(false)?;
                    }
                    sequence.record_next("C_DigestFinal")?;
                    // SAFETY: aligned length slot and exact output allocation both
                    // stay in the frame; no NULL size query or retry is performed.
                    let rv = returned.observe(
                        unsafe {
                            finish(
                                handle,
                                call.output.as_mut_slice().as_mut_ptr(),
                                &mut call.length,
                            )
                        },
                        &state.native,
                    );
                    let last = pieces.last().expect("at least one digest piece");
                    let inspected_return = sequence.inspect_output_return(
                        rv,
                        "C_DigestFinal",
                        capacity,
                        || call.length,
                        || {
                            if !call.mechanism_unchanged(kind)
                                || &call.input.as_slice()[..last.len()] != *last
                                || call.input.as_slice()[last.len()..]
                                    .iter()
                                    .any(|byte| *byte != 0)
                            {
                                return Err(Error::Rejected(
                                    crate::RejectionReason::ClassicalSignatures(
                                        crate::ClassicalSignaturesRejection::DigestMechanismChanged,
                                    ),
                                ));
                            }
                            if rv == fe11_sys::CKR_OK {
                                bounds::final_length(call.length, capacity).map_err(|_| {
                                    Error::Rejected(crate::RejectionReason::ClassicalSignatures(
                                        crate::ClassicalSignaturesRejection::NativeDigestCapacity,
                                    ))
                                })?;
                            }
                            Ok(())
                        },
                    )?;

                    inspected_return.check(false)?;
                }
                crate::crypto::native_route::Route::Single(digest) => {
                    let length = bounds::ck_length(pieces[0].len())?;
                    call.input.as_mut_slice().copy_from_slice(pieces[0]);
                    sequence.record_next("C_Digest")?;
                    // SAFETY: owned input, output and length slot are stable and
                    // protected by the same guard owner as the outer operation.
                    let rv = returned.observe(
                        unsafe {
                            digest(
                                handle,
                                call.input.as_mut_slice().as_mut_ptr(),
                                length,
                                call.output.as_mut_slice().as_mut_ptr(),
                                &mut call.length,
                            )
                        },
                        &state.native,
                    );
                    let inspected_return = sequence.inspect_output_return(
                        rv,
                        "C_Digest",
                        capacity,
                        || call.length,
                        || {
                            if !call.mechanism_unchanged(kind) || call.input.as_slice() != pieces[0]
                            {
                                return Err(Error::Rejected(
                                    crate::RejectionReason::ClassicalSignatures(
                                        crate::ClassicalSignaturesRejection::DigestInputChanged,
                                    ),
                                ));
                            }
                            if rv == fe11_sys::CKR_OK {
                                bounds::final_length(call.length, capacity).map_err(|_| {
                                    Error::Rejected(crate::RejectionReason::ClassicalSignatures(
                                        crate::ClassicalSignaturesRejection::NativeDigestCapacity,
                                    ))
                                })?;
                            }
                            Ok(())
                        },
                    )?;

                    inspected_return.check(false)?;
                }
            }
            let length = bounds::final_length(call.length, capacity).map_err(|_| {
                returned.quarantine(&state.native);
                sequence.invalid_output(crate::RejectionReason::ClassicalSignatures(
                    crate::ClassicalSignaturesRejection::NativeDigestCapacity,
                ))
            })?;
            if length != capacity {
                return Err(
                    sequence.invalid_value(crate::RejectionReason::ClassicalSignatures(
                        crate::ClassicalSignaturesRejection::DigestOutputLength,
                    )),
                );
            }
            sequence.complete();
        }
        let completed = frame.into_inner()?;
        self.public_result(&completed.access, Ok(completed.data.into_inner().output))
    }
}

// Internal closed dispatch: historical hashes cannot enter modern APIs.
pub(super) enum NativeHash {
    Modern(HashAlgorithm),
    Historical(historical::HistoricalHash),
}
impl NativeHash {
    fn mechanism(&self) -> CK_MECHANISM_TYPE {
        match self {
            Self::Modern(h) => h.mechanism(),
            Self::Historical(h) => h.mechanism(),
        }
    }
    fn output_length(&self) -> usize {
        match self {
            Self::Modern(h) => h.output_length(),
            Self::Historical(h) => h.output_length(),
        }
    }
}

/// Native agreement and KDF profiles with opaque results.
pub mod derivation;

pub use signing::{IntroducedSigningKey, SigningIntroductionSpec, TransportSigningKeyPair};

pub(crate) mod kem;
