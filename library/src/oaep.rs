// SPDX-License-Identifier: Apache-2.0

use crate::{bounds, session::Sequence, Error, ObjectClass, ObjectRef, Result, Session};
use fe11_sys::*;
use zeroize::{Zeroize, Zeroizing};
mod preparation;

/// Diagnostics stay at the public decryption boundary, independently of the
/// native frame and the credential borrow used for contextual authentication.
#[derive(Default)]
struct DecryptionDiagnostics {
    sequence: Option<crate::error::PreparedCompletionCell>,
    authentication: Option<crate::session::ContextDiagnostics>,
}

/// Explicit native RSA-OAEP hash, mask-generation function and exact binary label.
/// The provider decides parameter support; no additional label policy is imposed.
#[derive(Clone, Copy, Debug)]
pub struct OaepParams<'a> {
    /// Caller-selected PKCS#11 hash identifier.
    pub hash: u64,
    /// Caller-selected PKCS#11 mask-generation identifier.
    pub mgf: u64,
    /// Exact bytes; empty means an explicit empty label, with no normalization.
    pub label: &'a [u8],
}
impl OaepParams<'_> {
    fn validate(&self) -> Result<()> {
        let _: CK_MECHANISM_TYPE = self.hash.try_into().map_err(|_| {
            Error::Rejected(crate::RejectionReason::KeyTransport(
                crate::KeyTransportRejection::HashIdentifierConversion,
            ))
        })?;
        let _: CK_RSA_PKCS_MGF_TYPE = self.mgf.try_into().map_err(|_| {
            Error::Rejected(crate::RejectionReason::KeyTransport(
                crate::KeyTransportRejection::MgfIdentifierConversion,
            ))
        })?;
        bounds::ck_length(self.label.len())?;
        Ok(())
    }
    fn checked_label(&self) -> Result<Vec<u8>> {
        self.validate()?;
        let mut label = Vec::new();
        label.try_reserve_exact(self.label.len()).map_err(|_| {
            Error::Rejected(crate::RejectionReason::KeyTransport(
                crate::KeyTransportRejection::OaepLabelAllocation,
            ))
        })?;
        label.extend_from_slice(self.label);
        Ok(label)
    }
}
#[doc = include_str!("../docs/api/oaep/SecretPlaintext.md")]
pub struct SecretPlaintext {
    bytes: Zeroizing<Vec<u8>>,
    length: usize,
    // Present for module-produced results; autonomous construction stays unbound.
    credit: Option<crate::symmetric::memory::Credit>,
}
impl SecretPlaintext {
    /// Allocate the explicitly requested length before the first secret write.
    /// Algorithm-dependent plaintext limits are enforced by the selected native operation.
    pub fn new(length: usize) -> Result<Self> {
        bounds::ck_length(length)?;
        let mut bytes = Vec::new();
        bytes.try_reserve_exact(length).map_err(|_| {
            Error::Rejected(crate::RejectionReason::KeyTransport(
                crate::KeyTransportRejection::OaepPlaintextAllocation,
            ))
        })?;
        // Initialize all owned capacity so the entire allocation can be erased.
        bytes.resize(bytes.capacity(), 0);
        Ok(Self {
            bytes: Zeroizing::new(bytes),
            length,
            credit: None,
        })
    }
    /// Borrow only initialized logical plaintext bytes; do not log or copy them.
    pub fn as_slice(&self) -> &[u8] {
        &self.bytes[..self.length]
    }
    /// Fill or update the logical plaintext in its existing protected allocation.
    pub fn as_mut_slice(&mut self) -> &mut [u8] {
        &mut self.bytes[..self.length]
    }
    /// Logical length within the allocation chosen by the caller.
    pub fn len(&self) -> usize {
        self.length
    }
    /// Whether the logical plaintext is empty.
    pub fn is_empty(&self) -> bool {
        self.length == 0
    }
    fn erase(&mut self) {
        self.bytes.as_mut_slice().zeroize();
    }
}
impl Drop for SecretPlaintext {
    fn drop(&mut self) {
        self.erase();
    }
}
// Native output uses the same fallible, fully erased owner. Its requested
// capacity is the observed RSA modulus width, never a fixed profile size.
struct SecretScratch(SecretPlaintext);
// Public label copy is never resized after this creates its native pointer.
fn native_params(params: OaepParams<'_>, label: &mut [u8]) -> Result<CK_RSA_PKCS_OAEP_PARAMS> {
    Ok(CK_RSA_PKCS_OAEP_PARAMS {
        hashAlg: params.hash.try_into().map_err(|_| {
            Error::Rejected(crate::RejectionReason::KeyTransport(
                crate::KeyTransportRejection::HashIdentifierConversion,
            ))
        })?,
        mgf: params.mgf.try_into().map_err(|_| {
            Error::Rejected(crate::RejectionReason::KeyTransport(
                crate::KeyTransportRejection::MgfIdentifierConversion,
            ))
        })?,
        source: CKZ_DATA_SPECIFIED as _,
        pSourceData: if label.is_empty() {
            std::ptr::null_mut()
        } else {
            label.as_mut_ptr().cast()
        },
        ulSourceDataLen: bounds::ck_length(label.len())?,
    })
}
fn mechanism(p: &mut CK_RSA_PKCS_OAEP_PARAMS) -> Result<CK_MECHANISM> {
    Ok(CK_MECHANISM {
        mechanism: CKM_RSA_PKCS_OAEP as _,
        pParameter: (p as *mut CK_RSA_PKCS_OAEP_PARAMS).cast(),
        ulParameterLen: bounds::ck_length(std::mem::size_of_val(p))?,
    })
}
// Every native-addressable value belongs to the stable frame, including the
// parameter descriptor and output length. The object permit prevents concurrent
// mutation/destruction while a native call owns the object.
struct OaepCall<I, O> {
    label: Vec<u8>,
    parameters: CK_RSA_PKCS_OAEP_PARAMS,
    mechanism: CK_MECHANISM,
    input: I,
    output: O,
    output_length: CK_ULONG,
    _object: crate::registry::ReadPermit,
    _credit: crate::symmetric::memory::Credit,
}
// SAFETY: descriptor pointers target owned label/parameters and Send input/output;
// they are bound after stable allocation and retained until native termination.
unsafe impl<I: Send, O: Send> Send for OaepCall<I, O> {}
impl<I, O> OaepCall<I, O> {
    // Bind only after allocation in NativeFrame; parameters must not move again.
    fn bind(&mut self) -> Result<()> {
        self.mechanism = mechanism(&mut self.parameters)?;
        Ok(())
    }

    fn descriptors_unchanged(&self, expected: OaepParams<'_>) -> bool {
        let label_pointer = if self.label.is_empty() {
            std::ptr::null_mut()
        } else {
            self.label.as_ptr().cast_mut().cast()
        };
        self.mechanism.mechanism == CKM_RSA_PKCS_OAEP as CK_MECHANISM_TYPE
            && self.mechanism.pParameter == std::ptr::addr_of!(self.parameters).cast_mut().cast()
            && self.mechanism.ulParameterLen
                == std::mem::size_of::<CK_RSA_PKCS_OAEP_PARAMS>() as CK_ULONG
            && self.parameters.hashAlg as u64 == expected.hash
            && self.parameters.mgf as u64 == expected.mgf
            && self.parameters.source == CKZ_DATA_SPECIFIED as CK_RSA_PKCS_OAEP_SOURCE_TYPE
            && self.parameters.pSourceData == label_pointer
            && self.parameters.ulSourceDataLen as usize == self.label.len()
            && self.label == expected.label
    }
}
impl Session {
    /// Encrypt with an OAEP public key, using its observed access requirements.
    /// One call after Init, no sizing query, fallback or retry. Consumed plaintext
    /// is erased on ordinary return/unwind. If native completion is unproven,
    /// its complete frame is retained and the session cannot be reused;
    /// erasure cannot be promised while native code may still reference it.
    pub fn encrypt_oaep(
        &self,
        key: &ObjectRef,
        plaintext: SecretPlaintext,
        params: OaepParams<'_>,
    ) -> Result<Vec<u8>> {
        // Keep diagnostic ownership outside every access/frame scope, including
        // fallible preparation before the access is moved into its native frame.
        let mut diagnostic_root = None;
        params.validate()?;
        let capacity = key.identity.modulus_bits.div_ceil(8);
        let input_length = bounds::ck_length(plaintext.len())?;
        let progress = crate::session::AdmissionProgress::default();
        let epoch = self.snapshot.authentication_stamp();
        // Validate the route and reference before resource admission. This closure
        // grants access only: it must never initialize a native operation.
        let acquire = |attempt| {
            use crate::session::activity::PossessionAttempt;
            let access = match attempt {
                PossessionAttempt::Nonwaiting => {
                    self.try_operation_access_progress(false, &progress)
                }
                PossessionAttempt::Admitted => self.access_progress(&progress),
            }?;
            self.object(&access, key, Some(ObjectClass::PublicKey))?;
            access.native.table.C_EncryptInit.ok_or(Error::Rejected(
                crate::RejectionReason::KeyTransport(
                    crate::KeyTransportRejection::CEncryptInitUnavailable,
                ),
            ))?;
            access.native.table.C_Encrypt.ok_or(Error::Rejected(
                crate::RejectionReason::KeyTransport(
                    crate::KeyTransportRejection::CEncryptUnavailable,
                ),
            ))?;
            Ok(access)
        };
        drop(acquire(
            crate::session::activity::PossessionAttempt::Admitted,
        )?);
        let readers = crate::session::activity::Readers::prepare_at_epoch(
            self,
            [Some(&key.identity.activity)],
            epoch,
        )?;
        let mut authentication_plan =
            crate::session::ContextLoginPlan::at_epoch(self, None, epoch)?;
        let (storage, _, s, mut permits) = authentication_plan.prepare_readers_with(
            self,
            &readers,
            |overhead| {
                preparation::Encryption::prepare(
                    self, params, &plaintext, capacity, overhead, &progress, epoch,
                )
            },
            acquire,
        )?;
        let diagnostic = diagnostic_root.insert(storage.diagnostic).cell();
        let mut label = storage.label;
        let parameters = native_params(params, &mut label)?;
        let expected_input = storage.witness;
        let permit = permits[0].take().expect("prepared RSA key reader");
        let object = self.object(&s, key, Some(ObjectClass::PublicKey))?;
        let handle = self.entry(&s)?.handle;
        let init = s.native.table.C_EncryptInit.ok_or(Error::Rejected(
            crate::RejectionReason::KeyTransport(
                crate::KeyTransportRejection::CEncryptInitUnavailable,
            ),
        ))?;
        let encrypt = s.native.table.C_Encrypt.ok_or(Error::Rejected(
            crate::RejectionReason::KeyTransport(crate::KeyTransportRejection::CEncryptUnavailable),
        ))?;
        let mut frame = crate::native::frame::NativeFrame::session(
            s,
            OaepCall {
                label,
                parameters,
                mechanism: crate::native::output::mechanism(),
                input: plaintext,
                output: storage.output,
                _credit: storage.credit,
                output_length: bounds::ck_length(capacity)?,
                _object: permit,
            },
        )?;
        let (returned, body) = frame.session_parts();
        let s = &body.access;
        let call = &mut *body.data;
        let result = (|| {
            call.bind()?;

            s.native.record("C_EncryptInit")?;
            let mut sequence = Sequence::for_frame_prepared(s, self, returned, diagnostic);
            // SAFETY: the frame owns the access guards, object permit, stable
            // mechanism, nested parameters and label before dispatch.
            let rv = returned.observe(
                unsafe { init(handle, &mut call.mechanism, object) },
                &s.native,
            );
            let inspected_return = sequence.inspect_return(
                rv,
                "C_EncryptInit",
                crate::native_return::protocol::SequencePhase::Initialize,
                || {
                    if rv != CKR_PENDING
                        && (!call.descriptors_unchanged(params)
                            || call.input.as_slice() != expected_input.as_slice())
                    {
                        return Err(Error::Rejected(crate::RejectionReason::KeyTransport(
                            crate::KeyTransportRejection::OaepInputDescriptorChanged,
                        )));
                    }

                    Ok(())
                },
            )?;

            inspected_return.check(false)?;

            sequence.record_next("C_Encrypt")?;
            // SAFETY: inputs, output and length slot are owned by this stable
            // frame. PENDING is marked before reading any native output.
            let rv = returned.observe(
                unsafe {
                    encrypt(
                        handle,
                        call.input.bytes.as_mut_ptr(),
                        input_length,
                        call.output.as_mut_ptr(),
                        &mut call.output_length,
                    )
                },
                &s.native,
            );
            let inspected_return = sequence.inspect_output_return(
                rv,
                "C_Encrypt",
                capacity,
                || call.output_length,
                || {
                    if rv != CKR_PENDING
                        && (!call.descriptors_unchanged(params)
                            || call.input.as_slice() != expected_input.as_slice())
                    {
                        return Err(Error::Rejected(crate::RejectionReason::KeyTransport(
                            crate::KeyTransportRejection::OaepInputDescriptorChanged,
                        )));
                    }
                    if rv == fe11_sys::CKR_OK {
                        bounds::final_length(call.output_length, capacity).map_err(|_| {
                            Error::Rejected(crate::RejectionReason::KeyTransport(
                                crate::KeyTransportRejection::RsaCiphertextCapacity,
                            ))
                        })?;
                    }
                    Ok(())
                },
            )?;

            inspected_return.check(true)?;
            let length = bounds::final_length(call.output_length, capacity).map_err(|_| {
                returned.quarantine(&s.native);
                sequence.invalid_output(crate::RejectionReason::KeyTransport(
                    crate::KeyTransportRejection::RsaCiphertextCapacity,
                ))
            })?;
            if length != capacity {
                return Err(sequence.invalid_value(crate::RejectionReason::KeyTransport(
                    crate::KeyTransportRejection::RsaCiphertextLength,
                )));
            }
            sequence.complete();
            Ok(std::mem::take(&mut call.output))
        })();
        key.identity.access.result(self, s, result)
    }

    /// Decrypt into protected storage, releasing no plaintext on any failure.
    /// Native refusals retain their status; proven terminal refusals allow reuse.
    /// Unproven completion retains the complete native frame and withdraws it
    /// from ordinary use. A local wrong length makes no native call.
    /// No provider timing or network-oracle resistance is claimed by this API.
    pub fn decrypt_oaep(
        &self,
        key: &ObjectRef,
        ciphertext: &[u8],
        params: OaepParams<'_>,
    ) -> Result<SecretPlaintext> {
        let mut diagnostics = DecryptionDiagnostics::default();
        self.decrypt_oaep_selected(key, ciphertext, params, None, &mut diagnostics)
    }

    /// Decrypt after one explicit contextual login following C_DecryptInit.
    /// Credentials and their capability are prepared before Init. A login
    /// refusal retains the initialized frame until successful session closure;
    /// no plaintext is released and neither Init nor login is retried.
    pub fn decrypt_oaep_with_context(
        &self,
        key: &ObjectRef,
        ciphertext: &[u8],
        params: OaepParams<'_>,
        authentication: crate::ContextAuthentication,
    ) -> Result<SecretPlaintext> {
        let mut diagnostics = DecryptionDiagnostics::default();
        self.decrypt_oaep_selected(
            key,
            ciphertext,
            params,
            Some(authentication),
            &mut diagnostics,
        )
    }

    fn decrypt_oaep_selected(
        &self,
        key: &ObjectRef,
        ciphertext: &[u8],
        params: OaepParams<'_>,
        mut authentication: Option<crate::ContextAuthentication>,
        diagnostics: &mut DecryptionDiagnostics,
    ) -> Result<SecretPlaintext> {
        let mut prepared_authentication;
        params.validate()?;
        let capacity = key.identity.modulus_bits.div_ceil(8);
        // Validate the route and reference before resource admission. This closure
        // grants access only: it must never initialize a native operation.
        let progress = crate::session::AdmissionProgress::default();
        let epoch = self.snapshot.authentication_stamp();
        let mut authentication_plan =
            crate::session::ContextLoginPlan::at_epoch(self, authentication.as_ref(), epoch)?;
        let acquire = |attempt| {
            use crate::session::activity::PossessionAttempt;
            let access = match attempt {
                PossessionAttempt::Nonwaiting => {
                    self.try_operation_access_progress(authentication.is_some(), &progress)
                }
                PossessionAttempt::Admitted if authentication.is_some() => {
                    self.context_operation_access_progress(&progress)
                }
                PossessionAttempt::Admitted => self.access_progress(&progress),
            }?;
            self.object(&access, key, Some(ObjectClass::PrivateKey))?;
            access.native.table.C_DecryptInit.ok_or(Error::Rejected(
                crate::RejectionReason::KeyTransport(
                    crate::KeyTransportRejection::CDecryptInitUnavailable,
                ),
            ))?;
            access.native.table.C_Decrypt.ok_or(Error::Rejected(
                crate::RejectionReason::KeyTransport(
                    crate::KeyTransportRejection::CDecryptUnavailable,
                ),
            ))?;
            Ok(access)
        };
        drop(acquire(
            crate::session::activity::PossessionAttempt::Admitted,
        )?);
        let readers = crate::session::activity::Readers::prepare_at_epoch(
            self,
            [Some(&key.identity.activity)],
            epoch,
        )?;
        if ciphertext.len() != capacity {
            let (s, _permits) = readers.acquire_in_context(self, || {
                acquire(crate::session::activity::PossessionAttempt::Admitted)
            })?;
            return key
                .identity
                .access
                .result(self, &s, Err(Error::InvalidCiphertext));
        }
        let (storage, mut authentication_storage, s, permits) = authentication_plan
            .prepare_readers_with(
                self,
                &readers,
                |overhead| {
                    preparation::Decryption::prepare(
                        self, params, ciphertext, capacity, overhead, &progress, epoch,
                    )
                },
                acquire,
            )?;
        let diagnostic = diagnostics.sequence.insert(storage.diagnostic).cell();
        let mut label = storage.label;
        let parameters = native_params(params, &mut label)?;
        let mut permits = permits;
        let s = s;
        prepared_authentication = crate::session::PreparedContextLogin::from_prepared(
            self,
            &s,
            &mut authentication,
            &mut authentication_storage,
        )?;
        let permit = permits[0].take().expect("prepared RSA key reader");
        let object = self.object(&s, key, Some(ObjectClass::PrivateKey))?;
        let handle = self.entry(&s)?.handle;
        let init = s.native.table.C_DecryptInit.ok_or(Error::Rejected(
            crate::RejectionReason::KeyTransport(
                crate::KeyTransportRejection::CDecryptInitUnavailable,
            ),
        ))?;
        let decrypt = s.native.table.C_Decrypt.ok_or(Error::Rejected(
            crate::RejectionReason::KeyTransport(crate::KeyTransportRejection::CDecryptUnavailable),
        ))?;
        // Allocate all storage before Init. The native scratch never becomes
        // the published plaintext; publication is a bounded copy after success.
        let scratch = storage.scratch;
        let mut plaintext = storage.plaintext;
        let input = storage.input;
        let input_length = bounds::ck_length(input.len())?;
        let mut frame = crate::native::frame::NativeFrame::session(
            s,
            OaepCall {
                label,
                parameters,
                mechanism: crate::native::output::mechanism(),
                input,
                output: scratch,
                _credit: storage.credit,
                output_length: bounds::ck_length(capacity)?,
                _object: permit,
            },
        )?;
        let (returned, body) = frame.session_parts();
        let s = &body.access;
        let call = &mut *body.data;
        let result = (|| {
            call.bind()?;
            s.native.record("C_DecryptInit")?;

            let mut sequence = Sequence::for_frame_prepared(s, self, returned, diagnostic);
            // SAFETY: all nested descriptors and referenced owners are stable
            // in the frame; session and object access exclude interleaving.
            let rv = returned.observe(
                unsafe { init(handle, &mut call.mechanism, object) },
                &s.native,
            );
            let inspected_return = sequence.inspect_return(
                rv,
                "C_DecryptInit",
                crate::native_return::protocol::SequencePhase::Initialize,
                || {
                    if rv != CKR_PENDING && !call.descriptors_unchanged(params) {
                        return Err(Error::Rejected(crate::RejectionReason::KeyTransport(
                            crate::KeyTransportRejection::OaepInputDescriptorChanged,
                        )));
                    }

                    Ok(())
                },
            )?;

            inspected_return.check(false)?;

            if let Some(mut authentication) = prepared_authentication.take() {
                let result = authentication.perform(self);
                diagnostics.authentication = Some(authentication.into_diagnostics());
                if let Err(error) = result {
                    // Authentication owns its own return/descriptor diagnostic.
                    // Its failure does not establish that this separate OAEP
                    // graph is safe to inspect. Retain the initialized frame
                    // unchanged, report authentication, and issue no Decrypt.
                    // This branch makes no claim about OAEP descriptor integrity;
                    // successful authentication is required for that check below.
                    returned.recoverable();
                    return Err(error);
                }
                if !call.descriptors_unchanged(params) || call.input != ciphertext {
                    returned.quarantine(&s.native);
                    return Err(
                        sequence.invalid_output(crate::RejectionReason::KeyTransport(crate::KeyTransportRejection::OaepInputChangedDuringContextAuthentication))
                    );
                }
            }

            sequence.record_next("C_Decrypt")?;
            // SAFETY: copied public input, full modulus-sized protected output,
            // and output length slot stay owned even after unexpected PENDING.
            let rv = returned.observe(
                unsafe {
                    decrypt(
                        handle,
                        call.input.as_mut_ptr(),
                        input_length,
                        call.output.0.bytes.as_mut_ptr(),
                        &mut call.output_length,
                    )
                },
                &s.native,
            );

            let inspected_return = sequence.inspect_output_return(
                rv,
                "C_Decrypt",
                capacity,
                || call.output_length,
                || {
                    if !call.descriptors_unchanged(params) || call.input != ciphertext {
                        return Err(Error::Rejected(crate::RejectionReason::KeyTransport(
                            crate::KeyTransportRejection::OaepInputDescriptorChanged,
                        )));
                    }
                    if rv == fe11_sys::CKR_OK {
                        bounds::final_length(call.output_length, capacity).map_err(|_| {
                            Error::Rejected(crate::RejectionReason::KeyTransport(
                                crate::KeyTransportRejection::NativePlaintextLength,
                            ))
                        })?;
                    }
                    Ok(())
                },
            )?;

            if sequence.finish_invalid_decrypt(rv) {
                return Err(Error::InvalidCiphertext);
            }
            inspected_return.check(true)?;
            let length = bounds::final_length(call.output_length, capacity).map_err(|_| {
                returned.quarantine(&s.native);
                sequence.invalid_output(crate::RejectionReason::KeyTransport(
                    crate::KeyTransportRejection::NativePlaintextLength,
                ))
            })?;

            plaintext.bytes[..length].copy_from_slice(&call.output.0.as_slice()[..length]);
            plaintext.length = length;
            call.output.0.erase();
            sequence.complete();

            Ok(plaintext)
        })();
        key.identity.access.result(self, s, result)
    }
}
