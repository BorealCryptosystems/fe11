// SPDX-License-Identifier: Apache-2.0
//! Wrap a key using caller-selected transport parameters and output storage.
//! Native return checks preserve reported lengths and descriptor-boundary failures.

use super::*;

impl Session {
    pub(crate) fn check_wrap_return(
        &self,
        rv: CK_RV,
        function: &'static str,
        length: CK_ULONG,
        capacity: usize,
    ) -> Result<()> {
        // Context and input integrity have already passed the common barrier.
        // Wrapping produces bytes, never an object creation receipt.
        if let Some(size) =
            crate::NativeOutputSize::buffer_refusal(function, rv, capacity, || length)
        {
            return Err(size.buffer_too_small());
        }
        check(rv, function, false)
    }

    /// Invoke native wrapping with the exact selected mechanism and key handles.
    /// Native attribute permissions are enforced by the module.
    /// Standard wrapping queries the required size before its output call.
    pub fn wrap_key(
        &self,
        kek: &WrappingKey,
        target: &ManagedObjectRef,
        parameters: WrapParameters<'_>,
        limits: WrapLimits,
    ) -> Result<WrappedKey> {
        let capacity = limits.validate()?;
        let profile = parameters.profile();
        let authenticated = matches!(&parameters, WrapParameters::AuthenticatedGcm { .. });
        // CallData and its enclosing SessionFrame are separate stable allocations.
        let frame_bytes = std::mem::size_of::<WrapCall>()
            + crate::native::frame::SessionFrame::<'_, WrapCall>::allocation_bytes()
            - if authenticated {
                std::mem::size_of::<super::super::authenticated::GcmBuffers>()
            } else {
                0
            };
        let diagnostic_bytes = crate::error::CompletionStorage::allocation_bytes();
        let overhead_bytes = std::mem::size_of::<WrappedKey>() + diagnostic_bytes;
        let mut required = TransportStorage::wrap_allocation_bytes(&parameters)?
            .checked_add(frame_bytes)
            .and_then(|bytes| bytes.checked_add(overhead_bytes))
            .and_then(|bytes| bytes.checked_add(capacity))
            .ok_or(Error::Rejected(crate::RejectionReason::KeyTransport(
                crate::KeyTransportRejection::WrappingStorageSize,
            )))?;
        let stamp = self.snapshot.authentication_stamp();
        let progress = crate::session::AdmissionProgress::default();
        let ((prepared, overhead, diagnostic), s) = self.prepare_with_roles_prepaid_at_epoch(
            [
                (
                    Some(kek.inner.managed()),
                    crate::session::activity::AccessMode::Read,
                ),
                (Some(target), crate::session::activity::AccessMode::Read),
            ],
            false,
            stamp,
            &progress,
            |overhead| loop {
                let admitted = required.checked_add(overhead).ok_or(Error::Rejected(
                    crate::RejectionReason::KeyTransport(
                        crate::KeyTransportRejection::WrappingStorageSize,
                    ),
                ))?;
                let mut prepaid = crate::advanced::reserve_preparation_at_epoch(
                    self, admitted, &progress, stamp,
                )?;
                let inputs = TransportStorage::for_wrap(&parameters)?;
                let output = crate::symmetric::memory::UnboundBuffer::allocate(capacity)?;
                let actual = inputs
                    .allocated_bytes()?
                    .checked_add(frame_bytes)
                    .and_then(|bytes| bytes.checked_add(overhead_bytes))
                    .and_then(|bytes| bytes.checked_add(output.allocated()))
                    .and_then(|bytes| bytes.checked_add(overhead))
                    .ok_or(Error::Rejected(crate::RejectionReason::KeyTransport(
                        crate::KeyTransportRejection::WrappingStorageSize,
                    )))?;
                if actual > admitted {
                    drop(output);
                    drop(inputs);
                    drop(prepaid);
                    required = actual.checked_sub(overhead).ok_or(Error::Rejected(
                        crate::RejectionReason::KeyTransport(
                            crate::KeyTransportRejection::WrappingStorageSize,
                        ),
                    ))?;
                    continue;
                }
                prepaid.release(admitted - actual);
                let prepared = WrapCall {
                    inputs: inputs.bind(&mut prepaid)?,
                    mechanism: mechanism(profile),
                    bytes: output.bind(&mut prepaid)?,
                    length: bounds::ck_length(capacity)?,
                    _credit: prepaid.split(frame_bytes)?,
                };
                let diagnostic = crate::error::PreparedCompletionCell::prepare(&mut prepaid)?;
                return Ok((
                    (
                        prepared,
                        prepaid.split(overhead_bytes - diagnostic_bytes)?,
                        diagnostic,
                    ),
                    prepaid,
                ));
            },
        )?;
        let h = self.entry(&s)?.handle;
        let mut frame = crate::native::frame::NativeFrame::session(s.clone(), prepared)?;
        let result = (|| {
            let target_handle = self.managed_handle(&s, target)?;
            let key_handle = kek.inner.native_handle(&s, self)?;
            bound(&s, self, target, target_handle)?;
            let function = if authenticated {
                "C_WrapKeyAuthenticated"
            } else {
                "C_WrapKey"
            };
            let native_call = resolved::Wrap::resolve(&s.native, frame.data.inputs.aad())?;
            let phases: &[WrapPhase] = if authenticated {
                &[WrapPhase::Output]
            } else {
                &[WrapPhase::Size, WrapPhase::Output]
            };
            for phase in phases {
                let query = matches!(phase, WrapPhase::Size);
                let (returned, body) = frame.session_parts();
                let data = &mut *body.data;
                // Capture by-value arguments before exposing nested parameters.
                data.mechanism = data.inputs.mechanism(profile);
                let pointer = data.mechanism.pParameter;
                if query {
                    data.length = 0;
                }
                self.entry(&s)?;
                s.native.record(function)?;
                returned.arm();
                // SAFETY: stable complete frame, exact selected ABI and retained
                // key activities; only the standard sizing phase uses NULL output.
                let rv = returned.observe(
                    unsafe {
                        match native_call {
                            resolved::Wrap::Authenticated {
                                native,
                                aad,
                                aad_len,
                            } => native(
                                h,
                                &mut data.mechanism,
                                key_handle,
                                target_handle,
                                aad,
                                aad_len,
                                data.bytes.as_mut().as_mut_ptr(),
                                &mut data.length,
                            ),
                            resolved::Wrap::Standard(native) => native(
                                h,
                                &mut data.mechanism,
                                key_handle,
                                target_handle,
                                if query {
                                    std::ptr::null_mut()
                                } else {
                                    data.bytes.as_mut().as_mut_ptr()
                                },
                                &mut data.length,
                            ),
                        }
                    },
                    &s.native,
                );
                let inspection = self.inspect_native_inputs(&s, function, rv, || {
                    data.inputs
                        .unchanged_wrap(&data.mechanism, pointer, &parameters)
                });
                let completed = inspection.memory_returned();
                let valid = !inspection.violated();
                let overflow = !query && rv == CKR_OK && data.length as u128 > capacity as u128;
                if !valid || overflow {
                    returned.quarantine(&s.native);
                } else if completed {
                    returned.terminated();
                } else {
                    returned.recoverable();
                    self.poison(&s);
                }

                // On an uncertain return even the length slot may still be in
                // use; the error path has no reason to inspect it.
                let length = if matches!(rv, CKR_OK | CKR_BUFFER_TOO_SMALL) {
                    data.length
                } else {
                    0
                };
                if !valid || overflow {
                    let cause =
                        Error::Rejected(crate::RejectionReason::KeyTransport(if overflow {
                            crate::KeyTransportRejection::WrappedOutputExceedsCapacity
                        } else {
                            crate::KeyTransportRejection::WrappingParametersChanged
                        }));
                    return Err(if rv == CKR_BUFFER_TOO_SMALL {
                        diagnostic.cell().output_failure(
                            crate::NativeOutputSize {
                                function,
                                code: rv as u64,
                                reported: length as u64,
                                limit: if query { 0 } else { capacity },
                            },
                            cause,
                        )
                    } else {
                        diagnostic.cell().boundary_failure(function, rv, cause)
                    });
                }
                self.check_wrap_return(rv, function, length, if query { 0 } else { capacity })?;
                if query {
                    data.length = wrap_output_capacity(length, capacity)?;
                }
            }
            let mut completed = frame.into_inner()?.data.into_inner();
            let n = bounds::final_length(completed.length, capacity)?;
            // Preserve the module's opaque output after validating its buffer bounds.
            self.entry(&s)?;
            bound(&s, self, target, target_handle)?;
            kek.inner.native_handle(&s, self)?;
            completed.bytes.set_length(n)?;

            let (oaep, authenticated) = match completed.inputs {
                TransportInputs::Standard => (None, None),
                TransportInputs::Oaep { buffers, .. } => (Some(buffers), None),
                TransportInputs::AuthenticatedGcm { buffers, .. } => (None, Some(buffers)),
            };
            Ok(WrappedKey {
                bytes: completed.bytes,
                profile,
                authenticated,
                oaep,
                _metadata: overhead,
            })
        })();
        self.metadata_result(&s, Some(stamp), result)
    }
}
