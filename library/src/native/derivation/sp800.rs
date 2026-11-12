// SPDX-License-Identifier: Apache-2.0
//! Owned SP800-108 descriptors, ordered segments and additional output slots.

use super::*;
use crate::{Sp800Data, Sp800Mode, Sp800Request};

mod preparation;
pub(crate) use preparation::Sp800Storage;

// Inline template owners are charged by each arena. This credit covers only
// excess Vec capacity and must follow the vector through partial construction.
pub(crate) struct TemplateArray {
    pub(crate) values: Vec<InputTemplate>,
    pub(crate) credit: Credit,
}

pub(crate) fn size<T>(count: usize) -> Result<usize> {
    count.checked_mul(size_of::<T>()).ok_or(Error::Rejected(
        crate::RejectionReason::NativeDerivation(
            crate::NativeDerivationRejection::Sp800ArrayStorageOverflow,
        ),
    ))
}
fn sum(parts: &[usize]) -> Result<usize> {
    parts.iter().try_fold(0usize, |n, v| {
        n.checked_add(*v)
            .ok_or(Error::Rejected(crate::RejectionReason::NativeDerivation(
                crate::NativeDerivationRejection::Sp800StorageOverflow,
            )))
    })
}

enum Segment {
    Iteration,
    Counter {
        raw: CK_SP800_108_COUNTER_FORMAT,
        width: CK_ULONG,
        little: CK_BBOOL,
        kind: CK_ULONG,
    },
    Length {
        raw: CK_SP800_108_DKM_LENGTH_FORMAT,
        method: CK_ULONG,
        width: CK_ULONG,
        little: CK_BBOOL,
    },
    Bytes(InputBytes),
    Key {
        raw: CK_OBJECT_HANDLE,
        expected: CK_OBJECT_HANDLE,
    },
}
impl Segment {
    fn prepare<'a>(input: &Sp800Data<'a>) -> Result<preparation::PreparedSegment<'a>> {
        Ok(preparation::PreparedSegment::Ready(match input {
            Sp800Data::Iteration => Self::Iteration,
            Sp800Data::CounterIteration(format) | Sp800Data::Counter(format) => {
                let width = native_ulong(format.width_bits)?;
                let little = CK_BBOOL::from(format.little_endian);
                let kind = if matches!(input, Sp800Data::CounterIteration(_)) {
                    CK_SP800_108_ITERATION_VARIABLE
                } else {
                    CK_SP800_108_COUNTER
                };
                Self::Counter {
                    raw: CK_SP800_108_COUNTER_FORMAT {
                        bLittleEndian: little,
                        ulWidthInBits: width,
                    },
                    width,
                    little,
                    kind,
                }
            }
            Sp800Data::Length(format) => {
                let method = native_ulong(format.method)?;
                let width = native_ulong(format.width_bits)?;
                let little = CK_BBOOL::from(format.little_endian);
                Self::Length {
                    raw: CK_SP800_108_DKM_LENGTH_FORMAT {
                        dkmLengthMethod: method,
                        bLittleEndian: little,
                        ulWidthInBits: width,
                    },
                    method,
                    width,
                    little,
                }
            }
            Sp800Data::Bytes(bytes) => {
                return Ok(preparation::PreparedSegment::Bytes {
                    input: bytes,
                    storage: InputBytesStorage::allocate(bytes.len())?,
                })
            }
            Sp800Data::Key(key) => Self::Key {
                raw: key.identity.handle,
                expected: key.identity.handle,
            },
        }))
    }
    fn projection(&mut self) -> CK_PRF_DATA_PARAM {
        let (r#type, value_pointer, value_length) = match self {
            Self::Iteration => (CK_SP800_108_ITERATION_VARIABLE, std::ptr::null_mut(), 0),
            Self::Counter { raw, kind, .. } => (
                *kind,
                (raw as *mut CK_SP800_108_COUNTER_FORMAT).cast(),
                size_of::<CK_SP800_108_COUNTER_FORMAT>() as CK_ULONG,
            ),
            Self::Length { raw, .. } => (
                CK_SP800_108_DKM_LENGTH,
                (raw as *mut CK_SP800_108_DKM_LENGTH_FORMAT).cast(),
                size_of::<CK_SP800_108_DKM_LENGTH_FORMAT>() as CK_ULONG,
            ),
            Self::Bytes(bytes) => (
                CK_SP800_108_BYTE_ARRAY,
                bytes.pointer().cast(),
                bytes.length(),
            ),
            Self::Key { raw, .. } => (
                CK_SP800_108_KEY_HANDLE,
                (raw as *mut CK_OBJECT_HANDLE).cast(),
                size_of::<CK_OBJECT_HANDLE>() as CK_ULONG,
            ),
        };
        CK_PRF_DATA_PARAM {
            r#type,
            pValue: value_pointer,
            ulValueLen: value_length,
        }
    }
    fn unchanged(&self, descriptor: &CK_PRF_DATA_PARAM) -> bool {
        let (kind, pointer, length, value) = match self {
            Self::Iteration => (
                CK_SP800_108_ITERATION_VARIABLE,
                std::ptr::null_mut(),
                0,
                true,
            ),
            Self::Counter {
                raw,
                width,
                little,
                kind,
            } => (
                *kind,
                (raw as *const CK_SP800_108_COUNTER_FORMAT)
                    .cast_mut()
                    .cast(),
                size_of::<CK_SP800_108_COUNTER_FORMAT>() as CK_ULONG,
                raw.bLittleEndian == *little && raw.ulWidthInBits == *width,
            ),
            Self::Length {
                raw,
                method,
                width,
                little,
            } => (
                CK_SP800_108_DKM_LENGTH,
                (raw as *const CK_SP800_108_DKM_LENGTH_FORMAT)
                    .cast_mut()
                    .cast(),
                size_of::<CK_SP800_108_DKM_LENGTH_FORMAT>() as CK_ULONG,
                raw.dkmLengthMethod == *method
                    && raw.bLittleEndian == *little
                    && raw.ulWidthInBits == *width,
            ),
            Self::Bytes(bytes) => (
                CK_SP800_108_BYTE_ARRAY,
                bytes.expected_pointer().cast(),
                bytes.length(),
                bytes.unchanged(),
            ),
            Self::Key { raw, expected } => (
                CK_SP800_108_KEY_HANDLE,
                (raw as *const CK_OBJECT_HANDLE).cast_mut().cast(),
                size_of::<CK_OBJECT_HANDLE>() as CK_ULONG,
                raw == expected,
            ),
        };
        descriptor.r#type == kind
            && descriptor.pValue == pointer
            && descriptor.ulValueLen == length
            && value
    }
}
enum Raw {
    Ordinary(CK_SP800_108_KDF_PARAMS),
    Feedback(CK_SP800_108_FEEDBACK_KDF_PARAMS),
}
pub(crate) struct Sp800Frame {
    mechanism: CK_MECHANISM,
    expected_kind: CK_MECHANISM_TYPE,
    raw: Raw,
    prf: CK_MECHANISM_TYPE,
    iv: Option<InputBytes>,
    segments: Vec<Segment>,
    descriptors: Vec<CK_PRF_DATA_PARAM>,
    templates: Vec<InputTemplate>,
    additional: Vec<CK_DERIVED_KEY>,
    handles: Vec<CK_OBJECT_HANDLE>,
    _credit: Credit,
    _template_array_credit: Credit,
}
// SAFETY: the pinned frame and its fixed-capacity arrays own every descriptor,
// format, IV, copied attribute and output slot. SessionAccess retains all source
// activities and the creation reservation through uncertain native completion.
unsafe impl Send for Sp800Frame {}
impl Sp800Frame {
    pub(crate) fn output_handles(&self) -> &[CK_OBJECT_HANDLE] {
        &self.handles
    }

    pub(crate) fn allocation_bytes(input: &Sp800Request<'_>, outputs: usize) -> Result<usize> {
        let extra = outputs.checked_sub(1).ok_or(Error::Rejected(
            crate::RejectionReason::DerivedObjectCreation(
                crate::DerivedObjectCreationRejection::Sp800PrimaryOutputRequired,
            ),
        ))?;
        bounds::ck_length(outputs)?;
        bounds::ck_length(input.data.len())?;
        native_ulong(input.prf)?;
        let mut payload = 0usize;
        for segment in input.data {
            match segment {
                Sp800Data::CounterIteration(v) | Sp800Data::Counter(v) => {
                    native_ulong(v.width_bits)?;
                }
                Sp800Data::Length(v) => {
                    native_ulong(v.width_bits)?;
                    native_ulong(v.method)?;
                }
                Sp800Data::Bytes(v) => {
                    bounds::ck_length(v.len())?;
                    payload = sum(&[payload, size::<u8>(v.len())?, v.len()])?;
                }
                _ => {}
            }
        }
        if let Sp800Mode::Feedback { iv: Some(iv) } = input.mode {
            bounds::ck_length(iv.len())?;
            payload = sum(&[payload, iv.len(), iv.len()])?;
        }
        // InputTemplate includes its inline size in its own measured credit.
        sum(&[
            size_of::<Self>(),
            crate::native::frame::SessionFrame::<'_, Self>::allocation_bytes(),
            size::<Segment>(input.data.len())?,
            size::<preparation::PreparedSegment<'_>>(input.data.len())?,
            size::<CK_PRF_DATA_PARAM>(input.data.len())?,
            size::<CK_DERIVED_KEY>(extra)?,
            size::<CK_OBJECT_HANDLE>(outputs)?,
            payload,
        ])
    }

    fn from_storage(
        input: &Sp800Request<'_>,
        templates: TemplateArray,
        prepaid: &mut Credit,
        mut storage: Sp800Storage<'_>,
    ) -> Result<Self> {
        if templates.values.len() != storage.handles.len() {
            return Err(Error::Rejected(crate::RejectionReason::NativeDerivation(
                crate::NativeDerivationRejection::Sp800TemplateCountChanged,
            )));
        }
        let actual = storage.allocated_bytes()?;
        let metadata = storage.metadata_bytes()?;
        let remaining = storage.credit.insert(prepaid.split(actual)?);
        let prf = native_ulong(input.prf)?;
        let credit = remaining.split(metadata)?;
        let mut segments = std::mem::take(&mut storage.segments);
        let descriptors = std::mem::take(&mut storage.descriptors);
        let additional = std::mem::take(&mut storage.additional);
        let handles = std::mem::take(&mut storage.handles);
        // All final arrays leave storage together before a fallible binding.
        // Their locals were declared after credit and therefore drop first.
        for segment in storage.prepared.drain(..) {
            segments.push(segment.bind(remaining)?);
        }
        let iv = match (input.mode, storage.iv.take()) {
            (Sp800Mode::Feedback { iv: Some(input) }, Some(storage)) => {
                Some(storage.bind(input, remaining)?)
            }
            (
                Sp800Mode::Feedback { iv: None } | Sp800Mode::Counter | Sp800Mode::DoublePipeline,
                None,
            ) => None,
            _ => {
                return Err(Error::Rejected(crate::RejectionReason::NativeDerivation(
                    crate::NativeDerivationRejection::Sp800IvStorageChanged,
                )))
            }
        };
        let (expected_kind, raw, iv) = match input.mode {
            Sp800Mode::Counter | Sp800Mode::DoublePipeline => (
                if matches!(input.mode, Sp800Mode::Counter) {
                    CKM_SP800_108_COUNTER_KDF
                } else {
                    CKM_SP800_108_DOUBLE_PIPELINE_KDF
                },
                Raw::Ordinary(CK_SP800_108_KDF_PARAMS {
                    prfType: prf,
                    ulNumberOfDataParams: input.data.len() as CK_ULONG,
                    pDataParams: std::ptr::null_mut(),
                    ulAdditionalDerivedKeys: 0,
                    pAdditionalDerivedKeys: std::ptr::null_mut(),
                }),
                None,
            ),
            Sp800Mode::Feedback { .. } => {
                let mut iv = iv;
                (
                    CKM_SP800_108_FEEDBACK_KDF,
                    Raw::Feedback(CK_SP800_108_FEEDBACK_KDF_PARAMS {
                        prfType: prf,
                        ulNumberOfDataParams: input.data.len() as CK_ULONG,
                        pDataParams: std::ptr::null_mut(),
                        ulIVLen: optional_length(&iv),
                        pIV: optional_pointer(&mut iv),
                        ulAdditionalDerivedKeys: 0,
                        pAdditionalDerivedKeys: std::ptr::null_mut(),
                    }),
                    iv,
                )
            }
        };
        Ok(Self {
            mechanism: CK_MECHANISM {
                mechanism: expected_kind,
                pParameter: std::ptr::null_mut(),
                ulParameterLen: 0,
            },
            expected_kind,
            raw,
            prf,
            iv,
            segments,
            descriptors,
            templates: templates.values,
            additional,
            handles,
            _credit: credit,
            _template_array_credit: templates.credit,
        })
    }
    fn bind(&mut self) -> Result<*mut CK_OBJECT_HANDLE> {
        if self.handles.is_empty() || self.handles.len() != self.templates.len() {
            return Err(Error::Rejected(crate::RejectionReason::NativeDerivation(
                crate::NativeDerivationRejection::Sp800TemplateCountChanged,
            )));
        }
        // All arrays have their final allocation. Every native output pointer
        // derives from this one base; do not borrow the handle elements again
        // until the protocol establishes return of their memory.
        let handles = self.handles.as_mut_ptr();
        for segment in &mut self.segments {
            self.descriptors.push(segment.projection());
        }
        for index in 1..self.templates.len() {
            self.additional.push(CK_DERIVED_KEY {
                pTemplate: self.templates[index].as_mut_ptr(),
                ulAttributeCount: self.templates[index].count(),
                // SAFETY: index is below templates.len() == handles.len();
                // the initialized handle allocation cannot move during this loan.
                phKey: unsafe { handles.add(index) },
            });
        }
        let params = if self.descriptors.is_empty() {
            std::ptr::null_mut()
        } else {
            self.descriptors.as_mut_ptr()
        };
        let extra = if self.additional.is_empty() {
            std::ptr::null_mut()
        } else {
            self.additional.as_mut_ptr()
        };
        let count = bounds::ck_length(self.additional.len())?;
        let (pointer, length) = match &mut self.raw {
            Raw::Ordinary(raw) => {
                raw.pDataParams = params;
                raw.pAdditionalDerivedKeys = extra;
                raw.ulAdditionalDerivedKeys = count;
                (
                    (raw as *mut CK_SP800_108_KDF_PARAMS).cast(),
                    size_of::<CK_SP800_108_KDF_PARAMS>() as CK_ULONG,
                )
            }
            Raw::Feedback(raw) => {
                raw.pDataParams = params;
                raw.pAdditionalDerivedKeys = extra;
                raw.ulAdditionalDerivedKeys = count;
                (
                    (raw as *mut CK_SP800_108_FEEDBACK_KDF_PARAMS).cast(),
                    size_of::<CK_SP800_108_FEEDBACK_KDF_PARAMS>() as CK_ULONG,
                )
            }
        };
        self.mechanism.pParameter = pointer;
        self.mechanism.ulParameterLen = length;
        Ok(handles)
    }
    fn unchanged(&mut self) -> bool {
        let params = if self.descriptors.is_empty() {
            std::ptr::null_mut()
        } else {
            self.descriptors.as_mut_ptr()
        };
        let extra = if self.additional.is_empty() {
            std::ptr::null_mut()
        } else {
            self.additional.as_mut_ptr()
        };
        let count = self.additional.len() as CK_ULONG;
        let (pointer, length, raw_ok) = match &self.raw {
            Raw::Ordinary(raw) => (
                (raw as *const CK_SP800_108_KDF_PARAMS).cast_mut().cast(),
                size_of::<CK_SP800_108_KDF_PARAMS>() as CK_ULONG,
                raw.prfType == self.prf
                    && raw.pDataParams == params
                    && raw.ulNumberOfDataParams == self.descriptors.len() as CK_ULONG
                    && raw.pAdditionalDerivedKeys == extra
                    && raw.ulAdditionalDerivedKeys == count,
            ),
            Raw::Feedback(raw) => (
                (raw as *const CK_SP800_108_FEEDBACK_KDF_PARAMS)
                    .cast_mut()
                    .cast(),
                size_of::<CK_SP800_108_FEEDBACK_KDF_PARAMS>() as CK_ULONG,
                raw.prfType == self.prf
                    && raw.pDataParams == params
                    && raw.ulNumberOfDataParams == self.descriptors.len() as CK_ULONG
                    && raw.pAdditionalDerivedKeys == extra
                    && raw.ulAdditionalDerivedKeys == count
                    && raw.pIV == optional_expected_pointer(&self.iv)
                    && raw.ulIVLen == optional_length(&self.iv),
            ),
        };
        let inputs_ok = self
            .segments
            .iter()
            .zip(&self.descriptors)
            .all(|(s, d)| s.unchanged(d));
        let templates_ok = self.templates.iter_mut().all(InputTemplate::unchanged);
        let additional_ok = self.additional.iter().enumerate().all(|(i, d)| {
            d.pTemplate == self.templates[i + 1].as_mut_ptr()
                && d.ulAttributeCount == self.templates[i + 1].count()
                && d.phKey == (&self.handles[i + 1] as *const CK_OBJECT_HANDLE).cast_mut()
        });
        self.mechanism.mechanism == self.expected_kind
            && self.mechanism.pParameter == pointer
            && self.mechanism.ulParameterLen == length
            && raw_ok
            && inputs_ok
            && templates_ok
            && additional_ok
            && optional_unchanged(&self.iv)
    }
    pub(crate) fn execute_resident(
        self,
        session: &Session,
        access: &SessionAccess<'_>,
        diagnostic: crate::error::CompletionStorage,
        mut creation: crate::managed::PreparedCreation,
        base: CK_OBJECT_HANDLE,
        sources: Vec<(CK_OBJECT_HANDLE, crate::managed::ResourceIdentity)>,
        cleanup: &mut crate::error::CleanupStorage,
    ) -> Result<Completed> {
        self.execute_prepared(
            session,
            access,
            diagnostic,
            || creation.begin(),
            base,
            sources,
            cleanup,
        )
    }
    fn execute_prepared(
        self,
        session: &Session,
        access: &SessionAccess<'_>,
        diagnostic: crate::error::CompletionStorage,
        begin: impl FnOnce() -> Result<crate::managed::CreationTicket>,
        base: CK_OBJECT_HANDLE,
        sources: Vec<(CK_OBJECT_HANDLE, crate::managed::ResourceIdentity)>,
        cleanup: &mut crate::error::CleanupStorage,
    ) -> Result<Completed> {
        let call = MutationCall::Derive;
        let native = access.native.table.C_DeriveKey.ok_or(Error::Rejected(
            crate::RejectionReason::NativeDerivation(
                crate::NativeDerivationRejection::CDeriveKeyUnavailable,
            ),
        ))?;
        let diagnostic = diagnostic.bind(call.function());
        let self_output_count = self.handles.len();
        let mut frame = NativeFrame::session(access.clone(), self)?;
        let creation = begin()?.prepare_group(access, self_output_count)?;
        let (returned, body) = frame.session_parts();
        let state = &body.access;
        let data = &mut *body.data;
        let primary = data.bind()?;
        creation.prepare_dispatch(state, || {
            session.entry(state)?;
            state.native.record(call.function())
        })?;
        returned.arm();
        // SAFETY: all pointers address the stable owned frame and fixed-capacity
        // arrays; the access guard retains source keys and output reservations.
        let rv = returned.observe(
            unsafe {
                native(
                    session.entry.handle,
                    &mut data.mechanism,
                    base,
                    data.templates[0].as_mut_ptr(),
                    data.templates[0].count(),
                    primary,
                )
            },
            &state.native,
        );
        let inspection =
            session.inspect_native_inputs(state, call.function(), rv, || data.unchanged());
        let known = inspection.memory_returned();
        let unchanged = !inspection.violated();
        if !unchanged {
            returned.quarantine(&state.native);
        } else if known {
            returned.terminated();
        } else {
            returned.recoverable();
            session.poison(state);
        }
        let result = inspection.check(!call.definite_object_refusal(rv));
        if result.is_err()
            && inspection.no_objects(crate::native_return::protocol::CreationContract::Function(
                call,
            ))
        {
            creation.refused(state, call, rv);
        }
        if !unchanged {
            return Err(cleanup.mark_remaining(diagnostic.boundary_failure(
                rv,
                Error::Rejected(crate::RejectionReason::NativeDerivation(
                    crate::NativeDerivationRejection::Sp800NativeInputMutation,
                )),
            )));
        }
        result?;
        let mut source_alias = false;
        for (source, resource) in sources {
            if data.handles.contains(&source) {
                if let Err(cause) =
                    crate::managed::revoke_returned_source(state, resource, |cause| {
                        cleanup.mark_remaining(cause)
                    })
                {
                    return diagnostic.finish(Err(cause));
                }
                source_alias = true;
            }
        }
        if source_alias {
            return diagnostic.finish(Err(cleanup.mark_remaining(Error::Rejected(
                crate::RejectionReason::NativeDerivation(
                    crate::NativeDerivationRejection::Sp800OutputAliasesSource,
                ),
            ))));
        }
        if let Err(cause) = creation
            .handles_group_prepared(state, &data.handles, |cause| cleanup.mark_remaining(cause))
        {
            return diagnostic.finish(Err(cause));
        }
        let data = match frame.into_inner() {
            Ok(frame) => frame.data.into_inner(),
            Err(cause) => return diagnostic.finish(Err(cause)),
        };
        Ok(Completed {
            data,
            creation,
            diagnostic,
        })
    }
}
pub(crate) struct Completed {
    data: Sp800Frame,
    creation: crate::managed::CreationTicket,
    diagnostic: CompletionDiagnostic,
}
impl Completed {
    pub(crate) fn into_parts(
        self,
    ) -> (
        Sp800Frame,
        crate::managed::CreationTicket,
        CompletionDiagnostic,
    ) {
        (self.data, self.creation, self.diagnostic)
    }
}
