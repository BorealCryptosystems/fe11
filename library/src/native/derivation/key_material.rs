// SPDX-License-Identifier: Apache-2.0
//! A single template and multiple native handles/IVs, without borrowed outputs.
use super::tls::{Randoms, RandomsStorage};
use super::*;
use crate::tls_key_material::MaterialIvs;
use crate::{TlsKeyMaterialMechanism as Kind, TlsKeyMaterialPart as Part, TlsKeyMaterialRequest};

enum Raw {
    Ssl {
        parameters: CK_SSL3_KEY_MAT_PARAMS,
        output: CK_SSL3_KEY_MAT_OUT,
    },
    Tls12 {
        parameters: CK_TLS12_KEY_MAT_PARAMS,
        output: CK_SSL3_KEY_MAT_OUT,
    },
    Wtls {
        parameters: CK_WTLS_KEY_MAT_PARAMS,
        output: CK_WTLS_KEY_MAT_OUT,
    },
}
struct Scalars {
    mac: CK_ULONG,
    key: CK_ULONG,
    iv: CK_ULONG,
    export: CK_BBOOL,
    hash: CK_MECHANISM_TYPE,
    sequence: CK_ULONG,
}
pub(crate) struct KeyMaterial {
    mechanism: CK_MECHANISM,
    kind: Kind,
    raw: Raw,
    scalars: Scalars,
    randoms: Randoms,
    template: InputTemplate,
    first_iv: Buffer,
    second_iv: Buffer,
    handles: [CK_OBJECT_HANDLE; 4],
    count: usize,
    missing_required: bool,
    _credit: Credit,
}
// SAFETY: the frame owns every parameter, nested output structure, template and
// IV buffer. Raw pointers are installed only in stable NativeFrame storage.
unsafe impl Send for KeyMaterial {}
fn iv_bytes(request: &TlsKeyMaterialRequest<'_>) -> Result<usize> {
    native_ulong(request.iv_bits)?;
    if matches!(request.mechanism, Kind::Tls12Safe { .. }) {
        return Ok(0);
    }
    let n = request.iv_bits / 8 + u64::from(request.iv_bits % 8 != 0);
    let n = usize::try_from(n).map_err(|_| {
        Error::Rejected(crate::RejectionReason::NativeDerivation(
            crate::NativeDerivationRejection::KeyMaterialIvWidth,
        ))
    })?;
    bounds::ck_length(n)?;
    Ok(n)
}
fn pointer(buffer: &mut Buffer) -> CK_BYTE_PTR {
    if buffer.as_slice().is_empty() {
        std::ptr::null_mut()
    } else {
        buffer.as_mut().as_mut_ptr()
    }
}
fn expected_pointer(buffer: &Buffer) -> CK_BYTE_PTR {
    if buffer.as_slice().is_empty() {
        std::ptr::null_mut()
    } else {
        buffer.as_slice().as_ptr().cast_mut()
    }
}
pub(crate) struct KeyMaterialStorage {
    randoms: RandomsStorage,
    first_iv: crate::symmetric::memory::UnboundBuffer,
    second_iv: crate::symmetric::memory::UnboundBuffer,
}
impl KeyMaterialStorage {
    pub(crate) fn allocate(request: &TlsKeyMaterialRequest<'_>) -> Result<Self> {
        KeyMaterial::allocation_bytes(request)?;
        Ok(Self {
            randoms: RandomsStorage::allocate(request.randoms)?,
            first_iv: crate::symmetric::memory::UnboundBuffer::allocate(iv_bytes(request)?)?,
            second_iv: crate::symmetric::memory::UnboundBuffer::allocate(
                if request.mechanism.count() == 4 {
                    iv_bytes(request)?
                } else {
                    0
                },
            )?,
        })
    }
    pub(crate) fn allocated_bytes(&self) -> Result<usize> {
        self.randoms
            .allocated_bytes()?
            .checked_add(self.first_iv.allocated())
            .and_then(|n| n.checked_add(self.second_iv.allocated()))
            .and_then(|n| n.checked_add(KeyMaterial::frame_bytes()))
            .ok_or(Error::Rejected(crate::RejectionReason::NativeDerivation(
                crate::NativeDerivationRejection::KeyMaterialStorage,
            )))
    }
    pub(crate) fn bind(
        self,
        request: &TlsKeyMaterialRequest<'_>,
        template: InputTemplate,
        prepaid: &mut Credit,
    ) -> Result<KeyMaterial> {
        KeyMaterial::from_storage(request, template, prepaid, self)
    }
}
impl KeyMaterial {
    /// Retain credit for CallData and SessionFrame outside the owned template.
    fn frame_bytes() -> usize {
        size_of::<Self>() + crate::native::frame::SessionFrame::<'_, Self>::allocation_bytes()
            - size_of::<InputTemplate>()
    }

    pub(crate) fn tls_ivs(&self) -> Option<(&[u8], &[u8])> {
        (self.kind.count() == 4).then(|| (self.first_iv.as_slice(), self.second_iv.as_slice()))
    }
    pub(crate) fn wtls_iv(&self) -> Option<&[u8]> {
        (self.kind.count() != 4).then(|| self.first_iv.as_slice())
    }

    pub(crate) fn check_output_presence(&self) -> Result<()> {
        if self.missing_required {
            Err(Error::Rejected(crate::RejectionReason::NativeDerivation(
                crate::NativeDerivationRejection::MissingKeyMaterialOutput,
            )))
        } else {
            Ok(())
        }
    }
    pub(crate) fn take_output_ivs(&mut self) -> MaterialIvs {
        if self.kind.count() == 4 {
            MaterialIvs::Tls {
                client: self.first_iv.take(),
                server: self.second_iv.take(),
            }
        } else {
            MaterialIvs::Wtls(self.first_iv.take())
        }
    }

    pub(crate) fn allocation_bytes(request: &TlsKeyMaterialRequest<'_>) -> Result<usize> {
        native_ulong(request.mac_bits)?;
        native_ulong(request.key_bits)?;
        match request.mechanism {
            Kind::Tls12 { hash } | Kind::Tls12Safe { hash } => {
                native_ulong(hash)?;
            }
            Kind::WtlsServer { digest, sequence } | Kind::WtlsClient { digest, sequence } => {
                native_ulong(digest)?;
                native_ulong(sequence)?;
            }
            _ => {}
        }
        let mut bytes = Self::frame_bytes();
        for len in [request.randoms.client.len(), request.randoms.server.len()] {
            bounds::ck_length(len)?;
            bytes = len
                .checked_mul(2)
                .and_then(|n| bytes.checked_add(n))
                .ok_or(Error::Rejected(crate::RejectionReason::NativeDerivation(
                    crate::NativeDerivationRejection::KeyMaterialRandomStorage,
                )))?;
        }
        let ivs = iv_bytes(request)?
            .checked_mul(if request.mechanism.count() == 4 { 2 } else { 1 })
            .ok_or(Error::Rejected(crate::RejectionReason::NativeDerivation(
                crate::NativeDerivationRejection::KeyMaterialIvStorage,
            )))?;
        bytes
            .checked_add(ivs)
            .ok_or(Error::Rejected(crate::RejectionReason::NativeDerivation(
                crate::NativeDerivationRejection::KeyMaterialStorage,
            )))
    }

    fn from_storage(
        request: &TlsKeyMaterialRequest<'_>,
        template: InputTemplate,
        prepaid: &mut Credit,
        storage: KeyMaterialStorage,
    ) -> Result<Self> {
        let _credit = prepaid.split(Self::frame_bytes())?;
        let randoms = storage.randoms.bind(request.randoms, prepaid)?;
        let first_iv = storage.first_iv.bind(prepaid)?;
        let second_iv = storage.second_iv.bind(prepaid)?;
        let (hash, sequence) = match request.mechanism {
            Kind::Tls12 { hash } | Kind::Tls12Safe { hash } => (native_ulong(hash)?, 0),
            Kind::WtlsServer { digest, sequence } | Kind::WtlsClient { digest, sequence } => {
                (native_ulong(digest)?, native_ulong(sequence)?)
            }
            _ => (0, 0),
        };
        let scalars = Scalars {
            mac: native_ulong(request.mac_bits)?,
            key: native_ulong(request.key_bits)?,
            iv: native_ulong(request.iv_bits)?,
            export: CK_BBOOL::from(request.export),
            hash,
            sequence,
        };
        // SAFETY: these C structures contain only integer fields and nullable
        // raw pointers. Zero is a valid unbound representation; bind replaces
        // every input before dispatch, including the invalid-handle slots.
        let raw = unsafe {
            match request.mechanism {
                Kind::Ssl3 | Kind::Tls => Raw::Ssl {
                    parameters: std::mem::zeroed(),
                    output: std::mem::zeroed(),
                },
                Kind::Tls12 { .. } | Kind::Tls12Safe { .. } => Raw::Tls12 {
                    parameters: std::mem::zeroed(),
                    output: std::mem::zeroed(),
                },
                Kind::WtlsServer { .. } | Kind::WtlsClient { .. } => Raw::Wtls {
                    parameters: std::mem::zeroed(),
                    output: std::mem::zeroed(),
                },
            }
        };
        Ok(Self {
            mechanism: CK_MECHANISM {
                mechanism: request.mechanism.native(),
                pParameter: std::ptr::null_mut(),
                ulParameterLen: 0,
            },
            kind: request.mechanism,
            raw,
            scalars,
            randoms,
            template,
            first_iv,
            second_iv,
            handles: [CK_INVALID_HANDLE; 4],
            count: 0,
            missing_required: false,
            _credit,
        })
    }
    fn bind(&mut self) {
        let first = pointer(&mut self.first_iv);
        let second = pointer(&mut self.second_iv);
        let s = &self.scalars;
        let (p, len) = match &mut self.raw {
            Raw::Ssl {
                parameters: p,
                output,
            } => {
                p.ulMacSizeInBits = s.mac;
                p.ulKeySizeInBits = s.key;
                p.ulIVSizeInBits = s.iv;
                p.bIsExport = s.export;
                output.pIVClient = first;
                output.pIVServer = second;
                p.RandomInfo = self.randoms.ssl();
                p.pReturnedKeyMaterial = output as *mut CK_SSL3_KEY_MAT_OUT;
                (
                    (p as *mut CK_SSL3_KEY_MAT_PARAMS).cast(),
                    size_of::<CK_SSL3_KEY_MAT_PARAMS>() as CK_ULONG,
                )
            }
            Raw::Tls12 {
                parameters: p,
                output,
            } => {
                p.ulMacSizeInBits = s.mac;
                p.ulKeySizeInBits = s.key;
                p.ulIVSizeInBits = s.iv;
                p.bIsExport = s.export;
                p.prfHashMechanism = s.hash;
                output.pIVClient = first;
                output.pIVServer = second;
                p.RandomInfo = self.randoms.ssl();
                p.pReturnedKeyMaterial = output as *mut CK_SSL3_KEY_MAT_OUT;
                (
                    (p as *mut CK_TLS12_KEY_MAT_PARAMS).cast(),
                    size_of::<CK_TLS12_KEY_MAT_PARAMS>() as CK_ULONG,
                )
            }
            Raw::Wtls {
                parameters: p,
                output,
            } => {
                p.ulMacSizeInBits = s.mac;
                p.ulKeySizeInBits = s.key;
                p.ulIVSizeInBits = s.iv;
                p.bIsExport = s.export;
                p.DigestMechanism = s.hash;
                p.ulSequenceNumber = s.sequence;
                output.pIV = first;
                p.RandomInfo = self.randoms.wtls();
                p.pReturnedKeyMaterial = output as *mut CK_WTLS_KEY_MAT_OUT;
                (
                    (p as *mut CK_WTLS_KEY_MAT_PARAMS).cast(),
                    size_of::<CK_WTLS_KEY_MAT_PARAMS>() as CK_ULONG,
                )
            }
        };
        self.mechanism.pParameter = p;
        self.mechanism.ulParameterLen = len;
    }
    fn unchanged(&mut self) -> bool {
        let s = &self.scalars;
        let first = expected_pointer(&self.first_iv);
        let second = expected_pointer(&self.second_iv);
        let (pointer, length, fields) = match &self.raw {
            Raw::Ssl {
                parameters: p,
                output,
            } => (
                (p as *const CK_SSL3_KEY_MAT_PARAMS).cast_mut().cast(),
                size_of::<CK_SSL3_KEY_MAT_PARAMS>() as CK_ULONG,
                p.ulMacSizeInBits == s.mac
                    && p.ulKeySizeInBits == s.key
                    && p.ulIVSizeInBits == s.iv
                    && p.bIsExport == s.export
                    && p.pReturnedKeyMaterial == (output as *const CK_SSL3_KEY_MAT_OUT).cast_mut()
                    && output.pIVClient == first
                    && output.pIVServer == second
                    && self.randoms.unchanged(
                        p.RandomInfo.pClientRandom,
                        p.RandomInfo.ulClientRandomLen,
                        p.RandomInfo.pServerRandom,
                        p.RandomInfo.ulServerRandomLen,
                    ),
            ),
            Raw::Tls12 {
                parameters: p,
                output,
            } => (
                (p as *const CK_TLS12_KEY_MAT_PARAMS).cast_mut().cast(),
                size_of::<CK_TLS12_KEY_MAT_PARAMS>() as CK_ULONG,
                p.ulMacSizeInBits == s.mac
                    && p.ulKeySizeInBits == s.key
                    && p.ulIVSizeInBits == s.iv
                    && p.bIsExport == s.export
                    && p.prfHashMechanism == s.hash
                    && p.pReturnedKeyMaterial == (output as *const CK_SSL3_KEY_MAT_OUT).cast_mut()
                    && output.pIVClient == first
                    && output.pIVServer == second
                    && self.randoms.unchanged(
                        p.RandomInfo.pClientRandom,
                        p.RandomInfo.ulClientRandomLen,
                        p.RandomInfo.pServerRandom,
                        p.RandomInfo.ulServerRandomLen,
                    ),
            ),
            Raw::Wtls {
                parameters: p,
                output,
            } => (
                (p as *const CK_WTLS_KEY_MAT_PARAMS).cast_mut().cast(),
                size_of::<CK_WTLS_KEY_MAT_PARAMS>() as CK_ULONG,
                p.ulMacSizeInBits == s.mac
                    && p.ulKeySizeInBits == s.key
                    && p.ulIVSizeInBits == s.iv
                    && p.bIsExport == s.export
                    && p.DigestMechanism == s.hash
                    && p.ulSequenceNumber == s.sequence
                    && p.pReturnedKeyMaterial == (output as *const CK_WTLS_KEY_MAT_OUT).cast_mut()
                    && output.pIV == first
                    && self.randoms.unchanged(
                        p.RandomInfo.pClientRandom,
                        p.RandomInfo.ulClientRandomLen,
                        p.RandomInfo.pServerRandom,
                        p.RandomInfo.ulServerRandomLen,
                    ),
            ),
        };
        self.mechanism.mechanism == self.kind.native()
            && self.mechanism.pParameter == pointer
            && self.mechanism.ulParameterLen == length
            && fields
            && self.template.unchanged()
    }
    pub(crate) fn slots(&self) -> [CK_OBJECT_HANDLE; 4] {
        match &self.raw {
            Raw::Ssl { output, .. } | Raw::Tls12 { output, .. } => [
                output.hClientMacSecret,
                output.hServerMacSecret,
                output.hClientKey,
                output.hServerKey,
            ],
            Raw::Wtls { output, .. } => [
                output.hMacSecret,
                output.hKey,
                CK_INVALID_HANDLE,
                CK_INVALID_HANDLE,
            ],
        }
    }
    fn collect_handles(&mut self) {
        for (index, handle) in self.slots().into_iter().take(self.kind.count()).enumerate() {
            let mac = if self.kind.count() == 4 {
                index < 2
            } else {
                index == 0
            };
            if handle == CK_INVALID_HANDLE {
                self.missing_required |= if mac {
                    self.scalars.mac != 0
                } else {
                    self.scalars.key != 0
                };
            } else {
                self.handles[self.count] = handle;
                self.count += 1;
            }
        }
    }
    pub(crate) fn roles(&self) -> &'static [Part] {
        if self.kind.count() == 4 {
            &[
                Part::ClientMac,
                Part::ServerMac,
                Part::ClientKey,
                Part::ServerKey,
            ]
        } else {
            &[Part::WtlsMac, Part::WtlsKey]
        }
    }
    pub(crate) fn execute_resident(
        self,
        session: &Session,
        access: &SessionAccess<'_>,
        diagnostic: crate::error::CompletionStorage,
        mut creation: crate::managed::PreparedCreation,
        base: CK_OBJECT_HANDLE,
        aliases: RevocationTargets,
        cleanup: &mut crate::error::CleanupStorage,
    ) -> Result<Completed> {
        self.execute_prepared(
            session,
            access,
            diagnostic,
            || creation.begin(),
            base,
            aliases,
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
        aliases: RevocationTargets,
        cleanup: &mut crate::error::CleanupStorage,
    ) -> Result<Completed> {
        let call = MutationCall::Derive;
        let native = access.native.table.C_DeriveKey.ok_or(Error::Rejected(
            crate::RejectionReason::NativeDerivation(
                crate::NativeDerivationRejection::CDeriveKeyUnavailable,
            ),
        ))?;
        let diagnostic = diagnostic.bind(call.function());
        let capacity = self.kind.count();
        let mut frame = NativeFrame::session(access.clone(), self)?;
        let creation = begin()?.prepare_group(access, capacity)?;
        let (returned, body) = frame.session_parts();
        let state = &body.access;
        let data = &mut *body.data;
        data.bind();
        creation.prepare_dispatch(state, || {
            session.entry(state)?;
            state.native.record(call.function())
        })?;
        returned.arm();
        // SAFETY: the stable frame owns all nested pointers. This mechanism
        // returns handles in its parameter output structure, so phKey is NULL.
        let rv = returned.observe(
            unsafe {
                native(
                    session.entry.handle,
                    &mut data.mechanism,
                    base,
                    data.template.as_mut_ptr(),
                    data.template.count(),
                    std::ptr::null_mut(),
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
        // Apply native context effects even when this mechanism proves that
        // completed failure created no keys (SSL/TLS/WTLS key-material clauses).
        let result = inspection.check(!call.definite_object_refusal(rv));
        let result = if inspection
            .no_objects(crate::native_return::protocol::CreationContract::KeyMaterial)
        {
            creation.refused_without_objects(state);
            crate::error::check(rv, call.function(), false)
        } else {
            result
        };
        if !unchanged {
            return Err(cleanup.mark_remaining(diagnostic.boundary_failure(
                rv,
                Error::Rejected(crate::RejectionReason::NativeDerivation(
                    crate::NativeDerivationRejection::KeyMaterialNativeInputMutation,
                )),
            )));
        }
        result?;
        data.collect_handles();
        if data.handles[..data.count].contains(&base) {
            drop(aliases.arm());
            return diagnostic.finish(Err(cleanup.mark_remaining(Error::Rejected(
                crate::RejectionReason::NativeDerivation(
                    crate::NativeDerivationRejection::KeyMaterialOutputAliasesSource,
                ),
            ))));
        }
        if let Err(cause) =
            creation.handles_group_prepared(state, &data.handles[..data.count], |cause| {
                cleanup.mark_remaining(cause)
            })
        {
            return diagnostic.finish(Err(cause));
        }
        let data = match frame.into_inner() {
            Ok(v) => v.data.into_inner(),
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
    pub(crate) data: KeyMaterial,
    creation: crate::managed::CreationTicket,
    diagnostic: CompletionDiagnostic,
}
impl Completed {
    pub(crate) fn into_parts(
        self,
    ) -> (
        KeyMaterial,
        crate::managed::CreationTicket,
        CompletionDiagnostic,
    ) {
        (self.data, self.creation, self.diagnostic)
    }
}
