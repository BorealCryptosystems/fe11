// SPDX-License-Identifier: Apache-2.0
//! Owned TLS/WTLS randoms, session hashes and version output slots.
use super::*;
use crate::{NativeDerivationOutput, TlsKdfParameters, TlsMasterDerivation, TlsRandoms};

pub(super) struct Randoms {
    client: InputBytes,
    server: InputBytes,
}
pub(super) struct RandomsStorage {
    client: InputBytesStorage,
    server: InputBytesStorage,
}
impl RandomsStorage {
    pub(super) fn allocate(input: TlsRandoms<'_>) -> Result<Self> {
        Ok(Self {
            client: InputBytesStorage::allocate(input.client.len())?,
            server: InputBytesStorage::allocate(input.server.len())?,
        })
    }
    pub(super) fn allocated_bytes(&self) -> Result<usize> {
        self.client
            .allocated_bytes()?
            .checked_add(self.server.allocated_bytes()?)
            .ok_or(Error::Rejected(crate::RejectionReason::NativeDerivation(
                crate::NativeDerivationRejection::TlsParameterAccounting,
            )))
    }
    pub(super) fn bind(self, input: TlsRandoms<'_>, prepaid: &mut Credit) -> Result<Randoms> {
        Ok(Randoms {
            client: self.client.bind(input.client, prepaid)?,
            server: self.server.bind(input.server, prepaid)?,
        })
    }
}
impl Randoms {
    pub(super) fn ssl(&mut self) -> CK_SSL3_RANDOM_DATA {
        CK_SSL3_RANDOM_DATA {
            pClientRandom: self.client.pointer(),
            ulClientRandomLen: self.client.length(),
            pServerRandom: self.server.pointer(),
            ulServerRandomLen: self.server.length(),
        }
    }
    pub(super) fn wtls(&mut self) -> CK_WTLS_RANDOM_DATA {
        CK_WTLS_RANDOM_DATA {
            pClientRandom: self.client.pointer(),
            ulClientRandomLen: self.client.length(),
            pServerRandom: self.server.pointer(),
            ulServerRandomLen: self.server.length(),
        }
    }
    pub(super) fn unchanged(
        &self,
        client: CK_BYTE_PTR,
        client_len: CK_ULONG,
        server: CK_BYTE_PTR,
        server_len: CK_ULONG,
    ) -> bool {
        let inputs = self.client.unchanged() & self.server.unchanged();
        client == self.client.expected_pointer()
            && client_len == self.client.length()
            && server == self.server.expected_pointer()
            && server_len == self.server.length()
            && inputs
    }
}
pub(super) enum Master {
    Classic {
        raw: CK_SSL3_MASTER_KEY_DERIVE_PARAMS,
        randoms: Randoms,
        version: Option<CK_VERSION>,
    },
    Tls12 {
        raw: CK_TLS12_MASTER_KEY_DERIVE_PARAMS,
        randoms: Randoms,
        hash: CK_MECHANISM_TYPE,
        version: Option<CK_VERSION>,
    },
    Extended {
        raw: CK_TLS12_EXTENDED_MASTER_KEY_DERIVE_PARAMS,
        session: InputBytes,
        hash: CK_MECHANISM_TYPE,
        version: Option<CK_VERSION>,
    },
    Wtls {
        raw: CK_WTLS_MASTER_KEY_DERIVE_PARAMS,
        randoms: Randoms,
        digest: CK_MECHANISM_TYPE,
        version: Option<CK_BYTE>,
    },
}
fn payload(lengths: &[usize]) -> Result<usize> {
    lengths.iter().try_fold(0usize, |n, len| {
        bounds::ck_length(*len)?;
        len.checked_mul(2)
            .and_then(|v| n.checked_add(v))
            .ok_or(Error::Rejected(crate::RejectionReason::NativeDerivation(
                crate::NativeDerivationRejection::TlsParameterAccounting,
            )))
    })
}
fn version_pointer(version: &mut Option<CK_VERSION>) -> CK_VERSION_PTR {
    version
        .as_mut()
        .map_or(std::ptr::null_mut(), |v| v as *mut CK_VERSION)
}
fn version_expected(version: &Option<CK_VERSION>) -> CK_VERSION_PTR {
    version.as_ref().map_or(std::ptr::null_mut(), |v| {
        (v as *const CK_VERSION).cast_mut()
    })
}
fn tls_output(version: &Option<CK_VERSION>) -> NativeDerivationOutput {
    match version {
        Some(v) => NativeDerivationOutput::TlsVersion {
            major: v.major,
            minor: v.minor,
        },
        None => NativeDerivationOutput::None,
    }
}
pub(super) enum MasterStorage {
    Randoms(RandomsStorage),
    Session(InputBytesStorage),
}
impl MasterStorage {
    pub(super) fn allocate(input: &TlsMasterDerivation<'_>) -> Result<Self> {
        Master::payload_bytes(input)?;
        Ok(match input {
            TlsMasterDerivation::Ssl3 { randoms, .. }
            | TlsMasterDerivation::Tls { randoms, .. }
            | TlsMasterDerivation::Tls12 { randoms, .. }
            | TlsMasterDerivation::Wtls { randoms, .. } => {
                Self::Randoms(RandomsStorage::allocate(*randoms)?)
            }
            TlsMasterDerivation::Tls12Extended { session_hash, .. } => {
                Self::Session(InputBytesStorage::allocate(session_hash.len())?)
            }
        })
    }
    pub(super) fn allocated_bytes(&self) -> Result<usize> {
        match self {
            Self::Randoms(storage) => storage.allocated_bytes(),
            Self::Session(storage) => storage.allocated_bytes(),
        }
    }
    fn randoms(self) -> Result<RandomsStorage> {
        match self {
            Self::Randoms(storage) => Ok(storage),
            _ => Err(Error::Rejected(crate::RejectionReason::NativeDerivation(
                crate::NativeDerivationRejection::TlsMasterStorageChanged,
            ))),
        }
    }
    fn session(self) -> Result<InputBytesStorage> {
        match self {
            Self::Session(storage) => Ok(storage),
            _ => Err(Error::Rejected(crate::RejectionReason::NativeDerivation(
                crate::NativeDerivationRejection::TlsMasterStorageChanged,
            ))),
        }
    }
    pub(super) fn bind(
        self,
        input: &TlsMasterDerivation<'_>,
        credit: &mut Credit,
    ) -> Result<Master> {
        Master::from_storage(input, self, credit)
    }
}
impl Master {
    pub(super) fn payload_bytes(input: &TlsMasterDerivation<'_>) -> Result<usize> {
        match input {
            TlsMasterDerivation::Ssl3 { randoms, .. }
            | TlsMasterDerivation::Tls { randoms, .. } => {
                payload(&[randoms.client.len(), randoms.server.len()])
            }
            TlsMasterDerivation::Tls12 { randoms, hash, .. } => {
                native_ulong(*hash)?;
                payload(&[randoms.client.len(), randoms.server.len()])
            }
            TlsMasterDerivation::Tls12Extended {
                session_hash, hash, ..
            } => {
                native_ulong(*hash)?;
                payload(&[session_hash.len()])
            }
            TlsMasterDerivation::Wtls {
                randoms, digest, ..
            } => {
                native_ulong(*digest)?;
                payload(&[randoms.client.len(), randoms.server.len()])
            }
        }
    }

    fn from_storage(
        input: &TlsMasterDerivation<'_>,
        storage: MasterStorage,
        credit: &mut Credit,
    ) -> Result<Self> {
        Ok(match input {
            TlsMasterDerivation::Ssl3 { randoms, dh }
            | TlsMasterDerivation::Tls { randoms, dh } => {
                let mut randoms = storage.randoms()?.bind(*randoms, credit)?;
                Self::Classic {
                    raw: CK_SSL3_MASTER_KEY_DERIVE_PARAMS {
                        RandomInfo: randoms.ssl(),
                        pVersion: std::ptr::null_mut(),
                    },
                    randoms,
                    version: (!*dh).then_some(CK_VERSION { major: 0, minor: 0 }),
                }
            }
            TlsMasterDerivation::Tls12 { randoms, hash, dh } => {
                let hash = native_ulong(*hash)?;
                let mut randoms = storage.randoms()?.bind(*randoms, credit)?;
                Self::Tls12 {
                    raw: CK_TLS12_MASTER_KEY_DERIVE_PARAMS {
                        RandomInfo: randoms.ssl(),
                        pVersion: std::ptr::null_mut(),
                        prfHashMechanism: hash,
                    },
                    randoms,
                    hash,
                    version: (!*dh).then_some(CK_VERSION { major: 0, minor: 0 }),
                }
            }
            TlsMasterDerivation::Tls12Extended {
                session_hash,
                hash,
                dh,
            } => {
                let hash = native_ulong(*hash)?;
                let mut session = storage.session()?.bind(session_hash, credit)?;
                Self::Extended {
                    raw: CK_TLS12_EXTENDED_MASTER_KEY_DERIVE_PARAMS {
                        prfHashMechanism: hash,
                        pSessionHash: session.pointer(),
                        ulSessionHashLen: session.length(),
                        pVersion: std::ptr::null_mut(),
                    },
                    session,
                    hash,
                    version: (!*dh).then_some(CK_VERSION { major: 0, minor: 0 }),
                }
            }
            TlsMasterDerivation::Wtls {
                randoms,
                digest,
                dh_ecc,
            } => {
                let digest = native_ulong(*digest)?;
                let mut randoms = storage.randoms()?.bind(*randoms, credit)?;
                Self::Wtls {
                    raw: CK_WTLS_MASTER_KEY_DERIVE_PARAMS {
                        DigestMechanism: digest,
                        RandomInfo: randoms.wtls(),
                        pVersion: std::ptr::null_mut(),
                    },
                    randoms,
                    digest,
                    version: (!*dh_ecc).then_some(0),
                }
            }
        })
    }
    pub(super) fn projection(&mut self) -> (CK_VOID_PTR, CK_ULONG) {
        // The version slot is inline in this owner: bind only after the complete
        // derivation frame reaches stable storage, never in its constructor.
        match self {
            Self::Classic { raw, version, .. } => {
                raw.pVersion = version_pointer(version);
                (
                    (raw as *mut CK_SSL3_MASTER_KEY_DERIVE_PARAMS).cast(),
                    size_of::<CK_SSL3_MASTER_KEY_DERIVE_PARAMS>() as CK_ULONG,
                )
            }
            Self::Tls12 { raw, version, .. } => {
                raw.pVersion = version_pointer(version);
                (
                    (raw as *mut CK_TLS12_MASTER_KEY_DERIVE_PARAMS).cast(),
                    size_of::<CK_TLS12_MASTER_KEY_DERIVE_PARAMS>() as CK_ULONG,
                )
            }
            Self::Extended { raw, version, .. } => {
                raw.pVersion = version_pointer(version);
                (
                    (raw as *mut CK_TLS12_EXTENDED_MASTER_KEY_DERIVE_PARAMS).cast(),
                    size_of::<CK_TLS12_EXTENDED_MASTER_KEY_DERIVE_PARAMS>() as CK_ULONG,
                )
            }
            Self::Wtls { raw, version, .. } => {
                raw.pVersion = version
                    .as_mut()
                    .map_or(std::ptr::null_mut(), |v| v as *mut CK_BYTE);
                (
                    (raw as *mut CK_WTLS_MASTER_KEY_DERIVE_PARAMS).cast(),
                    size_of::<CK_WTLS_MASTER_KEY_DERIVE_PARAMS>() as CK_ULONG,
                )
            }
        }
    }
    pub(super) fn unchanged(&self) -> bool {
        match self {
            Self::Classic {
                raw,
                randoms,
                version,
            } => {
                raw.pVersion == version_expected(version)
                    && randoms.unchanged(
                        raw.RandomInfo.pClientRandom,
                        raw.RandomInfo.ulClientRandomLen,
                        raw.RandomInfo.pServerRandom,
                        raw.RandomInfo.ulServerRandomLen,
                    )
            }
            Self::Tls12 {
                raw,
                randoms,
                version,
                hash,
            } => {
                raw.pVersion == version_expected(version)
                    && raw.prfHashMechanism == *hash
                    && randoms.unchanged(
                        raw.RandomInfo.pClientRandom,
                        raw.RandomInfo.ulClientRandomLen,
                        raw.RandomInfo.pServerRandom,
                        raw.RandomInfo.ulServerRandomLen,
                    )
            }
            Self::Extended {
                raw,
                session,
                version,
                hash,
            } => {
                raw.pVersion == version_expected(version)
                    && raw.prfHashMechanism == *hash
                    && raw.pSessionHash == session.expected_pointer()
                    && raw.ulSessionHashLen == session.length()
                    && session.unchanged()
            }
            Self::Wtls {
                raw,
                randoms,
                version,
                digest,
            } => {
                raw.DigestMechanism == *digest
                    && raw.pVersion
                        == version
                            .as_ref()
                            .map_or(std::ptr::null_mut(), |v| (v as *const CK_BYTE).cast_mut())
                    && randoms.unchanged(
                        raw.RandomInfo.pClientRandom,
                        raw.RandomInfo.ulClientRandomLen,
                        raw.RandomInfo.pServerRandom,
                        raw.RandomInfo.ulServerRandomLen,
                    )
            }
        }
    }
    pub(super) fn output(&self) -> NativeDerivationOutput {
        match self {
            Self::Classic { version, .. }
            | Self::Tls12 { version, .. }
            | Self::Extended { version, .. } => tls_output(version),
            Self::Wtls { version, .. } => version.map_or(
                NativeDerivationOutput::None,
                NativeDerivationOutput::WtlsVersion,
            ),
        }
    }
}

pub(super) struct Kdf {
    raw: CK_TLS_KDF_PARAMS,
    prf: CK_MECHANISM_TYPE,
    label: InputBytes,
    randoms: Randoms,
    context: Option<InputBytes>,
}
pub(super) struct KdfStorage {
    label: InputBytesStorage,
    randoms: RandomsStorage,
    context: Option<InputBytesStorage>,
}
impl KdfStorage {
    pub(super) fn allocate(input: &TlsKdfParameters<'_>) -> Result<Self> {
        Kdf::payload_bytes(input)?;
        Ok(Self {
            label: InputBytesStorage::allocate(input.label.len())?,
            randoms: RandomsStorage::allocate(input.randoms)?,
            context: input
                .context
                .map(|v| InputBytesStorage::allocate(v.len()))
                .transpose()?,
        })
    }
    pub(super) fn allocated_bytes(&self) -> Result<usize> {
        let context = self
            .context
            .as_ref()
            .map(InputBytesStorage::allocated_bytes)
            .transpose()?
            .unwrap_or(0);
        self.label
            .allocated_bytes()?
            .checked_add(self.randoms.allocated_bytes()?)
            .and_then(|n| n.checked_add(context))
            .ok_or(Error::Rejected(crate::RejectionReason::NativeDerivation(
                crate::NativeDerivationRejection::TlsParameterAccounting,
            )))
    }
    pub(super) fn bind(self, input: &TlsKdfParameters<'_>, credit: &mut Credit) -> Result<Kdf> {
        Kdf::from_storage(input, self, credit)
    }
}
impl Kdf {
    pub(super) fn payload_bytes(input: &TlsKdfParameters<'_>) -> Result<usize> {
        native_ulong(input.prf)?;
        payload(&[
            input.label.len(),
            input.randoms.client.len(),
            input.randoms.server.len(),
            input.context.map_or(0, |v| v.len()),
        ])
    }
    fn from_storage(
        input: &TlsKdfParameters<'_>,
        storage: KdfStorage,
        credit: &mut Credit,
    ) -> Result<Self> {
        let prf = native_ulong(input.prf)?;
        let mut label = storage.label.bind(input.label, credit)?;
        let mut randoms = storage.randoms.bind(input.randoms, credit)?;
        let mut context = match (storage.context, input.context) {
            (Some(storage), Some(input)) => Some(storage.bind(input, credit)?),
            (None, None) => None,
            _ => {
                return Err(Error::Rejected(crate::RejectionReason::NativeDerivation(
                    crate::NativeDerivationRejection::TlsContextStorageChanged,
                )))
            }
        };
        let raw = CK_TLS_KDF_PARAMS {
            prfMechanism: prf,
            pLabel: label.pointer(),
            ulLabelLength: label.length(),
            RandomInfo: randoms.ssl(),
            pContextData: optional_pointer(&mut context),
            ulContextDataLength: optional_length(&context),
        };
        Ok(Self {
            raw,
            prf,
            label,
            randoms,
            context,
        })
    }
    pub(super) fn projection(&mut self) -> (CK_VOID_PTR, CK_ULONG) {
        (
            (&mut self.raw as *mut CK_TLS_KDF_PARAMS).cast(),
            size_of::<CK_TLS_KDF_PARAMS>() as CK_ULONG,
        )
    }
    pub(super) fn unchanged(&self) -> bool {
        let inputs = self.label.unchanged() & optional_unchanged(&self.context);
        self.raw.prfMechanism == self.prf
            && self.raw.pLabel == self.label.expected_pointer()
            && self.raw.ulLabelLength == self.label.length()
            && self.raw.pContextData == optional_expected_pointer(&self.context)
            && self.raw.ulContextDataLength == optional_length(&self.context)
            && self.randoms.unchanged(
                self.raw.RandomInfo.pClientRandom,
                self.raw.RandomInfo.ulClientRandomLen,
                self.raw.RandomInfo.pServerRandom,
                self.raw.RandomInfo.ulServerRandomLen,
            )
            && inputs
    }
}
