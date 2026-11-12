// SPDX-License-Identifier: Apache-2.0
//! Private recovery cryptographic section; not an authenticated recovery manifest.

use super::{Descriptor, Function, KeyBindings, Kind, Limits, Messages};
use crate::advanced::record::Family;
use crate::{Error, Result};

pub(in crate::advanced) struct RecoverySection<'a> {
    pub profile: u8,
    pub mechanism: u64,
    pub keys: KeyBindings<'a>,
    pub messages: Messages<'a>,
}
impl<'a> RecoverySection<'a> {
    pub(in crate::advanced) fn read_with(
        bytes: &'a [u8],
        limits: Limits,
        observer: super::GraphObserver<'a>,
    ) -> Result<Self> {
        let (kind, mut reader) = super::decode_with(bytes, limits, observer)?;
        if kind != Kind::GcmRecovery {
            return Err(Error::Rejected(crate::RejectionReason::RecoveryRecord(
                crate::RecoveryRecordRejection::RecoveryRecordKind,
            )));
        }
        let profile = reader.u8()?;
        let mechanism = reader.u64()?;
        let keys = KeyBindings::read(&mut reader)?;
        let messages = Messages::read(&mut reader, limits)?;
        reader.finish()?;
        let descriptor = Descriptor {
            input: crate::advanced::input::InputState::closed(),
            family: Family::MessageDecrypt,
            profile,
            phase: Function::from_name("C_MessageDecryptInit")?,
            mechanism,
            size: 0,
            active_flags: 0,
            validation_requested: false,
            digest_bits: None,
            cipher_options: None,
            carried_messages: 0,
        };
        descriptor.validate_recovery(&keys, &messages, limits)?;
        Ok(Self {
            profile,
            mechanism,
            keys,
            messages,
        })
    }
}


