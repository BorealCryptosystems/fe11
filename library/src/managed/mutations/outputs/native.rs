// SPDX-License-Identifier: Apache-2.0
//! Family-specific native storage enclosed by the common output protocol.
//!
//! Only creation identity and the completion receipt are shared. Mechanism
//! parameters and auxiliary results remain in their original typed owners.
use super::*;
use crate::managed::RevocationTargets;
use crate::mechanism_extension::transport::{CreationOutput, KeyCreation};
use crate::native::{
    derivation::{kea::Kea, key_material::KeyMaterial, sp800::Sp800Frame, Derivation},
    generation::{KeyGeneration, PairGeneration},
};

type SecondaryAliases = [Option<(CK_OBJECT_HANDLE, RevocationTargets)>; 4];
pub(in crate::managed::mutations) enum PreparedCall {
    Key(Box<KeyGeneration>),
    Pair(Box<PairGeneration>),
    Derived {
        call: Box<Derivation>,
        base: CK_OBJECT_HANDLE,
        aliases: RevocationTargets,
        secondary: SecondaryAliases,
        mutation: Option<RevocationTargets>,
    },
    Transport {
        call: Box<KeyCreation>,
        key: CK_OBJECT_HANDLE,
        aliases: Option<RevocationTargets>,
        mutation: Option<RevocationTargets>,
        secondary: SecondaryAliases,
    },
    Kea {
        call: Box<Kea>,
        base: CK_OBJECT_HANDLE,
        aliases: RevocationTargets,
    },
    Tls {
        call: Box<KeyMaterial>,
        base: CK_OBJECT_HANDLE,
        aliases: RevocationTargets,
        publication: super::super::key_material::Publication,
    },
    Sp800 {
        call: Box<Sp800Frame>,
        base: CK_OBJECT_HANDLE,
        publication: super::super::sp800::Publication,
    },
}
pub(in crate::managed) enum Output {
    Key {
        handle: CK_OBJECT_HANDLE,
        value: Result<crate::NativeGenerationOutput>,
    },
    Pair {
        handles: [CK_OBJECT_HANDLE; 2],
        value: Result<crate::NativeGenerationOutput>,
    },
    Derived {
        handle: CK_OBJECT_HANDLE,
        value: crate::NativeDerivationOutput,
    },
    Transport {
        handle: CK_OBJECT_HANDLE,
        value: Result<CreationOutput>,
    },
    Kea {
        handle: CK_OBJECT_HANDLE,
        randoms: crate::KeaRandoms,
    },
    Tls {
        data: KeyMaterial,
        publication: super::super::key_material::Publication,
    },
    Sp800 {
        data: Sp800Frame,
        publication: super::super::sp800::Publication,
    },
}
pub(super) struct Success {
    pub(super) output: Output,
    pub(super) creation: crate::managed::CreationTicket,
    pub(super) receipt: crate::error::CompletionDiagnostic,
}
impl PreparedCall {
    pub(super) fn execute(
        self,
        session: &Session,
        access: &SessionAccess<'_>,
        diagnostic: crate::error::CompletionStorage,
        creation: crate::managed::PreparedCreation,
        cleanup: &mut crate::error::CleanupStorage,
    ) -> Result<Success> {
        let (output, creation, receipt) = match self {
            Self::Key(call) => {
                let call = crate::allocation::unbox(call);
                let (effect, value) =
                    call.execute_resident(session, access, diagnostic, creation, cleanup)?;
                let ([handle], creation, receipt) = effect.into_parts();
                (Output::Key { handle, value }, creation, receipt)
            }
            Self::Pair(call) => {
                let call = crate::allocation::unbox(call);
                let effect = call.execute_resident(
                    session,
                    access,
                    diagnostic,
                    creation,
                    || {

                    },
                    |cause| cleanup.mark_remaining(cause),
                )?;
                let (handles, creation, receipt, value) = effect.into_parts_with_output();
                (Output::Pair { handles, value }, creation, receipt)
            }
            Self::Derived {
                call,
                base,
                aliases,
                secondary,
                mutation,
            } => {
                let call = crate::allocation::unbox(call);
                let (effect, value) = call.execute_resident(
                    session, access, diagnostic, creation, base, aliases, secondary, mutation,
                    cleanup,
                )?;
                let ([handle], creation, receipt) = effect.into_parts();
                (Output::Derived { handle, value }, creation, receipt)
            }
            Self::Transport {
                call,
                key,
                aliases,
                mutation,
                secondary,
            } => {
                let call = crate::allocation::unbox(call);
                let (effect, value) = call.execute_resident(
                    session, access, diagnostic, creation, key, aliases, mutation, secondary,
                    cleanup,
                )?;
                let ([handle], creation, receipt) = effect.into_parts();
                (Output::Transport { handle, value }, creation, receipt)
            }
            Self::Kea {
                call,
                base,
                aliases,
            } => {
                let call = crate::allocation::unbox(call);
                let effect = call.execute_resident(
                    session, access, diagnostic, creation, base, aliases, cleanup,
                )?;
                let (handle, randoms, creation, receipt) = effect.into_created_parts()?;
                (Output::Kea { handle, randoms }, creation, receipt)
            }
            Self::Tls {
                call,
                base,
                aliases,
                publication,
            } => {
                let call = crate::allocation::unbox(call);
                let effect = call.execute_resident(
                    session, access, diagnostic, creation, base, aliases, cleanup,
                )?;
                let (data, creation, receipt) = effect.into_parts();
                (Output::Tls { data, publication }, creation, receipt)
            }
            Self::Sp800 {
                call,
                base,
                mut publication,
            } => {
                let call = crate::allocation::unbox(call);
                let sources = std::mem::take(&mut publication.sources);
                let effect = call.execute_resident(
                    session, access, diagnostic, creation, base, sources, cleanup,
                )?;
                let (data, creation, receipt) = effect.into_parts();
                (Output::Sp800 { data, publication }, creation, receipt)
            }
        };
        Ok(Success {
            output,
            creation,
            receipt,
        })
    }
}
impl Output {
    pub(super) fn slot_handle(&self, index: usize) -> Result<CK_OBJECT_HANDLE> {
        match self {
            Self::Key { handle, .. }
            | Self::Derived { handle, .. }
            | Self::Transport { handle, .. }
            | Self::Kea { handle, .. }
                if index == 0 =>
            {
                Ok(*handle)
            }
            Self::Pair { handles, .. } => handles.get(index).copied().ok_or(Error::Rejected(
                crate::RejectionReason::ObjectPublication(
                    crate::ObjectPublicationRejection::PairOutputSlot,
                ),
            )),
            Self::Tls { data, .. } => data.slots().get(index).copied().ok_or(Error::Rejected(
                crate::RejectionReason::ObjectPublication(
                    crate::ObjectPublicationRejection::TlsOutputSlot,
                ),
            )),
            Self::Sp800 { data, .. } => {
                data.output_handles()
                    .get(index)
                    .copied()
                    .ok_or(Error::Rejected(crate::RejectionReason::ObjectPublication(
                        crate::ObjectPublicationRejection::Sp800OutputSlot,
                    )))
            }
            _ => Err(Error::Rejected(crate::RejectionReason::ObjectPublication(
                crate::ObjectPublicationRejection::NativeOutputSlot,
            ))),
        }
    }
    pub(super) fn check_output_integrity(&mut self) -> Result<()> {
        // Generation/transport output-integrity errors originally precede the
        // mutation-context check. Keep that refusal order, including its receipt.
        match self {
            Self::Key { value, .. } | Self::Pair { value, .. } if value.is_err() => {
                let Err(error) = std::mem::replace(
                    value,
                    Err(Error::Rejected(crate::RejectionReason::ObjectPublication(
                        crate::ObjectPublicationRejection::GenerationOutputConsumed,
                    ))),
                ) else {
                    unreachable!()
                };
                return Err(error);
            }
            Self::Transport { value, .. } if value.is_err() => {
                let Err(error) = std::mem::replace(
                    value,
                    Err(Error::Rejected(crate::RejectionReason::ObjectPublication(
                        crate::ObjectPublicationRejection::TransportOutputConsumed,
                    ))),
                ) else {
                    unreachable!()
                };
                return Err(error);
            }
            _ => {}
        }
        if let Self::Tls { data, .. } = self {
            data.check_output_presence()?;
        }
        Ok(())
    }
}
