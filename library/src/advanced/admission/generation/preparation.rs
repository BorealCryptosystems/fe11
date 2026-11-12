// SPDX-License-Identifier: Apache-2.0
//! Generation's borrowed recipe and unpublished graph for common-start admission.
use super::{
    scalar_storage, stable_values, Generation, GenerationDiagnostics, GenerationOwnership,
    StorageUse, Templates,
};
use crate::crypto::{KeyAdmissionDescription, KeyGenerationDescription};
use crate::{
    attributes::{OwnedTemplate, OwnedTemplateStorage, Template, TemplateSize},
    managed,
    symmetric::memory::Credit,
    Error, ManagedClass, Result, Session,
};
use fe11_sys::{CK_INVALID_HANDLE, CK_MECHANISM, CK_MECHANISM_TYPE, CK_OBJECT_HANDLE};
use std::mem::size_of;

pub(in crate::advanced::admission) struct Plan {
    kind: CK_MECHANISM_TYPE,
    count: usize,
    fixed: usize,
    slots: usize,
    requested: usize,
}
pub(in crate::advanced::admission) struct Storage {
    public: OwnedTemplateStorage,
    private: Option<OwnedTemplateStorage>,
    outputs: Vec<CK_OBJECT_HANDLE>,
    mechanism: Vec<CK_MECHANISM>,
    objects: Vec<crate::registry::WritePermit>,
    diagnostics: GenerationDiagnostics,
    fixed: usize,
    scalar_excess: usize,
}
fn sum(values: &[usize]) -> Result<usize> {
    values
        .iter()
        .try_fold(0usize, |total, value| total.checked_add(*value))
        .ok_or(Error::Rejected(crate::RejectionReason::KeyAdmission(
            crate::KeyAdmissionRejection::GenerationRetainedMetadataSize,
        )))
}
impl Plan {
    pub(in crate::advanced::admission) fn new(
        policy: &impl KeyGenerationDescription,
    ) -> Result<Self> {
        if policy.is_pair() {
            policy.generation_identity()?;
        }
        let (public, private) = policy.generation_templates_as::<TemplateSize>()?;
        let (count, kind, template_bytes) = match private {
            Some(private) => (
                2,
                policy.generation_mechanism()?,
                sum(&[public.owned_bytes()?, private.owned_bytes()?])?,
            ),
            None => {
                let bytes = public.owned_bytes()?;
                (1, policy.generation_mechanism()?, bytes)
            }
        };
        let fixed = size_of::<Generation>()
            .checked_sub(count * size_of::<OwnedTemplate>())
            .and_then(|n| n.checked_add(size_of::<CK_MECHANISM>()))
            .and_then(|n| n.checked_add(count * size_of::<CK_OBJECT_HANDLE>()))
            .and_then(|n| n.checked_add(GenerationDiagnostics::allocation_bytes()))
            .ok_or(Error::Rejected(crate::RejectionReason::KeyAdmission(
                crate::KeyAdmissionRejection::GenerationRetainedMetadataSize,
            )))?;
        let permits = count
            .checked_mul(size_of::<crate::registry::WritePermit>())
            .ok_or(Error::Rejected(crate::RejectionReason::ObjectMutation(
                crate::ObjectMutationRejection::OperationDestinationCount,
            )))?;
        Ok(Self {
            kind,
            count,
            fixed,
            slots: count,
            requested: sum(&[template_bytes, fixed, permits])?,
        })
    }
    pub(in crate::advanced::admission) fn count(&self) -> usize {
        self.count
    }
    pub(in crate::advanced::admission) fn recipes<'a>(
        &self,
        session: &Session,
        policy: &'a impl KeyAdmissionDescription,
    ) -> Result<[managed::DestinationRecipe<'a>; 2]> {
        let primary = managed::DestinationRecipe::new(
            session,
            policy.admission_class(),
            &[policy.admission_id()],
        )?;
        let secondary = if self.count == 2 {
            managed::DestinationRecipe::new(
                session,
                ManagedClass::PrivateKey,
                &[policy.admission_id()],
            )?
        } else {
            primary
        };
        Ok([primary, secondary])
    }
    pub(in crate::advanced::admission) fn requested_bytes(&self) -> usize {
        self.requested
    }

    pub(in crate::advanced::admission) fn allocate(
        &self,
        policy: &impl KeyGenerationDescription,
    ) -> Result<Storage> {
        let (public, private) = policy.generation_templates_as::<Template>()?;
        if usize::from(private.is_some()) + 1 != self.count {
            return Err(Error::Rejected(crate::RejectionReason::KeyAdmission(
                crate::KeyAdmissionRejection::GenerationTemplateArity,
            )));
        }
        let public = OwnedTemplateStorage::allocate(public)?;
        let private = private.map(OwnedTemplateStorage::allocate).transpose()?;
        let outputs = scalar_storage((0..self.count).map(|_| CK_INVALID_HANDLE))?;
        let mechanism = scalar_storage(
            [CK_MECHANISM {
                mechanism: self.kind,
                pParameter: std::ptr::null_mut(),
                ulParameterLen: 0,
            }]
            .into_iter(),
        )?;
        let scalar_excess = outputs
            .capacity()
            .checked_sub(self.count)
            .and_then(|n| n.checked_mul(size_of::<CK_OBJECT_HANDLE>()))
            .and_then(|n| {
                mechanism
                    .capacity()
                    .checked_sub(1)
                    .and_then(|m| m.checked_mul(size_of::<CK_MECHANISM>()))
                    .and_then(|m| n.checked_add(m))
            })
            .ok_or(Error::Rejected(crate::RejectionReason::KeyAdmission(
                crate::KeyAdmissionRejection::GenerationRetainedMetadataSize,
            )))?;
        let mut objects = Vec::new();
        objects.try_reserve_exact(self.slots).map_err(|_| {
            Error::Rejected(crate::RejectionReason::ObjectMutation(
                crate::ObjectMutationRejection::OperationDestinationAllocation,
            ))
        })?;
        Ok(Storage {
            public,
            private,
            outputs,
            mechanism,
            objects,
            diagnostics: GenerationDiagnostics::allocate()?,
            fixed: self.fixed,
            scalar_excess,
        })
    }
    pub(in crate::advanced::admission) fn bind(
        &self,
        storage: Storage,
        prepaid: &mut Credit,
    ) -> Result<Prepared> {
        let metadata_bytes = sum(&[
            storage.fixed,
            storage.scalar_excess,
            storage
                .objects
                .capacity()
                .checked_mul(size_of::<crate::registry::WritePermit>())
                .ok_or(Error::Rejected(crate::RejectionReason::ObjectMutation(
                    crate::ObjectMutationRejection::OperationDestinationCount,
                )))?,
        ])?;
        let public = storage.public.bind(prepaid)?;
        let public_count = public.count()?;
        let templates = match storage.private {
            Some(private) => {
                let private = private.bind(prepaid)?;
                let private_count = private.count()?;
                Templates::Pair {
                    public,
                    private,
                    public_count,
                    private_count,
                    outputs: stable_values(storage.outputs)?,
                }
            }
            None => Templates::Single {
                template: public,
                count: public_count,
                output: stable_values(storage.outputs)?,
            },
        };
        let mechanism = stable_values(storage.mechanism)?;
        let mut credit = prepaid.split(metadata_bytes)?;
        credit.release(storage.scalar_excess);
        Ok(Prepared {
            objects: storage.objects,
            templates,
            mechanism,
            kind: self.kind,
            ticket: None,
            diagnostics: storage.diagnostics,
            credit,
        })
    }
}
impl Storage {
    pub(in crate::advanced::admission) fn allocated_bytes(&self) -> Result<usize> {
        sum(&[
            self.fixed,
            self.scalar_excess,
            self.public.allocated_bytes()?,
            self.private
                .as_ref()
                .map(OwnedTemplateStorage::allocated_bytes)
                .transpose()?
                .unwrap_or(0),
            self.objects
                .capacity()
                .checked_mul(size_of::<crate::registry::WritePermit>())
                .ok_or(Error::Rejected(crate::RejectionReason::ObjectMutation(
                    crate::ObjectMutationRejection::OperationDestinationCount,
                )))?,
        ])
    }
}

/// Conversions and credits are complete before possession. Partial writers
/// leave before the ticket/storage; the reservation lives in the outer attempt.
pub(in crate::advanced::admission) struct Prepared {
    objects: Vec<crate::registry::WritePermit>,
    templates: Templates,
    mechanism: Box<[CK_MECHANISM; 1]>,
    kind: CK_MECHANISM_TYPE,
    ticket: Option<managed::PreparedCreation>,
    diagnostics: GenerationDiagnostics,
    credit: Credit,
}
impl Prepared {
    pub(in crate::advanced::admission) fn prepare_ticket(
        &mut self,
        session: &Session,
        reservation: &managed::Reservation,
    ) -> Result<()> {
        if self.ticket.is_some() {
            return Err(Error::Rejected(crate::RejectionReason::KeyAdmission(
                crate::KeyAdmissionRejection::GenerationTicketAlreadyPrepared,
            )));
        }
        self.ticket = Some(reservation.prepare_creation_ticket(session)?);
        Ok(())
    }
    pub(in crate::advanced::admission) fn try_possession(
        &mut self,
        session: &Session,
        reservation: &managed::Reservation,
    ) -> Result<Option<std::sync::Arc<crate::registry::Activity>>> {
        reservation.try_operation_permits_retained(session, &mut self.objects)
    }
    /// All fallible checks precede taking either input. The caller's envelope
    /// retains partial ownership on error and therefore drops its access first.
    pub(in crate::advanced::admission) fn transfer(
        candidate: &mut Option<Self>,
        session: &Session,
        reservation: &mut managed::Reservation,
    ) -> Result<Generation> {
        let prepared =
            candidate
                .as_mut()
                .ok_or(Error::Rejected(crate::RejectionReason::KeyAdmission(
                    crate::KeyAdmissionRejection::GenerationCandidateAbsent,
                )))?;
        if prepared.ticket.is_none() {
            return Err(Error::Rejected(crate::RejectionReason::KeyAdmission(
                crate::KeyAdmissionRejection::GenerationTicketAbsent,
            )));
        }
        let (reservation, objects) =
            reservation.transfer_to_operation(session, &mut prepared.objects)?;
        let prepared = candidate
            .take()
            .expect("generation candidate checked before transfer");
        Ok(Generation {
            templates: prepared.templates,
            mechanism: prepared.mechanism,
            kind: prepared.kind,
            cleanup_private: false,
            prepared: prepared
                .ticket
                .expect("generation ticket checked before transfer"),
            creation: None,
            _ownership: GenerationOwnership {
                _objects: objects,
                _reservation: reservation,
            },
            storage: StorageUse::Prepared,
            created: false,
            effect_possible: false,
            cleanup_attempted: false,
            diagnostics: prepared.diagnostics,
            _credit: prepared.credit,
        })
    }
}
