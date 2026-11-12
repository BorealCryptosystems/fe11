// SPDX-License-Identifier: Apache-2.0
//! Both copy entry points prepare one graph before taking source/destination roles.
use super::*;
use crate::{
    attribute_values::{InputTemplate, InputTemplatePlan, InputTemplateStorage},
    attributes::{OwnedTemplate, OwnedTemplateStorage, Template, TemplateSize},
    destination_controls::DestinationIdentity,
    native::template::NativeTemplate,
};

enum Input<'a> {
    Public(&'a CopyTarget),
    Typed {
        plan: InputTemplatePlan<'a>,
        identity: input_identity::InputIdentity<'a>,
    },
}
enum TemplateStorage<'a> {
    Public(OwnedTemplateStorage),
    Typed(InputTemplateStorage<'a>),
}
fn add(values: impl IntoIterator<Item = usize>) -> Result<usize> {
    values.into_iter().try_fold(0usize, |sum, value| {
        sum.checked_add(value)
            .ok_or(Error::Rejected(crate::RejectionReason::ObjectCopy(
                crate::ObjectCopyRejection::CopyStorageSize,
            )))
    })
}
impl<'a> Input<'a> {
    fn destination<'b>(
        &'b self,
        session: &Session,
        source: &'b ManagedObjectRef,
    ) -> Result<DestinationRecipe<'b>> {
        match self {
            Self::Typed { identity, .. } => identity.destination(session),
            Self::Public(CopyTarget::KeyOrCertificate { id, .. }) => {
                DestinationRecipe::new(session, source.identity.class, &[id])
            }
            Self::Public(CopyTarget::Data {
                application, label, ..
            }) => {
                let previous = identity_recipe(session, &source.identity)?;
                DestinationRecipe::with_parts(
                    session,
                    source.identity.class,
                    [
                        Some(application.as_bytes()),
                        previous.parts[1],
                        Some(label.as_bytes()),
                    ],
                )
            }
        }
    }
    fn public_recipe<T: crate::attributes::TemplateSink>(&self) -> Result<T> {
        let Self::Public(target) = self else {
            return Err(Error::Rejected(crate::RejectionReason::ObjectCopy(
                crate::ObjectCopyRejection::CopyTemplateRecipeKind,
            )));
        };
        Ok(match target {
            CopyTarget::KeyOrCertificate {
                id,
                label,
                persistent,
            } => super::super::public_template(fe11_sys::CKA_ID, id, label.as_bytes(), *persistent),
            CopyTarget::Data {
                application,
                label,
                persistent,
            } => super::super::public_template(
                fe11_sys::CKA_APPLICATION,
                application.as_bytes(),
                label.as_bytes(),
                *persistent,
            ),
        })
    }
    fn frame_bytes(&self) -> usize {
        // Template storage pays its own inline payload; CopyCall retains the
        // rest of its allocation and the enclosing SessionFrame.
        std::mem::size_of::<CopyCall>()
            + crate::native::frame::SessionFrame::<'_, CopyCall>::allocation_bytes()
            - match self {
                Self::Public(_) => std::mem::size_of::<OwnedTemplate>(),
                Self::Typed { .. } => std::mem::size_of::<InputTemplate>(),
            }
    }
    fn requested(&self) -> Result<usize> {
        match self {
            Self::Public(_) => self.public_recipe::<TemplateSize>()?.owned_bytes(),
            Self::Typed { plan, .. } => plan.prepared_allocation_bytes(),
        }
    }
    fn allocate(&self) -> Result<TemplateStorage<'a>> {
        match self {
            Self::Public(_) => OwnedTemplateStorage::allocate(self.public_recipe::<Template>()?)
                .map(TemplateStorage::Public),
            Self::Typed { plan, .. } => plan.allocate().map(TemplateStorage::Typed),
        }
    }
    fn with_identity<T>(
        &self,
        destination: &DestinationRecipe<'_>,
        visit: impl FnOnce(DestinationIdentity<'_>) -> Result<T>,
    ) -> Result<T> {
        match self {
            Self::Typed { identity, .. } => visit(identity.identity()),
            Self::Public(target) => {
                let label = match target {
                    CopyTarget::KeyOrCertificate { label, .. } | CopyTarget::Data { label, .. } => {
                        label
                    }
                };
                destination.with_identity(label, visit)
            }
        }
    }
}
impl TemplateStorage<'_> {
    fn allocated_bytes(&self) -> Result<usize> {
        match self {
            Self::Public(storage) => storage.allocated_bytes(),
            Self::Typed(storage) => storage.allocated_bytes(),
        }
    }
    fn bind(self, credit: &mut Credit) -> Result<NativeTemplate> {
        match self {
            Self::Public(storage) => storage.bind(credit).map(NativeTemplate::Public),
            Self::Typed(storage) => storage.bind(credit).map(NativeTemplate::Typed),
        }
    }
}
fn snapshot_bytes(plan: &crate::MutationObservationPlan) -> Result<usize> {
    if plan.attributes.is_empty() {
        Ok(0)
    } else {
        ReadStorage::requested(Recipe::Mutation(plan))
    }
}
fn snapshot(plan: &crate::MutationObservationPlan) -> Result<Option<ReadStorage>> {
    if plan.attributes.is_empty() {
        Ok(None)
    } else {
        ReadStorage::allocate(Recipe::Mutation(plan)).map(Some)
    }
}
fn actual(storage: &Option<ReadStorage>) -> Result<usize> {
    Ok(storage
        .as_ref()
        .map(ReadStorage::allocated_bytes)
        .transpose()?
        .unwrap_or(0))
}

pub(crate) fn public(
    session: &Session,
    source: &ManagedObjectRef,
    target: CopyTarget,
    admission: crate::ObjectAdmission,
    selection: crate::ObjectMutationPlan,
    content: crate::ContentMutationPlan,
    invocation: &mut super::super::InvocationDiagnostics,
) -> Result<crate::CreatedObjects<ManagedObjectRef>> {
    match &target {
        CopyTarget::KeyOrCertificate { id, label, .. }
            if source.identity.class.key()
                || source.identity.class == ManagedClass::Certificate =>
        {
            id_valid(id)?;
            label_valid(label)?;
        }
        CopyTarget::Data {
            application, label, ..
        } if source.identity.class == ManagedClass::Data => {
            label_valid(application)?;
            label_valid(label)?;
        }
        _ => {
            return Err(Error::Rejected(crate::RejectionReason::ObjectCopy(
                crate::ObjectCopyRejection::CopyDestinationClass,
            )))
        }
    }
    execute(
        session,
        source,
        Input::Public(&target),
        admission,
        selection,
        content,
        invocation,
    )
}
pub(crate) fn typed<'a>(
    session: &Session,
    source: &'a ManagedObjectRef,
    input: &'a [crate::AttributeInput<'a>],
    limits: crate::AttributeTemplateLimits,
    admission: crate::ObjectAdmission,
    selection: crate::ObjectMutationPlan,
    content: crate::ContentMutationPlan,
    invocation: &mut super::super::InvocationDiagnostics,
) -> Result<crate::CreatedObjects<ManagedObjectRef>> {
    let plan = InputTemplate::plan_scoped(input, limits, &session.inner)?;
    let identity =
        input_identity::InputIdentity::new(source.identity.class, input, Some(&source.identity));
    execute(
        session,
        source,
        Input::Typed { plan, identity },
        admission,
        selection,
        content,
        invocation,
    )
}
fn execute(
    session: &Session,
    object: &ManagedObjectRef,
    input: Input<'_>,
    admission: crate::ObjectAdmission,
    selection: crate::ObjectMutationPlan,
    content: crate::ContentMutationPlan,
    invocation: &mut super::super::InvocationDiagnostics,
) -> Result<crate::CreatedObjects<ManagedObjectRef>> {
    let epoch = session.snapshot.authentication_stamp();
    let quota = session.reference_admission_at_epoch(
        crate::session::ReferenceMode::Synchronous,
        epoch,
        |state| {
            state.native.table.C_CopyObject.ok_or(Error::Rejected(
                crate::RejectionReason::ObjectCopy(
                    crate::ObjectCopyRejection::CCopyObjectUnavailable,
                ),
            ))?;
            Ok(())
        },
    )?;
    let progress = quota.progress();
    let destination = input.destination(session, object)?;
    let previous = identity_recipe(session, &object.identity)?;
    let keys = [previous, destination];
    let keys = if previous == destination {
        &keys[1..]
    } else {
        &keys[..]
    };
    let class = object.identity.class;
    // The specialized entry point historically checks class once before the
    // after-snapshot; typed Copy performs only its later admission check.
    let post_class = matches!(input, Input::Public(_));
    let fixed = add([
        Prepared::allocation_bytes(),
        std::mem::size_of::<CopyOwner>(),
        crate::managed::NativeIdentity::allocation_bytes(),
        MutationProtection::allocation_bytes(),
        input.frame_bytes(),
        PreparedCopyDiagnostics::allocation_bytes(),
    ])?;
    let mut required = add([
        fixed,
        crate::error::CleanupStorage::requested(1)?,
        input.requested()?,
        ReferenceInitial::requested(&selection.source, object)?,
        input.with_identity(&destination, |identity| {
            DestinationInitial::requested(&selection.destination, &identity)
        })?,
        snapshot_bytes(&selection.before)?,
        snapshot_bytes(&selection.after)?,
        if post_class {
            ReadStorage::requested(class_recipe(&admission))?
        } else {
            0
        },
        SelectedInitial::requested(class, &admission)?,
    ])?;
    let (
        (
            (
                cleanup,
                diagnostics,
                template,
                mut source,
                destination_initial,
                before,
                after,
                class_read,
                selected,
                registry,
                mut permit,
                mut credit,
            ),
            reservation,
        ),
        access,
    ) = Reservation::prepare_mutation_prepaid(
        session,
        keys,
        1,
        Some(destination),
        [(Some(&**object), crate::session::activity::AccessMode::Read)],
        false,
        epoch,
        progress,
        |overhead, current| loop {
            context(session, Some(epoch), epoch)?;
            let admitted = required.checked_add(overhead).ok_or(Error::Rejected(
                crate::RejectionReason::ObjectReferences(
                    crate::ObjectReferencesRejection::DestinationAggregateAccounting,
                ),
            ))?;
            let group = quota.managed_with_observation_storage(1, admitted, || {
                context(session, Some(epoch), epoch)?;
                if !current()? {
                    return Err(Error::Busy(crate::BusyReason::ObjectCopy(
                        crate::ObjectCopyBusy::CopyCreationPlanChanged,
                    )));
                }
                Ok(())
            });
            let (permit, mut credit) = match group {
                Ok(group) => group,
                Err(Error::Busy(crate::BusyReason::ObjectCopy(
                    crate::ObjectCopyBusy::CopyCreationPlanChanged,
                ))) => return Ok(None),
                Err(error) => return Err(error),
            };
            let template = input.allocate()?;
            let source = ReferenceInitial::allocate(&selection.source, object)?;
            let destination_initial = input.with_identity(&destination, |identity| {
                DestinationInitial::allocate(&selection.destination, &identity)
            })?;
            let before = snapshot(&selection.before)?;
            let after = snapshot(&selection.after)?;
            let class_read = if post_class {
                Some(ReadStorage::allocate(class_recipe(&admission))?)
            } else {
                None
            };
            let selected = SelectedInitial::allocate(class, &admission)?;
            let cleanup = crate::error::CleanupStorage::allocate(1)?;
            let actual = add([
                fixed,
                cleanup.allocated_bytes()?,
                template.allocated_bytes()?,
                source.allocated_bytes()?,
                destination_initial.allocated_bytes()?,
                actual(&before)?,
                actual(&after)?,
                actual(&class_read)?,
                selected.allocated_bytes()?,
            ])?;
            let actual = actual.checked_add(overhead).ok_or(Error::Rejected(
                crate::RejectionReason::ObjectReferences(
                    crate::ObjectReferencesRejection::DestinationAggregateAccounting,
                ),
            ))?;
            if actual > admitted {
                drop(cleanup);
                drop((
                    template,
                    source,
                    destination_initial,
                    before,
                    after,
                    class_read,
                    selected,
                ));
                drop((credit, permit));
                required = actual.checked_sub(overhead).ok_or(Error::Rejected(
                    crate::RejectionReason::ObjectReferences(
                        crate::ObjectReferencesRejection::DestinationAggregateAccounting,
                    ),
                ))?;
                continue;
            }
            credit.release(admitted - actual);
            credit.observation_budget()?;
            let cleanup = crate::error::PreparedCleanupStorage::bind(cleanup, &mut credit)?;
            let diagnostics = PreparedCopyDiagnostics::prepare(&mut credit)?;
            let template = template.bind(&mut credit)?;
            template.check_extensions(&session.inner)?;
            let template = CopyCall {
                template,
                created: fe11_sys::CK_INVALID_HANDLE,
                _protection: None,
                _credit: credit.split(input.frame_bytes())?,
            };
            let registry = Prepared::allocate(&session.inner.symmetric_budget, &mut credit)?;
            let coordination = credit.split(overhead)?;
            return Ok(Some((
                (
                    cleanup,
                    diagnostics,
                    template,
                    source,
                    destination_initial,
                    before,
                    after,
                    class_read,
                    selected,
                    registry,
                    permit,
                    credit,
                ),
                coordination,
            )));
        },
        |access| {
            quota.check(access)?;
            context(session, Some(epoch), epoch)?;
            session.managed_handle(access, object).map(|_| ())
        },
    )?;
    // Retain both credits at the public entry before binding the resident owner.
    // Partial bind failure and later observation/cleanup errors use the same root.
    let (diagnostics, cleanup) = invocation.insert((diagnostics, cleanup));
    // Every privately owned result below is declared before the local access.
    // Refusal drops access first; retained binding keeps the source graph and
    // expected content in their original owners until activation succeeds.
    let destination_key;
    let creation;
    let protection;
    let mut reference_protection;
    let mut expected_content;
    let bound_source;
    let owner_credit;
    let publication;
    let mut registry = Some(registry);
    let access = access;
    destination_key = reservation.destination(&destination)?;
    quota.check(&access)?;
    // Consume only the prepared bookkeeping. Pending creation records are not
    // inserted until Copy dispatch, after all requested before-observations.
    creation = reservation.prepare_creation_at(session, &destination_key)?;
    protection = MutationProtection::take(session, &access, &mut credit)?;
    let before_content = reference::content_plan(&content.before);
    let after_content = reference::content_plan(&content.after);
    reference_protection = Some(ObservationProtection::mutation(&protection));
    expected_content = Some(content.before);
    bound_source = source.bind_retained(
        session,
        &access,
        object,
        &selection.source,
        &mut expected_content,
        epoch,
        &mut reference_protection,
        &mut credit,
    )?;
    owner_credit = credit.split(std::mem::size_of::<CopyOwner>())?;
    publication =
        crate::managed::SinglePublication::prepare(session, epoch, &mut permit, &mut credit)?;
    let owner = CopyOwner {
        publication,
        phase: Phase::Reference(Box::new(bound_source)),
        native: NativeCopy::Prepared {
            call: template.with_protection(ObservationProtection::mutation(&protection)),
            creation,
        },

        selection: selection.clone(),
        admission: admission.clone(),
        content: content.after,
        permit: Some(permit),
        future: FutureStorage {
            class: class_read,
            destination: Some(destination_initial),
            before,
            after,
            admission: Some(selected),
            prepaid: credit,
        },
        class,
        protection,
        epoch,
        _credit: owner_credit,
    };
    registry = Some(
        registry
            .take()
            .expect("copy registry preparation")
            .bind_copy(owner),
    );
    let coordination = session
        .entry
        .recovery
        .observations
        .publish_retained(&mut registry)?;
    // Only the original caller's immutable choices survive in the runner. The
    // native template, destination, creation proof and charged results are resident.
    drop((reservation, destination_key, input));
    runner::run(
        session,
        object,
        &selection,
        &admission,
        class,
        before_content,
        after_content,
        progress,
        epoch,
        coordination,
        access,
        diagnostics,
        cleanup,
    )
}
