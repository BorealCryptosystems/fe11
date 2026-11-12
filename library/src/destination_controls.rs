// SPDX-License-Identifier: Apache-2.0
//! Explicit destination observations for one creation or administrative mutation.
use crate::{
    attributes::Template, Error, IdentityAttribute, ManagedClass, Observation, ObservationIssue,
    ReferenceTemplate, Result, SearchPlan, Session,
};
pub(crate) mod resident;

/// Whether a destination count includes the exact source native handle.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DestinationSource {
    /// Count every visible match, including the source if it matches.
    Include,
    /// Exclude only the exact source handle; creation has no source to exclude.
    Exclude,
}

/// One explicit enumeration of the destination in this session's visibility.
/// This is not an atomic or token-global uniqueness guarantee.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum DestinationSearchPlan {
    /// Make no query and no cardinality claim.
    NotRequested,
    /// Query exactly the selected target metadata and report the full count.
    Observe {
        /// Selector recipe or exact fields. An absent operand never broadens a query.
        /// KeyType and UniqueId are not supplied by an administrative destination.
        template: ReferenceTemplate,
        /// Per-call batch capacity and complete-result ceiling.
        resources: SearchPlan,
        /// Whether the source itself contributes to the count.
        source: DestinationSource,
    },
}

/// Optional observation of the USER role recorded by this library's token context.
/// This does not query native state or detect an external client's login changes.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum DestinationUserObservation {
    /// Do not inspect the recorded USER role.
    NotRequested,
    /// Read the locally recorded role without authorizing or refusing an operation.
    Read,
}

/// Independent destination choices for one call; there is no implicit policy.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DestinationPlan {
    /// Optional native enumeration and its observed count.
    pub search: DestinationSearchPlan,
    /// Optional recorded-role observation, independent of the query.
    pub user: DestinationUserObservation,
}

impl DestinationPlan {
    /// Pure availability preflight for a generated key destination. A selected
    /// query with an absent operand remains an Unusable observation; it must
    /// not require native search functions that will never be called.
    pub(crate) fn key_search_required(&self, class: ManagedClass) -> Result<bool> {
        let DestinationSearchPlan::Observe {
            template,
            resources,
            ..
        } = &self.search
        else {
            return Ok(false);
        };
        let identity = DestinationIdentity::KeyOrCertificate {
            class,
            id: &[],
            label: &[],
        };
        for field in [
            IdentityAttribute::Class,
            IdentityAttribute::KeyType,
            IdentityAttribute::Id,
            IdentityAttribute::Label,
            IdentityAttribute::UniqueId,
            IdentityAttribute::Application,
            IdentityAttribute::ObjectId,
        ] {
            if template.contains(field, class)
                && field != IdentityAttribute::Class
                && identity.bytes(field).is_none()
            {
                return Ok(false);
            }
        }
        crate::bounds::ck_length(resources.batch_size.get())?;
        Ok(true)
    }

    pub(crate) fn retained_bytes(&self) -> Result<usize> {
        Ok(std::mem::size_of::<Self>())
    }
}

/// A historical observation at preparation time, not a uniqueness certificate.
/// Contains neither native handles nor target metadata values. Getters do no IO.
pub struct DestinationReport {
    selection: DestinationPlan,
    count: Observation<u64>,

    user: Observation<bool>,

    authentication: Option<u64>,
    // Advanced admission can transfer the report beyond its original owner.
    // Keep its prepaid storage accounted for through that report's lifetime.
    selection_credit: Option<crate::symmetric::memory::Credit>,
}

pub(crate) enum DestinationIdentity<'a> {
    Metadata {
        class: ManagedClass,
        fields: &'a [(IdentityAttribute, Option<&'a [u8]>)],
    },
    KeyOrCertificate {
        class: ManagedClass,
        id: &'a [u8],
        label: &'a [u8],
    },
    PublicImport {
        id: crate::attributes::ByteParts<'a>,
        label: &'a [u8],
    },
}
impl DestinationIdentity<'_> {
    /// Validate selected operands without allocating a partial query. This is
    /// also the known storage requirement before destination materialization.
    fn query_layout(
        &self,
        selected: &ReferenceTemplate,
    ) -> Result<std::result::Result<usize, IdentityAttribute>> {
        let mut count = 0usize;
        let mut payload = 0usize;
        for field in [
            IdentityAttribute::Class,
            IdentityAttribute::KeyType,
            IdentityAttribute::Id,
            IdentityAttribute::Label,
            IdentityAttribute::UniqueId,
            IdentityAttribute::Application,
            IdentityAttribute::ObjectId,
        ] {
            if !selected.contains(field, self.class()) {
                continue;
            }
            count += 1;
            if field == IdentityAttribute::Class {
                continue;
            }
            let Some(value) = self.bytes(field) else {
                return Ok(Err(field));
            };
            if field == IdentityAttribute::KeyType {
                if value.len() != std::mem::size_of::<fe11_sys::CK_ULONG>() {
                    return Err(Error::Rejected(
                        crate::RejectionReason::AttributePreparation(
                            crate::AttributePreparationRejection::ReferenceTemplateIntegerWidth,
                        ),
                    ));
                }
            } else {
                crate::bounds::ck_length(value.len())?;
                payload = payload.checked_add(value.len()).ok_or(Error::Rejected(
                    crate::RejectionReason::AttributePreparation(
                        crate::AttributePreparationRejection::TemplateAllocationSize,
                    ),
                ))?;
            }
        }
        Ok(Ok(Template::identity_allocation_bytes(count, payload)?))
    }
    pub(crate) fn query_allocation_bytes(&self, selection: &DestinationPlan) -> Result<usize> {
        match &selection.search {
            DestinationSearchPlan::NotRequested => Ok(0),
            DestinationSearchPlan::Observe {
                template,
                resources,
                ..
            } => match self.query_layout(template)? {
                Ok(bytes) => {
                    crate::bounds::ck_length(resources.batch_size.get())?;
                    Ok(bytes)
                }
                Err(_) => Ok(0),
            },
        }
    }
    fn class(&self) -> ManagedClass {
        match self {
            Self::KeyOrCertificate { class, .. } | Self::Metadata { class, .. } => *class,
            Self::PublicImport { .. } => ManagedClass::PublicKey,
        }
    }
    fn bytes(&self, field: IdentityAttribute) -> Option<crate::attributes::ByteParts<'_>> {
        use crate::attributes::ByteParts;
        match (self, field) {
            (Self::Metadata { fields, .. }, requested) => fields
                .iter()
                .find(|(field, _)| *field == requested)
                .and_then(|(_, value)| *value)
                .map(ByteParts::from),
            (Self::KeyOrCertificate { id, .. }, IdentityAttribute::Id) => {
                Some(ByteParts::from(*id))
            }
            (Self::PublicImport { id, .. }, IdentityAttribute::Id) => Some(*id),
            (
                Self::KeyOrCertificate { label, .. } | Self::PublicImport { label, .. },
                IdentityAttribute::Label,
            ) => Some(ByteParts::from(*label)),
            _ => None,
        }
    }
    fn template(
        &self,
        selected: &ReferenceTemplate,
    ) -> Result<std::result::Result<Template, IdentityAttribute>> {
        self.recipe::<Template>(selected)
    }
    fn recipe<T: crate::attributes::TemplateSink>(
        &self,
        selected: &ReferenceTemplate,
    ) -> Result<std::result::Result<T, IdentityAttribute>> {
        if let Err(field) = self.query_layout(selected)? {
            return Ok(Err(field));
        }
        let mut template = T::empty();
        let class = self.class().raw().to_ne_bytes();
        for field in [
            IdentityAttribute::Class,
            IdentityAttribute::KeyType,
            IdentityAttribute::Id,
            IdentityAttribute::Label,
            IdentityAttribute::UniqueId,
            IdentityAttribute::Application,
            IdentityAttribute::ObjectId,
        ] {
            if !selected.contains(field, self.class()) {
                continue;
            }
            let value = if field == IdentityAttribute::Class {
                Some(crate::attributes::ByteParts::from(class.as_slice()))
            } else {
                self.bytes(field)
            };
            let Some(value) = value else {
                return Ok(Err(field));
            };
            template.identity_parts(field, value)?;
        }
        Ok(Ok(template))
    }
}

impl DestinationReport {
    pub(crate) fn with_prepaid(mut self, credit: crate::symmetric::memory::Credit) -> Self {
        self.selection_credit = Some(credit);
        self
    }
    pub(crate) fn attach(
        self,
        session: &Session,
        mut reference: crate::ManagedObjectRef,
    ) -> Result<crate::ManagedObjectRef> {
        self.check_context(session)?;
        reference.destination_report = Some(self);
        Ok(reference)
    }

    /// Exact choices for this call, without target metadata values.
    pub fn selection(&self) -> &DestinationPlan {
        &self.selection
    }
    /// Count of all selected visible matches, or precise missing-operand evidence.
    pub fn cardinality(&self) -> Observation<u64> {
        self.count
    }

    /// Last recorded USER observation, only when requested. Unavailable means
    /// that no reliable observation is retained; it does not mean logged out.
    /// This evidence is historical and cannot authorize a subsequent native call.
    pub fn recorded_user(&self) -> Observation<bool> {
        self.user
    }

    /// Local role/operand reporting only. A native cardinality query is prepared
    /// and resumed by the resident destination owner, never by this fast path.
    pub(crate) fn observe_local(
        selection: DestinationPlan,
        state: &crate::session::SessionAccess<'_>,
        session: &Session,
        destination: DestinationIdentity<'_>,
    ) -> Result<Self> {
        session.entry(state)?;
        if destination.query_allocation_bytes(&selection)? != 0 {
            return Err(Error::Rejected(crate::RejectionReason::ObjectDestination(
                crate::ObjectDestinationRejection::DestinationObservationRequiresPreparedOwner,
            )));
        }
        let observed = !matches!(&selection.search, DestinationSearchPlan::NotRequested)
            || !matches!(&selection.user, DestinationUserObservation::NotRequested);
        let authentication = observed.then(|| session.snapshot.authentication_stamp());
        let result = (|| {
            let (prepared, query) = PreparedDestination::new(
                selection,
                || session.snapshot.recorded_user(),
                authentication,
                destination,
            )?;
            let count = match query {
                DestinationQuery::Ready(count) => count,
                DestinationQuery::Enumerate { .. } => {
                    return Err(Error::Rejected(crate::RejectionReason::ObjectDestination(
                        crate::ObjectDestinationRejection::DestinationQueryReachedLocalReport,
                    )))
                }
            };
            prepared.finish(count)
        })();
        session.metadata_result(state, authentication, result)
    }

    // Revalidate the evidence's local visibility context before native mutation
    // and before publication. This cannot detect external native-client changes.
    pub(crate) fn check_context(&self, session: &Session) -> Result<()> {
        if let Some(authentication) = self.authentication {
            session
                .snapshot
                .check_authentication_unchanged(authentication)?;
        }
        Ok(())
    }
}

// Only this preparation may be retained while a native enumeration is pending.
// It has no public evidence getters and cannot be mistaken for a final report.
pub(crate) struct PreparedDestination {
    selection: DestinationPlan,
    user: Observation<bool>,

    authentication: Option<u64>,
}

pub(crate) enum DestinationQuery {
    Ready(Observation<u64>),
    Enumerate {
        template: crate::attributes::Template,
        resources: SearchPlan,
    },
}

impl PreparedDestination {
    pub(crate) fn retained_selection_bytes(&self) -> Result<usize> {
        self.selection.retained_bytes()
    }
    pub(crate) fn new(
        selection: DestinationPlan,
        role: impl FnOnce() -> Result<Observation<bool>>,
        authentication: Option<u64>,
        destination: DestinationIdentity<'_>,
    ) -> Result<(Self, DestinationQuery)> {
        let prepared = Self::bind(selection, role, authentication)?;
        let query = match &prepared.selection.search {
            DestinationSearchPlan::NotRequested => {
                DestinationQuery::Ready(Observation::NotRequested)
            }
            DestinationSearchPlan::Observe {
                template,
                resources,
                ..
            } => match destination.template(template)? {
                Ok(template) => DestinationQuery::Enumerate {
                    template,
                    resources: *resources,
                },
                Err(field) => DestinationQuery::Ready(Observation::Unusable(
                    ObservationIssue::DestinationOperandAbsent(field),
                )),
            },
        };
        Ok((prepared, query))
    }

    fn bind(
        selection: DestinationPlan,
        role: impl FnOnce() -> Result<Observation<bool>>,
        authentication: Option<u64>,
    ) -> Result<Self> {
        let user = match &selection.user {
            DestinationUserObservation::NotRequested => Observation::NotRequested,
            DestinationUserObservation::Read => role()?,
        };
        Ok(Self {
            selection,
            user,

            authentication,
        })
    }

    pub(crate) fn finish(self, count: Observation<u64>) -> Result<DestinationReport> {
        if matches!(&self.selection.search, DestinationSearchPlan::NotRequested)
            && count != Observation::NotRequested
        {
            return Err(Error::Rejected(crate::RejectionReason::ObjectDestination(
                crate::ObjectDestinationRejection::UnrequestedDestinationCount,
            )));
        }
        Ok(DestinationReport {
            selection: self.selection,
            count,

            user: self.user,

            authentication: self.authentication,
            selection_credit: None,
        })
    }
}
