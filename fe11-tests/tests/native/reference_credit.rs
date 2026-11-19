// SPDX-License-Identifier: Apache-2.0
//! Reference quota distinguishes an impossible request from retained owners.
use super::super::{
    configuration::{select_token, Budgets, Configuration},
    module_controls,
    outcome::Failure,
    report::Report,
    search_fixture::Case,
};
use fe11::*;
use std::{
    collections::BTreeSet,
    io::{self, Write},
    num::NonZeroUsize,
};

pub(super) fn execute<W: Write>(
    config: &Configuration,
    limit: usize,
    report: Report<W>,
) -> io::Result<bool> {
    let mut module = None;
    let mut session = None;
    let mut created = Vec::new();
    let fixture = Case {
        before: "ABSENT".into(),
        action: "init".into(),
        label: format!("{}:reference-credit", config.label).into_bytes(),
        population: 3,
    };
    let setup = (|| -> std::result::Result<(), Failure> {
        if !matches!(limit, 2 | 6) {
            return Err(Failure::Input("reference_credit_limit"));
        }
        let mut budgets = Budgets::ordinary();
        budgets.sessions = 1;
        module = Some(
            config
                .builder(&budgets)
                .object_limits(ObjectLimits {
                    object_references: Some(limit),
                    managed_references: None,
                    destination_reservations: None,
                })
                .open()?,
        );
        let m = module
            .as_ref()
            .ok_or(Failure::Input("reference_credit_module"))?;
        let token =
            select_token(m, &config.label).ok_or(Failure::Input("reference_credit_token"))?;
        session = Some(m.select(&token)?.open_session(true)?);
        let s = session
            .as_ref()
            .ok_or(Failure::Input("reference_credit_session"))?;
        for index in 0..3 {
            let object = fixture.create_sized::<16>(s, index)?;
            if limit == 6 {
                created.push(object);
            }
            // With limit2 each published reference is dropped here; the native
            // session object remains until explicit session close at cleanup.
        }
        Ok(())
    })();
    let body = (|| -> std::result::Result<(), Failure> {
        let (Ok(()), Some(m), Some(s)) = (&setup, &module, &session) else {
            return Ok(());
        };
        let template = fixture.template();
        let plan = SearchPlan {
            maximum_objects: Some(3),
            batch_size: NonZeroUsize::new(2).ok_or(Failure::Input("reference_credit_batch"))?,
        };
        let find = || s.find_native_objects(&template, fixture.limits(), plan);
        if limit == 2 {
            match find() {
                Err(Error::Rejected(RejectionReason::ReferenceRegistry(
                    ReferenceRegistryRejection::ReferenceQuotaExceeded,
                ))) => (),
                Err(error) => return Err(error.into()),
                Ok(_) => return Err(Failure::Oracle("reference_quota_intrinsic_not_enforced")),
            }
            // A smaller caller-selected result still fits the unchanged quota.
            let selected = s.find_native_object_at(&template, fixture.limits(), plan, 1)?;
            if selected.matched != 3 {
                return Err(Failure::Oracle("reference_credit_population"));
            }
            fixture.identity_sized::<16>(
                s,
                selected
                    .object
                    .as_ref()
                    .ok_or(Failure::Oracle("reference_credit_selected_absent"))?,
            )?;
        } else {
            let held = find()?;
            if held.as_slice().len() != 3 {
                return Err(Failure::Oracle("reference_credit_first_count"));
            }
            // Created references use the managed registry. Two completed
            // searches, each retaining three distinct reference owners, fill
            // this ordinary-reference quota independently of the creations.
            let second = find()?;
            if second.as_slice().len() != 3 {
                return Err(Failure::Oracle("reference_credit_second_count"));
            }
            match find() {
                Err(Error::Busy(BusyReason::ReferenceRegistry(
                    ReferenceRegistryBusy::ReferenceQuotaExceeded,
                ))) => (),
                Err(error) => return Err(error.into()),
                Ok(_) => return Err(Failure::Oracle("reference_credit_retention_missing")),
            }
            drop(second);
            let resumed = find()?;
            let mut seen = BTreeSet::new();
            for object in resumed.as_slice() {
                seen.insert(fixture.identity_sized::<16>(s, object)?);
            }
            if resumed.as_slice().len() != 3 || seen != BTreeSet::from([0, 1, 2]) {
                return Err(Failure::Oracle("reference_credit_release_result"));
            }
            drop(held);
        }
        if m.object_limits().object_references != Some(limit) {
            return Err(Failure::Oracle("reference_credit_limit_changed"));
        }
        Ok(())
    })();
    let mut cleanup = Vec::new();
    if let Some(s) = &session {
        for object in &created {
            if let Err(error) = s.destroy_native_object(object) {
                cleanup.push(error.into());
            }
        }
        if let Err(error) = s.close() {
            cleanup.push(error.into());
        }
    }
    drop(created);
    drop(session);
    if let Some(m) = &module {
        if let Err(error) = m.close() {
            cleanup.push(error.into());
        }
    }
    drop(module);
    module_controls::finish(report, setup, body, cleanup)
}
