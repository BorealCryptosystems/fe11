// SPDX-License-Identifier: Apache-2.0
//! Native visibility of generated objects when their creating session closes.
use super::super::{
    configuration::{select_token, Configuration},
    generation_fixture::{Field, Fixture, Value},
    generation_observation,
    outcome::Failure,
};
use fe11::*;
use std::num::NonZeroUsize;

fn find(session: &Session, fields: &[Field]) -> std::result::Result<Vec<NativeObjectRef>, Failure> {
    let selected: Vec<_> = fields
        .iter()
        .filter(|f| {
            f.attribute == StandardAttribute::CLASS || f.attribute == StandardAttribute::LABEL
        })
        .collect();
    if selected.len() != 2 {
        return Err(Failure::Input("generated_lifetime_search_identity"));
    }
    let inputs: Vec<_> = selected.iter().map(|f| f.input()).collect();
    let mut search = session.iter_native_objects(
        &inputs,
        AttributeTemplateLimits {
            maximum_depth: 0,
            maximum_attributes: 2,
            maximum_value_bytes: selected.iter().map(|f| f.bytes()).sum(),
        },
        NonZeroUsize::new(2).unwrap(),
    )?;
    let mut found = Vec::new();
    while let Some(object) = search.next() {
        found.push(object?);
        if found.len() > 1 {
            search.finish()?;
            return Err(Failure::Oracle("generated_lifetime_duplicate"));
        }
    }
    search.finish()?;
    Ok(found)
}

pub(super) fn check(
    module: &Module,
    config: &Configuration,
    creator: &Session,
    fixture: &Fixture,
    original: &mut Option<CreatedObjectSet>,
    creator_closed: &mut bool,
) -> std::result::Result<(), Failure> {
    let token =
        select_token(module, &config.label).ok_or(Failure::Input("generated_lifetime_token"))?;
    let peer = module.select(&token)?.open_session(true)?;
    let fields: Vec<&[Field]> = if fixture.private.is_empty() {
        vec![&fixture.public]
    } else {
        vec![&fixture.public, &fixture.private]
    };
    let mechanism = match fixture.generator {
        super::super::generation_fixture::Generator::Single(g) => g.mechanism_number(),
        super::super::generation_fixture::Generator::Pair(g) => g.mechanism_number(),
    };
    let mut retained = Vec::new();
    let body = (|| -> std::result::Result<(), Failure> {
        // The creator's login is shared by its peer. Every generated object
        // must be visible before closing; these aliases are then discarded.
        for fields in &fields {
            if find(&peer, fields)?.len() != 1 {
                return Err(Failure::Oracle("generated_lifetime_initial_visibility"));
            }
        }
        creator.close()?;
        *creator_closed = true;
        *original = None;
        for fields in &fields {
            let token = match fields
                .iter()
                .find(|f| f.attribute == StandardAttribute::TOKEN)
                .map(|f| &f.value)
            {
                Some(Value::Boolean(value)) => *value,
                _ => return Err(Failure::Input("generated_lifetime_token_field")),
            };
            let objects = find(&peer, fields)?;
            let count = objects.len();
            retained.extend(objects);
            if count != usize::from(token) {
                return Err(Failure::Oracle("generated_lifetime_after_close"));
            }
            if token {
                generation_observation::check(
                    &peer,
                    retained
                        .last()
                        .ok_or(Failure::Input("generated_lifetime_owner"))?,
                    fields,
                    mechanism,
                )?;
            }
        }
        Ok(())
    })();
    // Retain all freshly selected token owners before checking attributes.
    // Destruction and close are attempted even after an assertion fails.
    let mut cleanup = None;
    for object in &retained {
        if let Err(error) = peer.destroy_native_object(object) {
            cleanup.get_or_insert(Failure::from(error));
        }
    }
    drop(retained);
    if let Err(error) = peer.close() {
        cleanup.get_or_insert(Failure::from(error));
    }
    body.and(match cleanup {
        Some(error) => Err(error),
        None => Ok(()),
    })
}
