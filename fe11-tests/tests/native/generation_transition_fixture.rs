// SPDX-License-Identifier: Apache-2.0
//! Generation owners retain created objects independently of observation success.
use super::{
    configuration::{select_token, Configuration},
    credentials::Credentials,
    generation_observation, generation_transition_spec as spec,
    outcome::Failure,
};
use fe11::*;
use std::{fs::File, io::Read, num::NonZeroUsize, path::Path};

pub struct Case {
    pub route: String,
    pub state: String,
    pub action: String,
}
impl Case {
    pub fn read(path: &Path) -> std::result::Result<Self, Failure> {
        let mut bytes = Vec::new();
        File::open(path)
            .map_err(|_| Failure::Input("fixture_open"))?
            .take(513)
            .read_to_end(&mut bytes)
            .map_err(|_| Failure::Input("fixture_read"))?;
        if bytes.len() > 512 {
            return Err(Failure::Input("fixture_size"));
        }
        let text = std::str::from_utf8(&bytes).map_err(|_| Failure::Input("fixture_encoding"))?;
        let fields: Vec<_> = text.split_terminator('\n').collect();
        if fields.len() != 3
            || !(super::generation_family_spec::supported(fields[0])
                || matches!(
                    fields[0],
                    "typed_generate_aes_key"
                        | "typed_generate_symmetric_key"
                        | "typed_generate_aes_key_encryption_key"
                        | "typed_generate_transport_symmetric_key"
                ))
            || !matches!(
                fields[1],
                "IDLE"
                    | "INITIALIZED"
                    | "CREATED_UNCLAIMED"
                    | "CONSUMED"
                    | "RETIRED"
                    | "REFUSED_TERMINAL"
                    | "OBSERVER_DROPPED"
            )
            || !matches!(
                fields[2],
                "init"
                    | "poll"
                    | "logout"
                    | "close"
                    | "capture"
                    | "cancel"
                    | "drop_ticket"
                    | "unsupported"
            )
        {
            return Err(Failure::Input("generation_transition_fields"));
        }
        if fields[2] == "unsupported"
            && (fields[1] != "IDLE"
                || !matches!(
                    fields[0],
                    "typed_generate_montgomery_key" | "typed_generate_montgomery_key_448"
                ))
        {
            return Err(Failure::Input("unsupported_generator_fixture"));
        }
        Ok(Self {
            route: fields[0].into(),
            state: fields[1].into(),
            action: fields[2].into(),
        })
    }
}
pub struct Fixture {
    pub peer: Option<Session>,
    pub subject: Option<AdvancedSession>,
    pub ticket: Option<OperationTicket>,
    pub closed: bool,
    pub logged: bool,
    pub completed: bool,
    created: usize,
    pub generation_returns: Vec<u64>,
    pub inventory_count: Option<usize>,
    pub remaining_count: Option<usize>,
    creation_outcome_unproven: bool,
    published: Vec<CreatedObjectSet>,
    cooperative: bool,
    route: String,
}
impl Fixture {
    pub fn empty() -> Self {
        Self {
            peer: None,
            subject: None,
            ticket: None,
            closed: false,
            logged: false,
            completed: false,
            created: 0,
            generation_returns: Vec::new(),
            inventory_count: None,
            remaining_count: None,
            creation_outcome_unproven: false,
            published: Vec::new(),
            cooperative: true,
            route: String::new(),
        }
    }
    pub fn observes_pair_return(&self) -> bool {
        matches!(
            self.route.as_str(),
            "typed_generate_montgomery_key" | "typed_generate_montgomery_key_448"
        )
    }

    // The observer flushes CK_RV before the calling thread resumes. A ticket
    // can retain either success or refusal; inspecting it by polling here
    // would change the transition that the case is intended to exercise.
    fn observe_pair_return(&mut self) -> std::result::Result<u64, Failure> {
        let missing = || Failure::Input("generation_return_observation");
        let path = std::env::var_os("FE11_PUBLIC_KEYPAIR_RETURNS").ok_or_else(missing)?;
        let mut text = String::new();
        File::open(path)
            .map_err(|_| missing())?
            .take(65)
            .read_to_string(&mut text)
            .map_err(|_| missing())?;
        if text.len() > 64 || !text.ends_with('\n') {
            return Err(missing());
        }
        let returns = text
            .lines()
            .map(str::parse::<u64>)
            .collect::<std::result::Result<Vec<_>, _>>()
            .map_err(|_| missing())?;
        let (code, previous) = returns.split_last().ok_or_else(missing)?;
        if previous != self.generation_returns.as_slice() {
            return Err(missing());
        }
        self.generation_returns.push(*code);
        Ok(*code)
    }

    pub fn subject(&self) -> std::result::Result<&AdvancedSession, Failure> {
        self.subject
            .as_ref()
            .ok_or(Failure::Input("generation_subject"))
    }
    pub fn peer(&self) -> std::result::Result<&Session, Failure> {
        self.peer.as_ref().ok_or(Failure::Input("generation_peer"))
    }
    pub fn begin(
        &self,
        case: &Case,
        label: &str,
        invalid: bool,
    ) -> std::result::Result<OperationTicket, Failure> {
        spec::start(self.subject()?, &case.route, label, invalid)
    }
    pub fn start(
        &mut self,
        module: &Module,
        case: &Case,
        label: &str,
    ) -> std::result::Result<(), Failure> {
        let before = module.call_counts()?;
        let started = self.begin(case, label, false);
        if started.is_err() {
            self.creation_outcome_unproven = true;
        }
        let observes_pair = self.observes_pair_return();
        let error = match started {
            Ok(ticket) => {
                self.ticket = Some(ticket);
                if !observes_pair {
                    self.created += spec::count(&case.route);
                }
                None
            }
            Err(error) if !observes_pair => return Err(error),
            Err(error) => Some(error),
        };
        self.completed = false;
        let after = module.call_counts()?;
        let generation = |m: &std::collections::BTreeMap<&str, u64>| {
            m.get(if spec::count(&case.route) == 1 {
                "C_GenerateKey"
            } else {
                "C_GenerateKeyPair"
            })
            .copied()
            .unwrap_or(0)
        };
        if generation(&after).checked_sub(generation(&before)) != Some(1) {
            if let Some(error) = error {
                return Err(error);
            }
            return Err(Failure::Oracle("generation_start_dispatch_count"));
        }
        if observes_pair {
            let code = self.observe_pair_return()?;
            if code == fe11_sys::CKR_OK as u64 {
                self.created += 2;
            } else if code != fe11_sys::CKR_MECHANISM_INVALID as u64 {
                self.creation_outcome_unproven = true;
            }
        }
        if let Some(error) = error {
            return Err(error);
        }
        if self.cooperative && after.values().sum::<u64>() - before.values().sum::<u64>() > 1 {
            return Err(Failure::Oracle("cooperative_start_native_budget"));
        }
        Ok(())
    }
    pub fn poll_once(
        &mut self,
        module: &Module,
    ) -> std::result::Result<OperationProgress, Failure> {
        let before = module.call_counts()?;
        let mut ticket = self
            .ticket
            .take()
            .ok_or(Failure::Input("generation_ticket"))?;
        let result = self.subject()?.poll(&mut ticket);
        self.ticket = Some(ticket);
        if result.is_err() && !self.completed && !self.observes_pair_return() {
            // A retained ticket is not proof that generation succeeded. Keep
            // the body failure, then discover and clean up whatever this owned
            // namespace actually contains instead of inventing two objects.
            self.creation_outcome_unproven = true;
        }
        let after = module.call_counts()?;
        if self.cooperative && after.values().sum::<u64>() - before.values().sum::<u64>() > 1 {
            return Err(Failure::Oracle("cooperative_poll_native_budget"));
        }
        Ok(result?)
    }
    pub fn finish(&mut self, module: &Module, case: &Case) -> std::result::Result<(), Failure> {
        // The fixture selects fewer than 32 attributes. Even one dispatch per
        // attribute plus generation/publication fits this structural step bound.
        for _ in 0..64 {
            match self.poll_once(module)? {
                OperationProgress::Ready | OperationProgress::Pending => (),
                OperationProgress::CreatedObjects(created) => {
                    let count = created.objects.as_slice().len();
                    self.published.push(created.objects);
                    self.completed = true;
                    if count != spec::count(&case.route) || created.remainder.is_some() {
                        return Err(Failure::Oracle("generated_native_owners"));
                    }
                    return spec::observation(created.observation?, &case.route);
                }
                _ => return Err(Failure::Oracle("generation_progress_kind")),
            }
        }
        Err(Failure::Oracle("generation_step_bound"))
    }
    pub fn close(&mut self) -> std::result::Result<(), Failure> {
        match self.subject()?.close()? {
            AdvancedCloseStatus::Complete => {
                self.closed = true;
                Ok(())
            }
            AdvancedCloseStatus::Pending => Err(Failure::Oracle("synchronous_close_pending")),
        }
    }
    pub fn prepare(
        &mut self,
        module: &Module,
        config: &Configuration,
        pins: &Credentials,
        case: &Case,
    ) -> std::result::Result<(), Failure> {
        self.route = case.route.clone();
        let token =
            select_token(module, &config.label).ok_or(Failure::Input("token_not_unique"))?;
        self.peer = Some(module.select(&token)?.open_session(true)?);
        self.peer()?
            .login_as(LoginRole::User, SecretPin::new(pins.user.to_vec()))?;
        self.logged = true;
        let mut subject = module.select(&token)?.open_session(true)?.into_advanced()?;
        self.cooperative = case.state != "CREATED_UNCLAIMED";
        subject.set_pacing(if self.cooperative {
            OperationPacing::Cooperative
        } else {
            OperationPacing::Eager
        })?;
        self.subject = Some(subject);
        if case.state == "IDLE" {
            return Ok(());
        }
        if case.state == "REFUSED_TERMINAL" {
            if spec::invalid_reason(&case.route).is_none() {
                // A cancelled caller admission is a local starter refusal, not
                // an invented algorithm policy or a native key-generation failure.
                // Restore the enclosing admission before the next tested action.
                let cancellation = AdmissionCancellation::new();
                cancellation.cancel();
                let deadline = std::time::Instant::now()
                    .checked_add(std::time::Duration::from_secs(3600))
                    .ok_or(Failure::Input("generation_admission_deadline"))?;
                let before = module.call_counts()?;
                let result = with_resource_admission(
                    ResourceAdmission::WaitUntil {
                        deadline,
                        cancellation,
                    },
                    || self.begin(case, &config.label, false),
                );
                if let Ok(ticket) = result {
                    self.ticket = Some(ticket);
                    if !self.observes_pair_return() {
                        self.created += spec::count(&case.route);
                    }
                    return Err(Failure::Oracle("cancelled_generation_admission_accepted"));
                }
                if module.call_counts()? != before {
                    return Err(Failure::Oracle("cancelled_generation_admission_dispatched"));
                }
                return match result {
                    Err(Failure::Product(Error::AdmissionCancelled)) => Ok(()),
                    Err(error) => Err(error),
                    Ok(_) => Err(Failure::Oracle("cancelled_generation_admission_accepted")),
                };
            }
            return match self.begin(case, &config.label, true) {
                Err(Failure::Product(Error::Rejected(reason)))
                    if Some(reason) == spec::invalid_reason(&case.route) =>
                {
                    Ok(())
                }
                Err(error) => Err(error),
                Ok(_) => Err(Failure::Oracle("invalid_generation_spec_accepted")),
            };
        }
        self.start(module, case, &config.label)?;
        if case.state == "CREATED_UNCLAIMED"
            && self.observes_pair_return()
            && self.generation_returns.last().copied() != Some(fe11_sys::CKR_OK as u64)
        {
            return Err(Failure::Oracle("generation_required_pair_not_created"));
        }
        match case.state.as_str() {
            "CONSUMED" => self.finish(module, case)?,
            "RETIRED" => self.close()?,
            "OBSERVER_DROPPED" => self.ticket = None,
            _ => (),
        }
        Ok(())
    }
    pub fn cleanup(&mut self, label: &str) -> Vec<Failure> {
        let mut errors = Vec::new();
        if self.subject.is_some() && !self.closed {
            if let Err(error) = self.close() {
                errors.push(error);
            }
        }
        self.ticket = None;
        let observes_pair = self.observes_pair_return();
        // These token objects deliberately survive their creating session. The
        // complete ID+label namespace was assigned by this case alone; a retained
        // peer independently discovers and validates every surviving object.
        if let Some(peer) = &self.peer {
            let attr = |attribute: StandardAttribute, value| AttributeInput {
                attribute: attribute.into(),
                value,
            };
            let template = [
                attr(
                    StandardAttribute::ID,
                    AttributeInputValue::Bytes(label.as_bytes()),
                ),
                attr(
                    StandardAttribute::LABEL,
                    AttributeInputValue::Bytes(label.as_bytes()),
                ),
            ];
            let search = peer.find_native_objects(
                &template,
                AttributeTemplateLimits {
                    maximum_depth: 0,
                    maximum_attributes: 2,
                    maximum_value_bytes: label.len() * 2,
                },
                SearchPlan {
                    maximum_objects: Some(8),
                    batch_size: NonZeroUsize::new(4).unwrap(),
                },
            );
            match search {
                Ok(objects) => {
                    let found = objects.as_slice().len();
                    self.inventory_count = Some(found);
                    if (!self.creation_outcome_unproven && found != self.created)
                        || (observes_pair && found < self.created)
                    {
                        errors.push(Failure::Oracle("generation_surviving_object_count"));
                    }
                    let mut public_count = 0;
                    let mut private_count = 0;
                    for object in objects.as_slice() {
                        if super::generation_family_spec::supported(&self.route) {
                            match super::generation_family_observation::check(
                                peer,
                                object,
                                label,
                                &self.route,
                            ) {
                                Ok(class) if class == fe11_sys::CKO_PUBLIC_KEY as u64 => {
                                    public_count += 1
                                }
                                Ok(class) if class == fe11_sys::CKO_PRIVATE_KEY as u64 => {
                                    private_count += 1
                                }
                                Ok(_) => (),
                                Err(error) => errors.push(error),
                            }
                        } else if let Err(error) = generation_observation::check(
                            peer,
                            object,
                            &spec::fields(label),
                            fe11_sys::CKM_AES_KEY_GEN as u64,
                        ) {
                            errors.push(error);
                        }
                        if let Err(error) = peer.destroy_native_object(object) {
                            errors.push(error.into());
                        }
                    }
                    if spec::count(&self.route) == 2
                        && ((!self.creation_outcome_unproven
                            && (public_count != self.created / 2
                                || private_count != self.created / 2))
                            || (observes_pair
                                && (public_count < self.created / 2
                                    || private_count < self.created / 2)))
                    {
                        errors.push(Failure::Oracle("generated_pair_class_counts"));
                    }
                    if self.creation_outcome_unproven || observes_pair {
                        match peer.find_native_objects(
                            &template,
                            AttributeTemplateLimits {
                                maximum_depth: 0,
                                maximum_attributes: 2,
                                maximum_value_bytes: label.len() * 2,
                            },
                            SearchPlan {
                                maximum_objects: Some(8),
                                batch_size: NonZeroUsize::new(4).unwrap(),
                            },
                        ) {
                            Ok(remaining) => {
                                self.remaining_count = Some(remaining.as_slice().len());
                                if !remaining.as_slice().is_empty() {
                                    errors
                                        .push(Failure::Oracle("generation_cleanup_objects_remain"));
                                }
                            }
                            Err(error) => errors.push(error.into()),
                        }
                    }
                }
                Err(error) => errors.push(error.into()),
            }
            if self.logged {
                if let Err(error) = peer.logout() {
                    errors.push(error.into());
                }
            }
            if let Err(error) = peer.close() {
                errors.push(error.into());
            }
        }
        errors
    }
}
