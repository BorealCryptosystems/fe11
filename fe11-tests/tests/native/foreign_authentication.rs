// SPDX-License-Identifier: Apache-2.0
//! Authentication by a registered direct-C peer is visible to a Fe11 session.
use super::super::{
    arguments::hex, credentials::Credentials, foreign_info_image::Image, native_support,
    outcome::Failure,
};
use fe11::*;
use fe11_sys::*;
use std::sync::{Arc, Mutex};
use zeroize::Zeroizing;

type Answer<T> = std::result::Result<T, Failure>;

struct Authentication<'a> {
    participant: &'a ForeignParticipant,
    session: &'a ForeignWork,
    image: &'a Arc<Image>,
    handle: CK_SESSION_HANDLE,
    pin: Arc<Mutex<Zeroizing<Vec<u8>>>>,
}
impl Authentication<'_> {
    fn call(&self, client: &Module, login: bool, logged: &mut bool) -> Answer<()> {
        let before = client.call_counts()?;
        // The copy is zeroizing and retained by the registered argument graph.
        // Lock before dispatch, so a poisoned fixture lock cannot invent a call.
        let mut pin = self
            .pin
            .lock()
            .map_err(|_| Failure::Input("peer_pin_lock"))?;
        let length =
            CK_ULONG::try_from(pin.len()).map_err(|_| Failure::Input("peer_pin_length"))?;
        let login_function = native_support::required(self.image.login)?;
        let logout_function = native_support::required(self.image.logout)?;
        // SAFETY: the parent is this participant's real session. Both calls
        // mutate token-wide authentication. The image and all PIN bytes remain
        // alive until the synchronous return, or retained on uncertain return.
        let mut work = unsafe {
            self.participant.prepare_operation(
                self.session,
                ForeignWorkKind::Call,
                ForeignAccess::Token,
                (self.pin.clone(), self.image.clone()),
            )
        }?;
        let mut call = work.begin(ForeignStep::Start)?;
        call.dispatched()?;
        // SAFETY: the exact registered session, bounded writable PIN storage,
        // and the actual matching image's checked common-prefix entry are used.
        let code = unsafe {
            if login {
                login_function(self.handle, CKU_USER, pin.as_mut_ptr(), length)
            } else {
                logout_function(self.handle)
            }
        };
        if code == CKR_OK {
            *logged = login;
        }
        // SAFETY: Login/Logout have no asynchronous buffer-lending contract.
        // A non-PENDING return returns the input storage, independently of
        // authentication success. PENDING cannot certify that release.
        let receipt = unsafe {
            call.returned(
                code as u64,
                if code == CKR_PENDING {
                    ForeignCompletion::Uncertain
                } else {
                    ForeignCompletion::Returned
                },
            )
        };
        if receipt.code != code as u64 {
            return Err(Failure::Oracle("peer_authentication_code"));
        }
        receipt.publication?;
        native_support::status(if login { "C_Login" } else { "C_Logout" }, code)?;
        if client.call_counts()? != before {
            return Err(Failure::Oracle("peer_authentication_local_counter"));
        }
        Ok(())
    }
}

fn create(session: &Session, token: bool) -> Result<NativeObjectRef> {
    let attr = |attribute: StandardAttribute, value| AttributeInput {
        attribute: attribute.into(),
        value,
    };
    // These are public, disposable data objects, never credentials or host data.
    let attributes = [
        attr(
            StandardAttribute::CLASS,
            AttributeInputValue::Unsigned(CKO_DATA as u64),
        ),
        attr(
            StandardAttribute::TOKEN,
            AttributeInputValue::Boolean(token),
        ),
        attr(
            StandardAttribute::PRIVATE,
            AttributeInputValue::Boolean(false),
        ),
        attr(StandardAttribute::VALUE, AttributeInputValue::Bytes(b"abc")),
    ];
    session.create_native_object(
        &attributes,
        AttributeTemplateLimits {
            maximum_depth: 0,
            maximum_attributes: 4,
            maximum_value_bytes: 64,
        },
    )
}

pub(super) fn check(
    participant: &ForeignParticipant,
    work: &ForeignWork,
    image: &Arc<Image>,
    handle: CK_SESSION_HANDLE,
    client: &Module,
    token: &TokenIdentity,
    pins: &Credentials,
    cleanup: &mut Vec<Failure>,
) -> Answer<()> {
    let subject = client.select(token)?.open_session(true)?;
    let authentication = Authentication {
        participant,
        session: work,
        image,
        handle,
        pin: Arc::new(Mutex::new(Zeroizing::new(pins.user.to_vec()))),
    };
    let mut objects = Vec::new();
    let mut logged = false;
    let body = (|| -> Answer<()> {
        subject.login_as(LoginRole::User, SecretPin::new(pins.user.to_vec()))?;
        logged = true;
        objects.push(create(&subject, true)?);
        objects.push(create(&subject, false)?);
        subject.logout()?;
        logged = false;
        if subject.info()?.state != CKS_RW_PUBLIC_SESSION as u64 {
            return Err(Failure::Oracle("peer_initial_public_state"));
        }
        authentication.call(client, true, &mut logged)?;
        if subject.info()?.state != CKS_RW_USER_FUNCTIONS as u64 {
            return Err(Failure::Oracle("peer_login_not_visible"));
        }
        let digest = subject.digest_multipart(
            HashAlgorithm::Sha256,
            &[b"abc"],
            InputLimits {
                maximum_parts: 1,
                maximum_total_bytes: 3,
            },
        )?;
        let expected = hex(
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad",
            32,
        )
        .map_err(Failure::Input)?;
        if digest.as_bytes() != expected {
            return Err(Failure::Oracle("peer_digest_before_logout"));
        }
        authentication.call(client, false, &mut logged)?;
        if subject.info()?.state != CKS_RW_PUBLIC_SESSION as u64 {
            return Err(Failure::Oracle("peer_logout_not_visible"));
        }
        // A completed byte owner is independent of a later token login change.
        if digest.as_bytes() != expected {
            return Err(Failure::Oracle("peer_logout_changed_completed_digest"));
        }
        for object in &objects {
            let read = subject.read_flat_attribute(
                object,
                StandardAttribute::VALUE,
                FlatAttributeReadPlan::Buffer { capacity: 3 },
            )?;
            if read.calls
                != (AttributeReadCalls::Direct {
                    code: CKR_OK as u64,
                })
            {
                return Err(Failure::Oracle("peer_object_read_return"));
            }
            match read.value {
                FlatAttributeValue::Available(value) if value.as_bytes() == b"abc" => (),
                _ => return Err(Failure::Oracle("peer_public_object_changed")),
            }
        }
        Ok(())
    })();
    for object in &objects {
        if let Err(error) = subject.destroy_native_object(object) {
            cleanup.push(error.into());
        }
    }
    if logged {
        if let Err(error) = authentication.call(client, false, &mut logged) {
            cleanup.push(error);
        }
    }
    if let Err(error) = subject.close() {
        cleanup.push(error.into());
    }
    body
}
