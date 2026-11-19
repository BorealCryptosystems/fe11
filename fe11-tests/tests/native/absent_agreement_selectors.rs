// SPDX-License-Identifier: Apache-2.0
//! Observe the selected agreement or key transport using independent, compatible key objects.
use super::{
    legacy, module_controls, refusal, select_token, Budgets, Configuration, Failure, Owner, Report,
};
use crate::{derived_value, key_wrap_fixture};
use fe11::*;
use fe11_sys::*;
use std::io::{self, Write};

#[path = "absent_agreement_keys.rs"]
mod keys;

pub(in super::super) fn execute<W: Write>(
    config: &Configuration,
    selector: &str,
    mut report: Report<W>,
) -> io::Result<bool> {
    let mut module = None;
    let mut owner = None;
    let mut objects = Vec::new();
    let mut derived = None;
    let setup = (|| -> std::result::Result<(), Failure> {
        let number = match selector {
            "cofactor" => CKM_ECDH1_COFACTOR_DERIVE,
            "mqv" => CKM_ECMQV_DERIVE,
            "public-from-private" => CKM_PUB_KEY_FROM_PRIV_KEY,
            "ecdh-wrap" => CKM_ECDH_AES_KEY_WRAP,
            "cofactor-wrap" => CKM_ECDH_COF_AES_KEY_WRAP,
            "gost-private-destination" | "gost-secret-destination" => CKM_GOSTR3410_DERIVE,
            "gost-wrap" => CKM_GOSTR3410_KEY_WRAP,
            _ => return Err(Failure::Input("unknown_agreement_selector")),
        };
        module = Some(config.open(&Budgets::ordinary())?);
        let m = module.as_ref().ok_or(Failure::Input("agreement_module"))?;
        let token = select_token(m, &config.label).ok_or(Failure::Input("agreement_token"))?;
        if m.mechanism_ids(token.slot)?.contains(&(number as u64)) {
            return Err(Failure::Oracle("unexpected_agreement_catalogue"));
        }
        owner = Some(Owner::open(m, config, false)?);
        let o = owner.as_ref().ok_or(Failure::Input("agreement_owner"))?;
        match selector {
            "cofactor" | "public-from-private" => objects.push(keys::ec_private(o, 1, false)?),
            "mqv" => {
                objects.push(keys::ec_private(o, 1, false)?);
                objects.push(keys::ec_private(o, 2, false)?);
                objects.push(keys::ec_public(
                    o,
                    &keys::point(0)?,
                    StandardAttribute::DERIVE,
                )?);
            }
            "ecdh-wrap" | "cofactor-wrap" => {
                objects.push(keys::ec_public(
                    o,
                    &keys::point(1)?,
                    StandardAttribute::WRAP,
                )?);
                objects.push(keys::ec_private(o, 1, true)?);
            }
            "gost-private-destination" | "gost-secret-destination" => {
                objects.push(keys::gost(o, true)?);
            }
            "gost-wrap" => {
                objects.push(keys::gost(o, false)?);
                objects.push(keys::gost(o, true)?);
                objects.push(legacy::secret(
                    o,
                    CKK_GOST28147,
                    b"0123456789abcdef0123456789abcdef",
                    StandardAttribute::ENCRYPT,
                    true,
                )?);
            }
            _ => return Err(Failure::Input("agreement_setup")),
        }
        Ok(())
    })();
    let body = (|| -> std::result::Result<(), Failure> {
        if setup.is_err() {
            return Ok(());
        }
        let Some(Owner::Session(session)) = &owner else {
            return Err(Failure::Input("agreement_session"));
        };
        let object = |i: usize| objects.get(i).ok_or(Failure::Input("agreement_object"));
        if matches!(selector, "ecdh-wrap" | "cofactor-wrap" | "gost-wrap") {
            let (p, target) = match selector {
                "gost-wrap" => (
                    NativeTransportParameters::GostR3410 {
                        oid: Some(legacy::GOST_PARAMETERS),
                        ukm: Some(&[1, 2, 3, 4, 5, 6, 7, 8]),
                        key: object(1)?,
                    },
                    object(2)?,
                ),
                "cofactor-wrap" => (
                    NativeTransportParameters::EcdhAesCofactor {
                        aes_key_bits: 128,
                        kdf: CKD_SHA256_KDF as u64,
                        shared: None,
                    },
                    object(1)?,
                ),
                _ => (
                    NativeTransportParameters::EcdhAes {
                        aes_key_bits: 128,
                        kdf: CKD_SHA256_KDF as u64,
                        shared: None,
                    },
                    object(1)?,
                ),
            };
            return refusal(
                session.wrap_native_key(object(0)?, target, p, 1024),
                "C_WrapKey",
                &mut report,
            );
        }
        if matches!(selector, "gost-private-destination" | "gost-secret-destination") {
            let class = if selector == "gost-private-destination" {
                CKO_PRIVATE_KEY
            } else {
                CKO_SECRET_KEY
            };
            // The isolated token contains exactly one private object and no secret keys.
            // With batch size one, the private search needs a second, empty batch.
            // This observes the class used before the module rejects the mechanism.
            let attributes = [keys::attr(
                StandardAttribute::CLASS,
                AttributeInputValue::Unsigned(class as u64),
            )];
            let fields = std::collections::BTreeSet::from([IdentityAttribute::Class]);
            let template = GenerationTemplate {
                attributes: &attributes,
                limits: key_wrap_fixture::limits(1, 8),
                observation: None,
                destination: DestinationPlan {
                    search: DestinationSearchPlan::Observe {
                        template: ReferenceTemplate::Fields(fields.into()),
                        resources: SearchPlan {
                            maximum_objects: Some(2),
                            batch_size: std::num::NonZeroUsize::MIN,
                        },
                        source: DestinationSource::Include,
                    },
                    user: DestinationUserObservation::NotRequested,
                },
            };
            let peer = keys::gost_peer()?;
            let parameters = NativeKeyDerivation::GostR3410 {
                kdf: CKD_NULL as u64,
                peer_public: &peer,
                ukm: Some(&[1, 2, 3, 4, 5, 6, 7, 8]),
            };
            return match session.derive_native_key(object(0)?, parameters, template) {
                Err(error) => refusal::<(), _>(Err(error), "C_DeriveKey", &mut report),
                Ok(created) => {
                    derived = Some(created.objects);
                    Err(Failure::Oracle("unexpected_gost_derivation"))
                }
            };
        }
        let peer = keys::point(1)?;
        let peer_ephemeral = keys::point(2)?;
        let p = match selector {
            "cofactor" => NativeKeyDerivation::Ecdh {
                cofactor: true,
                kdf: CKD_NULL as u64,
                peer_public: &peer,
                shared_data: None,
            },
            "public-from-private" => NativeKeyDerivation::PublicFromPrivate,
            "mqv" => NativeKeyDerivation::Ecmqv {
                agreement: NativeTwoPairAgreement {
                    kdf: CKD_NULL as u64,
                    peer_public: &peer,
                    peer_public_second: &peer_ephemeral,
                    private_second: object(1)?,
                    private_second_bytes: 32,
                    context: None,
                },
                layout: NativeMqvLayout::WithPublicKey(object(2)?),
            },
            _ => return Err(Failure::Input("agreement_derive")),
        };
        // A public key derived from a private key takes its mathematical parameters
        // from the base object. The explicit destroyable flag allows cleanup on success.
        let pub_fields = [
            keys::attr(
                StandardAttribute::DESTROYABLE,
                AttributeInputValue::Boolean(true),
            ),
            keys::attr(
                StandardAttribute::TOKEN,
                AttributeInputValue::Boolean(false),
            ),
        ];
        let secret_fields = derived_value::template_attributes(16);
        let fields = if selector == "public-from-private" {
            pub_fields.as_slice()
        } else {
            secret_fields.as_slice()
        };
        let request = GenerationTemplate {
            attributes: fields,
            limits: key_wrap_fixture::limits(fields.len(), 128),
            observation: None,
            destination: DestinationPlan {
                search: DestinationSearchPlan::NotRequested,
                user: DestinationUserObservation::NotRequested,
            },
        };
        let result = session.derive_native_key(object(0)?, p, request);
        match result {
            Err(error) => refusal::<(), _>(Err(error), "C_DeriveKey", &mut report),
            Ok(created) => {
                derived = Some(created.objects);
                Err(Failure::Oracle("unexpected_agreement_success"))
            }
        }
    })();
    let mut cleanup = Vec::new();
    if let Some(o) = &owner {
        if let Some(set) = &derived {
            for key in set.as_slice() {
                if let Err(error) = key_wrap_fixture::destroy(o, key) {
                    cleanup.push(error.into());
                }
            }
        }
        for key in objects.iter().rev() {
            if let Err(error) = key_wrap_fixture::destroy(o, key) {
                cleanup.push(error.into());
            }
        }
        cleanup.extend(o.close(None));
    }
    drop(derived);
    drop(objects);
    drop(owner);
    if let Some(m) = module {
        if let Err(error) = m.close() {
            cleanup.push(error.into());
        }
    }
    module_controls::finish(report, setup, body, cleanup)
}
