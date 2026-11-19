// SPDX-License-Identifier: Apache-2.0
//! Public P-256 and GOST inputs for negative key-agreement and key-transport calls.
use super::{Failure, Owner};
use crate::arguments::hex;
use fe11::*;
use fe11_sys::*;

const P256: &[u8] = &[6, 8, 42, 134, 72, 206, 61, 3, 1, 7];
// SEC 2 secp256r1, uncompressed encodings of 2G, 3G and 4G.
// The two local scalars are 1 and 2. The two peer public points are 3G and 4G.
const POINTS: [&str;3] = [
    "047cf27b188d034f7e8a52380304b51ac3c08969e277f21b35a60b48fc4766997807775510db8ed040293d9ac69f7430dbba7dade63ce982299e04b79d227873d1",
    "045ecbe4d1a6330a44c8f7ef951d4bf165e6c6b721efada985fb41661bc6e7fd6c8734640c4998ff7e374b06ce1a64a2ecd82ab036384fb83d9a79b127a27d5032",
    "04e2534a3532d08fbba02dde659ee62bd0031fe2db785596ef509302446b030852e0f1575a4c633cc719dfee5fda862d764efc96c3f30ee0055c42c23f184ed8c6",
];
pub(super) fn point(index: usize) -> std::result::Result<Vec<u8>, Failure> {
    let encoded = POINTS.get(index).ok_or(Failure::Input("agreement_point"))?;
    hex(encoded, 65).map_err(Failure::Input)
}

pub(super) fn attr<'a>(
    attribute: StandardAttribute,
    value: AttributeInputValue<'a>,
) -> AttributeInput<'a> {
    AttributeInput {
        attribute: attribute.into(),
        value,
    }
}
fn asymmetric(
    owner: &Owner,
    class: CK_OBJECT_CLASS,
    kind: CK_KEY_TYPE,
    usage: StandardAttribute,
    extractable: bool,
    material: Vec<AttributeInput<'_>>,
) -> fe11::Result<NativeObjectRef> {
    let mut fields = vec![
        attr(
            StandardAttribute::CLASS,
            AttributeInputValue::Unsigned(class as u64),
        ),
        attr(
            StandardAttribute::KEY_TYPE,
            AttributeInputValue::Unsigned(kind as u64),
        ),
        attr(
            StandardAttribute::TOKEN,
            AttributeInputValue::Boolean(false),
        ),
        attr(
            StandardAttribute::PRIVATE,
            AttributeInputValue::Boolean(false),
        ),
        attr(usage, AttributeInputValue::Boolean(true)),
    ];
    if class == CKO_PRIVATE_KEY {
        fields.push(attr(
            StandardAttribute::EXTRACTABLE,
            AttributeInputValue::Boolean(extractable),
        ));
    }
    fields.extend(material);
    owner.create(
        &fields,
        AttributeTemplateLimits {
            maximum_depth: 0,
            maximum_attributes: fields.len(),
            maximum_value_bytes: 256,
        },
    )
}

pub(super) fn ec_private(
    owner: &Owner,
    scalar: u8,
    extractable: bool,
) -> fe11::Result<NativeObjectRef> {
    let mut bytes = [0u8; 32];
    bytes[31] = scalar;
    asymmetric(
        owner,
        CKO_PRIVATE_KEY,
        CKK_EC,
        StandardAttribute::DERIVE,
        extractable,
        vec![
            attr(
                StandardAttribute::EC_PARAMS,
                AttributeInputValue::Bytes(P256),
            ),
            attr(StandardAttribute::VALUE, AttributeInputValue::Bytes(&bytes)),
        ],
    )
}
pub(super) fn ec_public(
    owner: &Owner,
    raw: &[u8],
    usage: StandardAttribute,
) -> fe11::Result<NativeObjectRef> {
    // CKA_EC_POINT contains a DER OCTET STRING. Derive mechanism parameters use the raw point.
    let mut der = vec![4, 65];
    der.extend_from_slice(raw);
    asymmetric(
        owner,
        CKO_PUBLIC_KEY,
        CKK_EC,
        usage,
        false,
        vec![
            attr(
                StandardAttribute::EC_PARAMS,
                AttributeInputValue::Bytes(P256),
            ),
            attr(
                StandardAttribute::EC_POINT,
                AttributeInputValue::Bytes(&der),
            ),
        ],
    )
}
/// CryptoPro-A base point G in the little-endian x || y encoding.
pub(super) fn gost_peer() -> std::result::Result<Vec<u8>, Failure> {
    hex(
        "0100000000000000000000000000000000000000000000000000000000000000141e9f9e9cc9ac22b1e323df2d4f2935762b3f455a50df27da9c98e071e4918d",
        64,
    )
    .map_err(Failure::Input)
}

pub(super) fn gost(owner: &Owner, sender: bool) -> std::result::Result<NativeObjectRef, Failure> {
    use crate::absent_mechanism_fixture::{CURVE_OID, DIGEST_OID};
    // CryptoPro-A: recipient public point G in native little-endian x || y,
    // sender private scalar 2. Both are public fixture data (RFC 4357).
    let mut scalar = [0u8; 32];
    scalar[0] = 2;
    let public = gost_peer()?;
    let (class, usage, bytes) = if sender {
        (
            CKO_PRIVATE_KEY,
            StandardAttribute::DERIVE,
            scalar.as_slice(),
        )
    } else {
        (CKO_PUBLIC_KEY, StandardAttribute::WRAP, public.as_slice())
    };
    Ok(asymmetric(
        owner,
        class,
        CKK_GOSTR3410,
        usage,
        false,
        vec![
            attr(
                StandardAttribute::GOSTR3410_PARAMS,
                AttributeInputValue::Bytes(CURVE_OID),
            ),
            attr(
                StandardAttribute::GOSTR3411_PARAMS,
                AttributeInputValue::Bytes(DIGEST_OID),
            ),
            attr(StandardAttribute::VALUE, AttributeInputValue::Bytes(bytes)),
        ],
    )?)
}
