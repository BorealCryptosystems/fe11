// SPDX-License-Identifier: Apache-2.0
//! Attribute ABI categories from the PKCS#11 object tables, independent of
//! whether a module accepts a particular attribute value on an object.
use fe11::{AttributeLayout, AttributeType, StandardAttribute};

#[test]
fn normative_attribute_shapes_and_standard_identity() {
    let expected = [
        (
            StandardAttribute::ALLOWED_MECHANISMS,
            AttributeLayout::UnsignedArray,
            fe11_sys::CKA_ALLOWED_MECHANISMS as u64,
        ),
        (
            StandardAttribute::ALWAYS_AUTHENTICATE,
            AttributeLayout::Boolean,
            fe11_sys::CKA_ALWAYS_AUTHENTICATE as u64,
        ),
        (
            StandardAttribute::ALWAYS_SENSITIVE,
            AttributeLayout::Boolean,
            fe11_sys::CKA_ALWAYS_SENSITIVE as u64,
        ),
        (
            StandardAttribute::APPLICATION,
            AttributeLayout::Bytes,
            fe11_sys::CKA_APPLICATION as u64,
        ),
        (
            StandardAttribute::BASE,
            AttributeLayout::Bytes,
            fe11_sys::CKA_BASE as u64,
        ),
        (
            StandardAttribute::CERTIFICATE_CATEGORY,
            AttributeLayout::Unsigned,
            fe11_sys::CKA_CERTIFICATE_CATEGORY as u64,
        ),
        (
            StandardAttribute::CERTIFICATE_TYPE,
            AttributeLayout::Unsigned,
            fe11_sys::CKA_CERTIFICATE_TYPE as u64,
        ),
        (
            StandardAttribute::CHECK_VALUE,
            AttributeLayout::Bytes,
            fe11_sys::CKA_CHECK_VALUE as u64,
        ),
        (
            StandardAttribute::CLASS,
            AttributeLayout::Unsigned,
            fe11_sys::CKA_CLASS as u64,
        ),
        (
            StandardAttribute::COEFFICIENT,
            AttributeLayout::Bytes,
            fe11_sys::CKA_COEFFICIENT as u64,
        ),
        (
            StandardAttribute::COPYABLE,
            AttributeLayout::Boolean,
            fe11_sys::CKA_COPYABLE as u64,
        ),
        (
            StandardAttribute::DECAPSULATE,
            AttributeLayout::Boolean,
            fe11_sys::CKA_DECAPSULATE as u64,
        ),
        (
            StandardAttribute::DECRYPT,
            AttributeLayout::Boolean,
            fe11_sys::CKA_DECRYPT as u64,
        ),
        (
            StandardAttribute::DERIVE,
            AttributeLayout::Boolean,
            fe11_sys::CKA_DERIVE as u64,
        ),
        (
            StandardAttribute::DERIVE_TEMPLATE,
            AttributeLayout::Template,
            fe11_sys::CKA_DERIVE_TEMPLATE as u64,
        ),
        (
            StandardAttribute::DESTROYABLE,
            AttributeLayout::Boolean,
            fe11_sys::CKA_DESTROYABLE as u64,
        ),
        (
            StandardAttribute::EC_PARAMS,
            AttributeLayout::Bytes,
            fe11_sys::CKA_EC_PARAMS as u64,
        ),
        (
            StandardAttribute::EC_POINT,
            AttributeLayout::Bytes,
            fe11_sys::CKA_EC_POINT as u64,
        ),
        (
            StandardAttribute::ENCAPSULATE,
            AttributeLayout::Boolean,
            fe11_sys::CKA_ENCAPSULATE as u64,
        ),
        (
            StandardAttribute::ENCRYPT,
            AttributeLayout::Boolean,
            fe11_sys::CKA_ENCRYPT as u64,
        ),
        (
            StandardAttribute::END_DATE,
            AttributeLayout::Date,
            fe11_sys::CKA_END_DATE as u64,
        ),
        (
            StandardAttribute::EXPONENT_1,
            AttributeLayout::Bytes,
            fe11_sys::CKA_EXPONENT_1 as u64,
        ),
        (
            StandardAttribute::EXPONENT_2,
            AttributeLayout::Bytes,
            fe11_sys::CKA_EXPONENT_2 as u64,
        ),
        (
            StandardAttribute::EXTRACTABLE,
            AttributeLayout::Boolean,
            fe11_sys::CKA_EXTRACTABLE as u64,
        ),
        (
            StandardAttribute::GOST28147_PARAMS,
            AttributeLayout::Bytes,
            fe11_sys::CKA_GOST28147_PARAMS as u64,
        ),
        (
            StandardAttribute::GOSTR3410_PARAMS,
            AttributeLayout::Bytes,
            fe11_sys::CKA_GOSTR3410_PARAMS as u64,
        ),
        (
            StandardAttribute::GOSTR3411_PARAMS,
            AttributeLayout::Bytes,
            fe11_sys::CKA_GOSTR3411_PARAMS as u64,
        ),
        (
            StandardAttribute::HASH_OF_ISSUER_PUBLIC_KEY,
            AttributeLayout::Bytes,
            fe11_sys::CKA_HASH_OF_ISSUER_PUBLIC_KEY as u64,
        ),
        (
            StandardAttribute::HASH_OF_SUBJECT_PUBLIC_KEY,
            AttributeLayout::Bytes,
            fe11_sys::CKA_HASH_OF_SUBJECT_PUBLIC_KEY as u64,
        ),
        (
            StandardAttribute::ID,
            AttributeLayout::Bytes,
            fe11_sys::CKA_ID as u64,
        ),
        (
            StandardAttribute::ISSUER,
            AttributeLayout::Bytes,
            fe11_sys::CKA_ISSUER as u64,
        ),
        (
            StandardAttribute::JAVA_MIDP_SECURITY_DOMAIN,
            AttributeLayout::Unsigned,
            fe11_sys::CKA_JAVA_MIDP_SECURITY_DOMAIN as u64,
        ),
        (
            StandardAttribute::KEY_GEN_MECHANISM,
            AttributeLayout::Unsigned,
            fe11_sys::CKA_KEY_GEN_MECHANISM as u64,
        ),
        (
            StandardAttribute::KEY_TYPE,
            AttributeLayout::Unsigned,
            fe11_sys::CKA_KEY_TYPE as u64,
        ),
        (
            StandardAttribute::LABEL,
            AttributeLayout::Bytes,
            fe11_sys::CKA_LABEL as u64,
        ),
        (
            StandardAttribute::LOCAL,
            AttributeLayout::Boolean,
            fe11_sys::CKA_LOCAL as u64,
        ),
        (
            StandardAttribute::MODIFIABLE,
            AttributeLayout::Boolean,
            fe11_sys::CKA_MODIFIABLE as u64,
        ),
        (
            StandardAttribute::MODULUS,
            AttributeLayout::Bytes,
            fe11_sys::CKA_MODULUS as u64,
        ),
        (
            StandardAttribute::MODULUS_BITS,
            AttributeLayout::Unsigned,
            fe11_sys::CKA_MODULUS_BITS as u64,
        ),
        (
            StandardAttribute::NAME_HASH_ALGORITHM,
            AttributeLayout::Unsigned,
            fe11_sys::CKA_NAME_HASH_ALGORITHM as u64,
        ),
        (
            StandardAttribute::NEVER_EXTRACTABLE,
            AttributeLayout::Boolean,
            fe11_sys::CKA_NEVER_EXTRACTABLE as u64,
        ),
        (
            StandardAttribute::OBJECT_ID,
            AttributeLayout::Bytes,
            fe11_sys::CKA_OBJECT_ID as u64,
        ),
        (
            StandardAttribute::OBJECT_VALIDATION_FLAGS,
            AttributeLayout::Unsigned,
            fe11_sys::CKA_OBJECT_VALIDATION_FLAGS as u64,
        ),
        (
            StandardAttribute::PARAMETER_SET,
            AttributeLayout::Unsigned,
            fe11_sys::CKA_PARAMETER_SET as u64,
        ),
        (
            StandardAttribute::PRIME,
            AttributeLayout::Bytes,
            fe11_sys::CKA_PRIME as u64,
        ),
        (
            StandardAttribute::PRIME_1,
            AttributeLayout::Bytes,
            fe11_sys::CKA_PRIME_1 as u64,
        ),
        (
            StandardAttribute::PRIME_2,
            AttributeLayout::Bytes,
            fe11_sys::CKA_PRIME_2 as u64,
        ),
        (
            StandardAttribute::PRIME_BITS,
            AttributeLayout::Unsigned,
            fe11_sys::CKA_PRIME_BITS as u64,
        ),
        (
            StandardAttribute::PRIVATE,
            AttributeLayout::Boolean,
            fe11_sys::CKA_PRIVATE as u64,
        ),
        (
            StandardAttribute::PRIVATE_EXPONENT,
            AttributeLayout::Bytes,
            fe11_sys::CKA_PRIVATE_EXPONENT as u64,
        ),
        (
            StandardAttribute::PUBLIC_CRC64_VALUE,
            AttributeLayout::Bytes,
            fe11_sys::CKA_PUBLIC_CRC64_VALUE as u64,
        ),
        (
            StandardAttribute::PUBLIC_EXPONENT,
            AttributeLayout::Bytes,
            fe11_sys::CKA_PUBLIC_EXPONENT as u64,
        ),
        (
            StandardAttribute::PUBLIC_KEY_INFO,
            AttributeLayout::Bytes,
            fe11_sys::CKA_PUBLIC_KEY_INFO as u64,
        ),
        (
            StandardAttribute::SEED,
            AttributeLayout::Bytes,
            fe11_sys::CKA_SEED as u64,
        ),
        (
            StandardAttribute::SENSITIVE,
            AttributeLayout::Boolean,
            fe11_sys::CKA_SENSITIVE as u64,
        ),
        (
            StandardAttribute::SERIAL_NUMBER,
            AttributeLayout::Bytes,
            fe11_sys::CKA_SERIAL_NUMBER as u64,
        ),
        (
            StandardAttribute::SIGN,
            AttributeLayout::Boolean,
            fe11_sys::CKA_SIGN as u64,
        ),
        (
            StandardAttribute::SIGN_RECOVER,
            AttributeLayout::Boolean,
            fe11_sys::CKA_SIGN_RECOVER as u64,
        ),
        (
            StandardAttribute::START_DATE,
            AttributeLayout::Date,
            fe11_sys::CKA_START_DATE as u64,
        ),
        (
            StandardAttribute::SUBJECT,
            AttributeLayout::Bytes,
            fe11_sys::CKA_SUBJECT as u64,
        ),
        (
            StandardAttribute::SUBPRIME,
            AttributeLayout::Bytes,
            fe11_sys::CKA_SUBPRIME as u64,
        ),
        (
            StandardAttribute::TOKEN,
            AttributeLayout::Boolean,
            fe11_sys::CKA_TOKEN as u64,
        ),
        (
            StandardAttribute::TRUSTED,
            AttributeLayout::Boolean,
            fe11_sys::CKA_TRUSTED as u64,
        ),
        (
            StandardAttribute::UNIQUE_ID,
            AttributeLayout::Bytes,
            fe11_sys::CKA_UNIQUE_ID as u64,
        ),
        (
            StandardAttribute::UNWRAP,
            AttributeLayout::Boolean,
            fe11_sys::CKA_UNWRAP as u64,
        ),
        (
            StandardAttribute::UNWRAP_TEMPLATE,
            AttributeLayout::Template,
            fe11_sys::CKA_UNWRAP_TEMPLATE as u64,
        ),
        (
            StandardAttribute::URL,
            AttributeLayout::Bytes,
            fe11_sys::CKA_URL as u64,
        ),
        (
            StandardAttribute::VALUE,
            AttributeLayout::Bytes,
            fe11_sys::CKA_VALUE as u64,
        ),
        (
            StandardAttribute::VALUE_BITS,
            AttributeLayout::Unsigned,
            fe11_sys::CKA_VALUE_BITS as u64,
        ),
        (
            StandardAttribute::VALUE_LEN,
            AttributeLayout::Unsigned,
            fe11_sys::CKA_VALUE_LEN as u64,
        ),
        (
            StandardAttribute::VERIFY,
            AttributeLayout::Boolean,
            fe11_sys::CKA_VERIFY as u64,
        ),
        (
            StandardAttribute::VERIFY_RECOVER,
            AttributeLayout::Boolean,
            fe11_sys::CKA_VERIFY_RECOVER as u64,
        ),
        (
            StandardAttribute::WRAP,
            AttributeLayout::Boolean,
            fe11_sys::CKA_WRAP as u64,
        ),
        (
            StandardAttribute::WRAP_TEMPLATE,
            AttributeLayout::Template,
            fe11_sys::CKA_WRAP_TEMPLATE as u64,
        ),
        (
            StandardAttribute::WRAP_WITH_TRUSTED,
            AttributeLayout::Boolean,
            fe11_sys::CKA_WRAP_WITH_TRUSTED as u64,
        ),
    ];
    assert_eq!(expected.len(), 75);
    for (attribute, layout, identifier) in expected {
        assert_eq!(attribute.layout(), layout, "{}", attribute.name());
        let selected = AttributeType::from(attribute);
        assert_eq!(selected.layout(), layout);
        assert_eq!(selected.identifier(), identifier);
        assert_eq!(selected.standard(), Some(attribute));
        assert_eq!(selected, attribute);
        assert_eq!(attribute, selected);
    }
}

#[test]
fn native_fixed_widths_and_variable_representations() {
    assert_eq!(AttributeLayout::Boolean.fixed_size(), Some(1));
    assert_eq!(AttributeLayout::Date.fixed_size(), Some(8));
    assert_eq!(AttributeLayout::Version.fixed_size(), Some(2));
    // PKCS#11 uses C unsigned long: LLP64 on Windows, LP64 on Unix x64.
    let unsigned_width = if cfg!(target_os = "windows") { 4 } else { 8 };
    assert_eq!(std::mem::size_of::<fe11_sys::CK_ULONG>(), unsigned_width);
    assert_eq!(AttributeLayout::Unsigned.fixed_size(), Some(unsigned_width));
    for variable in [
        AttributeLayout::Bytes,
        AttributeLayout::UnsignedArray,
        AttributeLayout::Template,
    ] {
        assert_eq!(variable.fixed_size(), None);
    }
}
