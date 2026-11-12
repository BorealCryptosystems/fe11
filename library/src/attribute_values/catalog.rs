// SPDX-License-Identifier: Apache-2.0
//! Standard PKCS#11 attribute names and ABI shapes from the published headers.
//! Keep aliases and ABI shape distinct from operation support and object policy.
use fe11_sys::*;

/// ABI representation of a standard attribute, independent of its availability.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum AttributeLayout {
    /// CK_BBOOL: one byte, decoded only after checking its value.
    Boolean,
    /// CK_ULONG or a native enum/flag typedef of that width.
    Unsigned,
    /// Flat bytes, including encoded big integers and strings; no pointers.
    Bytes,
    /// CK_DATE's eight character bytes; calendar policy is not inferred.
    Date,
    /// CK_VERSION's major and minor bytes.
    Version,
    /// A flat array of CK_ULONG-compatible native identifiers or values.
    UnsignedArray,
    /// An array of CK_ATTRIBUTE with recursively owned referents.
    Template,
}
impl AttributeLayout {
    /// Known native width, when the representation has one. This is independent
    /// of whether an object exposes the attribute or a module accepts its read.
    pub fn fixed_size(self) -> Option<usize> {
        match self {
            Self::Boolean => Some(std::mem::size_of::<CK_BBOOL>()),
            Self::Unsigned => Some(std::mem::size_of::<CK_ULONG>()),
            Self::Date => Some(std::mem::size_of::<CK_DATE>()),
            Self::Version => Some(std::mem::size_of::<CK_VERSION>()),
            Self::Bytes | Self::UnsignedArray | Self::Template => None,
        }
    }
}

/// Standard CKA identity with its reviewed ABI shape. A name is not a capability.
/// Aliases compare equal by native identifier; lookup returns the first name.
#[derive(Clone, Copy, Debug)]
pub struct StandardAttribute {
    kind: CK_ATTRIBUTE_TYPE,
    name: &'static str,
    layout: AttributeLayout,
}
impl PartialEq for StandardAttribute {
    fn eq(&self, other: &Self) -> bool {
        self.kind == other.kind
    }
}
impl Eq for StandardAttribute {}
impl StandardAttribute {
    /// Exact standard identifier, widened without changing its value.
    pub fn identifier(self) -> u64 {
        self.kind as u64
    }
    /// Header spelling of this identity, including an explicitly chosen alias.
    pub fn name(self) -> &'static str {
        self.name
    }
    /// Normative ABI shape; this does not assert semantic validity of a value.
    pub fn layout(self) -> AttributeLayout {
        self.layout
    }
    /// Look up a current standard identity. Unknown values, the vendor marker
    /// and the two deferred KEM templates are not promoted to typed attributes.
    pub fn from_identifier(identifier: u64) -> Option<Self> {
        let kind = CK_ATTRIBUTE_TYPE::try_from(identifier).ok()?;
        Self::ALL
            .iter()
            .copied()
            .find(|attribute| attribute.kind == kind)
    }
    pub(super) fn native(self) -> CK_ATTRIBUTE_TYPE {
        self.kind
    }
}
macro_rules! attributes {
    ($($name:ident => $native:ident, $layout:ident;)+) => {
        impl StandardAttribute {
            $(
                #[doc = concat!(stringify!($native), "; ABI shape: ", stringify!($layout), ".")]
                pub const $name: Self = Self {
                    kind: $native,
                    name: stringify!($native),
                    layout: AttributeLayout::$layout,
                };
            )+
            /// Current standard names, retaining aliases. No native discovery occurs.
            pub const ALL: &'static [Self] = &[$(Self::$name,)+];
        }
    };
}
attributes! {
    CLASS => CKA_CLASS, Unsigned;
    TOKEN => CKA_TOKEN, Boolean;
    PRIVATE => CKA_PRIVATE, Boolean;
    LABEL => CKA_LABEL, Bytes;
    UNIQUE_ID => CKA_UNIQUE_ID, Bytes;
    APPLICATION => CKA_APPLICATION, Bytes;
    VALUE => CKA_VALUE, Bytes;
    OBJECT_ID => CKA_OBJECT_ID, Bytes;
    CERTIFICATE_TYPE => CKA_CERTIFICATE_TYPE, Unsigned;
    ISSUER => CKA_ISSUER, Bytes;
    SERIAL_NUMBER => CKA_SERIAL_NUMBER, Bytes;
    AC_ISSUER => CKA_AC_ISSUER, Bytes;
    OWNER => CKA_OWNER, Bytes;
    ATTR_TYPES => CKA_ATTR_TYPES, Bytes;
    TRUSTED => CKA_TRUSTED, Boolean;
    CERTIFICATE_CATEGORY => CKA_CERTIFICATE_CATEGORY, Unsigned;
    JAVA_MIDP_SECURITY_DOMAIN => CKA_JAVA_MIDP_SECURITY_DOMAIN, Unsigned;
    URL => CKA_URL, Bytes;
    HASH_OF_SUBJECT_PUBLIC_KEY => CKA_HASH_OF_SUBJECT_PUBLIC_KEY, Bytes;
    HASH_OF_ISSUER_PUBLIC_KEY => CKA_HASH_OF_ISSUER_PUBLIC_KEY, Bytes;
    NAME_HASH_ALGORITHM => CKA_NAME_HASH_ALGORITHM, Unsigned;
    CHECK_VALUE => CKA_CHECK_VALUE, Bytes;
    KEY_TYPE => CKA_KEY_TYPE, Unsigned;
    SUBJECT => CKA_SUBJECT, Bytes;
    ID => CKA_ID, Bytes;
    SENSITIVE => CKA_SENSITIVE, Boolean;
    ENCRYPT => CKA_ENCRYPT, Boolean;
    DECRYPT => CKA_DECRYPT, Boolean;
    WRAP => CKA_WRAP, Boolean;
    UNWRAP => CKA_UNWRAP, Boolean;
    SIGN => CKA_SIGN, Boolean;
    SIGN_RECOVER => CKA_SIGN_RECOVER, Boolean;
    VERIFY => CKA_VERIFY, Boolean;
    VERIFY_RECOVER => CKA_VERIFY_RECOVER, Boolean;
    DERIVE => CKA_DERIVE, Boolean;
    START_DATE => CKA_START_DATE, Date;
    END_DATE => CKA_END_DATE, Date;
    MODULUS => CKA_MODULUS, Bytes;
    MODULUS_BITS => CKA_MODULUS_BITS, Unsigned;
    PUBLIC_EXPONENT => CKA_PUBLIC_EXPONENT, Bytes;
    PRIVATE_EXPONENT => CKA_PRIVATE_EXPONENT, Bytes;
    PRIME_1 => CKA_PRIME_1, Bytes;
    PRIME_2 => CKA_PRIME_2, Bytes;
    EXPONENT_1 => CKA_EXPONENT_1, Bytes;
    EXPONENT_2 => CKA_EXPONENT_2, Bytes;
    COEFFICIENT => CKA_COEFFICIENT, Bytes;
    PUBLIC_KEY_INFO => CKA_PUBLIC_KEY_INFO, Bytes;
    PRIME => CKA_PRIME, Bytes;
    SUBPRIME => CKA_SUBPRIME, Bytes;
    BASE => CKA_BASE, Bytes;
    PRIME_BITS => CKA_PRIME_BITS, Unsigned;
    SUBPRIME_BITS => CKA_SUBPRIME_BITS, Unsigned;
    SUB_PRIME_BITS => CKA_SUB_PRIME_BITS, Unsigned;
    VALUE_BITS => CKA_VALUE_BITS, Unsigned;
    VALUE_LEN => CKA_VALUE_LEN, Unsigned;
    EXTRACTABLE => CKA_EXTRACTABLE, Boolean;
    LOCAL => CKA_LOCAL, Boolean;
    NEVER_EXTRACTABLE => CKA_NEVER_EXTRACTABLE, Boolean;
    ALWAYS_SENSITIVE => CKA_ALWAYS_SENSITIVE, Boolean;
    KEY_GEN_MECHANISM => CKA_KEY_GEN_MECHANISM, Unsigned;
    MODIFIABLE => CKA_MODIFIABLE, Boolean;
    COPYABLE => CKA_COPYABLE, Boolean;
    DESTROYABLE => CKA_DESTROYABLE, Boolean;
    ECDSA_PARAMS => CKA_ECDSA_PARAMS, Bytes;
    EC_PARAMS => CKA_EC_PARAMS, Bytes;
    EC_POINT => CKA_EC_POINT, Bytes;
    SECONDARY_AUTH => CKA_SECONDARY_AUTH, Boolean;
    AUTH_PIN_FLAGS => CKA_AUTH_PIN_FLAGS, Unsigned;
    ALWAYS_AUTHENTICATE => CKA_ALWAYS_AUTHENTICATE, Boolean;
    WRAP_WITH_TRUSTED => CKA_WRAP_WITH_TRUSTED, Boolean;
    WRAP_TEMPLATE => CKA_WRAP_TEMPLATE, Template;
    UNWRAP_TEMPLATE => CKA_UNWRAP_TEMPLATE, Template;
    DERIVE_TEMPLATE => CKA_DERIVE_TEMPLATE, Template;
    OTP_FORMAT => CKA_OTP_FORMAT, Unsigned;
    OTP_LENGTH => CKA_OTP_LENGTH, Unsigned;
    OTP_TIME_INTERVAL => CKA_OTP_TIME_INTERVAL, Unsigned;
    OTP_USER_FRIENDLY_MODE => CKA_OTP_USER_FRIENDLY_MODE, Boolean;
    OTP_CHALLENGE_REQUIREMENT => CKA_OTP_CHALLENGE_REQUIREMENT, Unsigned;
    OTP_TIME_REQUIREMENT => CKA_OTP_TIME_REQUIREMENT, Unsigned;
    OTP_COUNTER_REQUIREMENT => CKA_OTP_COUNTER_REQUIREMENT, Unsigned;
    OTP_PIN_REQUIREMENT => CKA_OTP_PIN_REQUIREMENT, Unsigned;
    OTP_COUNTER => CKA_OTP_COUNTER, Bytes;
    OTP_TIME => CKA_OTP_TIME, Bytes;
    OTP_USER_IDENTIFIER => CKA_OTP_USER_IDENTIFIER, Bytes;
    OTP_SERVICE_IDENTIFIER => CKA_OTP_SERVICE_IDENTIFIER, Bytes;
    OTP_SERVICE_LOGO => CKA_OTP_SERVICE_LOGO, Bytes;
    OTP_SERVICE_LOGO_TYPE => CKA_OTP_SERVICE_LOGO_TYPE, Bytes;
    GOSTR3410_PARAMS => CKA_GOSTR3410_PARAMS, Bytes;
    GOSTR3411_PARAMS => CKA_GOSTR3411_PARAMS, Bytes;
    GOST28147_PARAMS => CKA_GOST28147_PARAMS, Bytes;
    HW_FEATURE_TYPE => CKA_HW_FEATURE_TYPE, Unsigned;
    RESET_ON_INIT => CKA_RESET_ON_INIT, Boolean;
    HAS_RESET => CKA_HAS_RESET, Boolean;
    PIXEL_X => CKA_PIXEL_X, Unsigned;
    PIXEL_Y => CKA_PIXEL_Y, Unsigned;
    RESOLUTION => CKA_RESOLUTION, Unsigned;
    CHAR_ROWS => CKA_CHAR_ROWS, Unsigned;
    CHAR_COLUMNS => CKA_CHAR_COLUMNS, Unsigned;
    COLOR => CKA_COLOR, Boolean;
    BITS_PER_PIXEL => CKA_BITS_PER_PIXEL, Unsigned;
    CHAR_SETS => CKA_CHAR_SETS, Bytes;
    ENCODING_METHODS => CKA_ENCODING_METHODS, Bytes;
    MIME_TYPES => CKA_MIME_TYPES, Bytes;
    MECHANISM_TYPE => CKA_MECHANISM_TYPE, Unsigned;
    REQUIRED_CMS_ATTRIBUTES => CKA_REQUIRED_CMS_ATTRIBUTES, Bytes;
    DEFAULT_CMS_ATTRIBUTES => CKA_DEFAULT_CMS_ATTRIBUTES, Bytes;
    SUPPORTED_CMS_ATTRIBUTES => CKA_SUPPORTED_CMS_ATTRIBUTES, Bytes;
    ALLOWED_MECHANISMS => CKA_ALLOWED_MECHANISMS, UnsignedArray;
    PROFILE_ID => CKA_PROFILE_ID, Unsigned;
    X2RATCHET_BAG => CKA_X2RATCHET_BAG, Bytes;
    X2RATCHET_BAGSIZE => CKA_X2RATCHET_BAGSIZE, Unsigned;
    X2RATCHET_BOBS1STMSG => CKA_X2RATCHET_BOBS1STMSG, Boolean;
    X2RATCHET_CKR => CKA_X2RATCHET_CKR, Bytes;
    X2RATCHET_CKS => CKA_X2RATCHET_CKS, Bytes;
    X2RATCHET_DHP => CKA_X2RATCHET_DHP, Bytes;
    X2RATCHET_DHR => CKA_X2RATCHET_DHR, Bytes;
    X2RATCHET_DHS => CKA_X2RATCHET_DHS, Bytes;
    X2RATCHET_HKR => CKA_X2RATCHET_HKR, Bytes;
    X2RATCHET_HKS => CKA_X2RATCHET_HKS, Bytes;
    X2RATCHET_ISALICE => CKA_X2RATCHET_ISALICE, Boolean;
    X2RATCHET_NHKR => CKA_X2RATCHET_NHKR, Bytes;
    X2RATCHET_NHKS => CKA_X2RATCHET_NHKS, Bytes;
    X2RATCHET_NR => CKA_X2RATCHET_NR, Unsigned;
    X2RATCHET_NS => CKA_X2RATCHET_NS, Unsigned;
    X2RATCHET_PNS => CKA_X2RATCHET_PNS, Unsigned;
    X2RATCHET_RK => CKA_X2RATCHET_RK, Bytes;
    HSS_LEVELS => CKA_HSS_LEVELS, Unsigned;
    HSS_LMS_TYPE => CKA_HSS_LMS_TYPE, Unsigned;
    HSS_LMOTS_TYPE => CKA_HSS_LMOTS_TYPE, Unsigned;
    HSS_LMS_TYPES => CKA_HSS_LMS_TYPES, UnsignedArray;
    HSS_LMOTS_TYPES => CKA_HSS_LMOTS_TYPES, UnsignedArray;
    HSS_KEYS_REMAINING => CKA_HSS_KEYS_REMAINING, Unsigned;
    PARAMETER_SET => CKA_PARAMETER_SET, Unsigned;
    OBJECT_VALIDATION_FLAGS => CKA_OBJECT_VALIDATION_FLAGS, Unsigned;
    VALIDATION_TYPE => CKA_VALIDATION_TYPE, Unsigned;
    VALIDATION_VERSION => CKA_VALIDATION_VERSION, Version;
    VALIDATION_LEVEL => CKA_VALIDATION_LEVEL, Unsigned;
    VALIDATION_MODULE_ID => CKA_VALIDATION_MODULE_ID, Bytes;
    VALIDATION_FLAG => CKA_VALIDATION_FLAG, Unsigned;
    VALIDATION_AUTHORITY_TYPE => CKA_VALIDATION_AUTHORITY_TYPE, Unsigned;
    VALIDATION_COUNTRY => CKA_VALIDATION_COUNTRY, Bytes;
    VALIDATION_CERTIFICATE_IDENTIFIER => CKA_VALIDATION_CERTIFICATE_IDENTIFIER, Bytes;
    VALIDATION_CERTIFICATE_URI => CKA_VALIDATION_CERTIFICATE_URI, Bytes;
    VALIDATION_VENDOR_URI => CKA_VALIDATION_VENDOR_URI, Bytes;
    VALIDATION_PROFILE => CKA_VALIDATION_PROFILE, Bytes;
    TRUST_SERVER_AUTH => CKA_TRUST_SERVER_AUTH, Unsigned;
    TRUST_CLIENT_AUTH => CKA_TRUST_CLIENT_AUTH, Unsigned;
    TRUST_CODE_SIGNING => CKA_TRUST_CODE_SIGNING, Unsigned;
    TRUST_EMAIL_PROTECTION => CKA_TRUST_EMAIL_PROTECTION, Unsigned;
    TRUST_IPSEC_IKE => CKA_TRUST_IPSEC_IKE, Unsigned;
    TRUST_TIME_STAMPING => CKA_TRUST_TIME_STAMPING, Unsigned;
    TRUST_OCSP_SIGNING => CKA_TRUST_OCSP_SIGNING, Unsigned;
    ENCAPSULATE => CKA_ENCAPSULATE, Boolean;
    DECAPSULATE => CKA_DECAPSULATE, Boolean;
    HASH_OF_CERTIFICATE => CKA_HASH_OF_CERTIFICATE, Bytes;
    PUBLIC_CRC64_VALUE => CKA_PUBLIC_CRC64_VALUE, Bytes;
    SEED => CKA_SEED, Bytes;
}
