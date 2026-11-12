// SPDX-License-Identifier: Apache-2.0
//! Borrowed, bounded private DER decoding. No private re-encoding or allocation.
//! Structural validation is not a proof of possession or private-key correctness.

use crate::symmetric::memory::Credit;
use crate::{ClassicalKeyAlgorithm, Error, PrivateEncodingReport, Result, SecretBytes};
use der::{
    asn1::{BitStringRef, Null, ObjectIdentifier, OctetStringRef, UintRef},
    Decode, Sequence,
};

use x509_cert::spki::AlgorithmIdentifierRef;

/// Keeps the imported allocation charged until its initialized bytes are erased.
/// Field order is deliberate: secret storage is dropped before its credit.
pub(crate) struct PreparedPrivateInput {
    material: SecretBytes,
    credit: std::sync::OnceLock<Credit>,
}
impl PreparedPrivateInput {
    /// Transfer the caller's owner without copying or charging new storage.
    /// Borrowed DER validation may precede reference admission. Any credit already
    /// carried by SecretBytes stays attached throughout that admission window.
    pub(crate) fn borrowed(material: SecretBytes) -> Self {
        Self {
            material,
            credit: std::sync::OnceLock::new(),
        }
    }

    /// Measure the transferred allocation without copying it or acquiring a
    /// separate credit. The initial creation candidate includes these bytes.
    pub(crate) fn allocation_bytes(&self) -> Result<usize> {
        std::mem::size_of::<Self>()
            .checked_add(self.material.allocated_bytes())
            .ok_or(Error::Rejected(crate::RejectionReason::KeyEncoding(
                crate::KeyEncodingRejection::PrivateInputAllocationSize,
            )))
    }

    /// Attach the already admitted share only after the complete candidate has
    /// possession. Parsed slices remain valid, and the source is still erased
    /// before this credit is released. This transition never waits or calls C.
    pub(crate) fn charge_prepaid(&self, prepaid: &mut Credit) -> Result<()> {
        self.charge_with(|bytes| prepaid.split(bytes))
    }

    fn charge_with(&self, reserve: impl FnOnce(usize) -> Result<Credit>) -> Result<()> {
        let bytes = self.allocation_bytes()?;
        if self.credit.get().is_some() {
            return Err(Error::Rejected(crate::RejectionReason::KeyEncoding(
                crate::KeyEncodingRejection::PrivateInputAlreadyCharged,
            )));
        }
        // OnceLock prevents charging twice without moving the borrowed source.
        // The reservation supplies a split of the complete candidate credit.
        let credit = reserve(bytes)?;
        self.credit.set(credit).map_err(|_| {
            Error::Rejected(crate::RejectionReason::KeyEncoding(
                crate::KeyEncodingRejection::PrivateInputAlreadyCharged,
            ))
        })
    }
    pub(crate) fn as_slice(&self) -> &[u8] {
        self.material.as_slice()
    }
}

const RSA: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.113549.1.1.1");
const EC: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.10045.2.1");
const ED25519: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.3.101.112");
const ED448: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.3.101.113");
#[derive(Sequence)]
struct PrivateKeyInfo<'a> {
    version: u8,
    algorithm: AlgorithmIdentifierRef<'a>,
    private_key: OctetStringRef<'a>,
}
#[derive(Sequence)]
struct RsaPrivate<'a> {
    version: u8,
    modulus: UintRef<'a>,
    public_exponent: UintRef<'a>,
    private_exponent: UintRef<'a>,
    prime1: UintRef<'a>,
    prime2: UintRef<'a>,
    exponent1: UintRef<'a>,
    exponent2: UintRef<'a>,
    coefficient: UintRef<'a>,
}
#[derive(Sequence)]
struct EcPrivate<'a> {
    version: u8,
    private_key: OctetStringRef<'a>,
    #[asn1(context_specific = "0", tag_mode = "EXPLICIT", optional = "true")]
    parameters: Option<ObjectIdentifier>,
    #[asn1(context_specific = "1", tag_mode = "EXPLICIT", optional = "true")]
    public_key: Option<BitStringRef<'a>>,
}
// No Debug/Clone, no ownership of a component. The source SecretBytes must outlive
// this view; the caller copies private slices directly into SecretTemplate.
pub(crate) enum PrivateMaterial<'a> {
    Rsa {
        modulus: &'a [u8],
        exponent: &'a [u8],
        components: [&'a [u8]; 6],
    },
    Scalar(&'a [u8]),
}

/// Parse canonical PKCS8 v1 (INTEGER version 0), without attributes or suffix.
/// The caller-selected budget covers private DER plus the expected public SPKI.
/// Decode the requested private-key representation into borrowed native operands.
/// The public declaration is bounded but is not compared with private material.
/// Parsing establishes encoding shape only; the module decides key validity.
pub(crate) fn parse_pkcs8<'a>(
    bytes: &'a [u8],
    algorithm: ClassicalKeyAlgorithm,
    expected_spki: &[u8],
    maximum_input_bytes: usize,
) -> Result<(PrivateMaterial<'a>, PrivateEncodingReport)> {
    let input_bytes = bytes
        .len()
        .checked_add(expected_spki.len())
        .ok_or(Error::Rejected(crate::RejectionReason::KeyEncoding(
            crate::KeyEncodingRejection::PrivateInputSizeOverflow,
        )))?;
    if bytes.is_empty() || input_bytes > maximum_input_bytes {
        return Err(Error::Rejected(crate::RejectionReason::KeyEncoding(
            crate::KeyEncodingRejection::PrivatePkcs8Size,
        )));
    }
    let key = PrivateKeyInfo::from_der(bytes).map_err(|_| {
        Error::Rejected(crate::RejectionReason::KeyEncoding(
            crate::KeyEncodingRejection::PrivatePkcs8Der,
        ))
    })?;
    if key.version != 0 {
        return Err(Error::Rejected(crate::RejectionReason::KeyEncoding(
            crate::KeyEncodingRejection::PrivatePkcs8Version,
        )));
    }
    let mut report = PrivateEncodingReport {
        destination: algorithm,
        encoded_algorithm: key.algorithm.oid,
        outer_curve: None,
        inner_curve: None,
        scalar_bytes: None,
        embedded_public: false,
        supplied_spki_bytes: expected_spki.len(),
    };
    match algorithm {
        ClassicalKeyAlgorithm::Rsa { .. } => {
            if key.algorithm.oid != RSA {
                return Err(Error::Rejected(crate::RejectionReason::KeyEncoding(
                    crate::KeyEncodingRejection::PrivateRsaProfile,
                )));
            }
            key.algorithm
                .parameters
                .ok_or(Error::Rejected(crate::RejectionReason::KeyEncoding(
                    crate::KeyEncodingRejection::PrivateRsaParametersAbsent,
                )))?
                .decode_as::<Null>()
                .map_err(|_| {
                    Error::Rejected(crate::RejectionReason::KeyEncoding(
                        crate::KeyEncodingRejection::PrivateRsaParameters,
                    ))
                })?;
            let rsa = RsaPrivate::from_der(key.private_key.as_bytes()).map_err(|_| {
                Error::Rejected(crate::RejectionReason::KeyEncoding(
                    crate::KeyEncodingRejection::PrivateRsaDer,
                ))
            })?;
            if rsa.version != 0 {
                return Err(Error::Rejected(crate::RejectionReason::KeyEncoding(
                    crate::KeyEncodingRejection::MultiPrimeRsaUnsupported,
                )));
            }

            // Borrow canonical unsigned components without local number-theoretic
            // assumptions. The module decides whether these operands form a key.
            let components = [
                rsa.private_exponent.as_bytes(),
                rsa.prime1.as_bytes(),
                rsa.prime2.as_bytes(),
                rsa.exponent1.as_bytes(),
                rsa.exponent2.as_bytes(),
                rsa.coefficient.as_bytes(),
            ];
            Ok((
                PrivateMaterial::Rsa {
                    modulus: rsa.modulus.as_bytes(),
                    exponent: rsa.public_exponent.as_bytes(),
                    components,
                },
                report,
            ))
        }
        ClassicalKeyAlgorithm::Ecdsa(_) => {
            if key.algorithm.oid != EC {
                return Err(Error::Rejected(crate::RejectionReason::KeyEncoding(
                    crate::KeyEncodingRejection::PrivateEcAlgorithm,
                )));
            }
            let supplied = key
                .algorithm
                .parameters
                .ok_or(Error::Rejected(crate::RejectionReason::KeyEncoding(
                    crate::KeyEncodingRejection::PrivateEcNamedCurveAbsent,
                )))?
                .decode_as::<ObjectIdentifier>()
                .map_err(|_| {
                    Error::Rejected(crate::RejectionReason::KeyEncoding(
                        crate::KeyEncodingRejection::PrivateEcParameters,
                    ))
                })?;
            let ec = EcPrivate::from_der(key.private_key.as_bytes()).map_err(|_| {
                Error::Rejected(crate::RejectionReason::KeyEncoding(
                    crate::KeyEncodingRejection::PrivateEcDer,
                ))
            })?;
            if ec.version != 1 {
                return Err(Error::Rejected(crate::RejectionReason::KeyEncoding(
                    crate::KeyEncodingRejection::PrivateEcVersion,
                )));
            }
            report.outer_curve = Some(supplied);
            report.inner_curve = ec.parameters;
            report.embedded_public = ec.public_key.is_some();
            let scalar = ec.private_key.as_bytes();
            report.scalar_bytes = Some(scalar.len());

            Ok((PrivateMaterial::Scalar(scalar), report))
        }
        ClassicalKeyAlgorithm::Ed25519 | ClassicalKeyAlgorithm::Ed448 => {
            // Decode the seed according to its encoded OID. The caller
            // independently selects the native destination template.
            let width = match key.algorithm.oid {
                ED25519 => 32,
                ED448 => 57,
                _ => {
                    return Err(Error::Rejected(crate::RejectionReason::KeyEncoding(
                        crate::KeyEncodingRejection::PrivateEdwardsAlgorithm,
                    )))
                }
            };
            if key.algorithm.parameters.is_some() {
                return Err(Error::Rejected(crate::RejectionReason::KeyEncoding(
                    crate::KeyEncodingRejection::PrivateEdwardsParameters,
                )));
            }

            let seed = OctetStringRef::from_der(key.private_key.as_bytes()).map_err(|_| {
                Error::Rejected(crate::RejectionReason::KeyEncoding(
                    crate::KeyEncodingRejection::PrivateEdwardsNestedOctetString,
                ))
            })?;
            if seed.as_bytes().len() != width {
                return Err(Error::Rejected(crate::RejectionReason::KeyEncoding(
                    crate::KeyEncodingRejection::PrivateEdwardsSeedLength,
                )));
            }
            report.scalar_bytes = Some(seed.as_bytes().len());
            Ok((PrivateMaterial::Scalar(seed.as_bytes()), report))
        }
    }
}
