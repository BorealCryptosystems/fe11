// SPDX-License-Identifier: Apache-2.0
//! Complete FIPS 203/204/205 parameter domains, independent of module support.
use fe11::{MlDsaParameterSet, MlKemParameterSet, PqcAlgorithm, SlhDsaParameterSet};

#[test]
fn ml_kem_parameter_order_and_standard_widths() {
    let expected = [
        (MlKemParameterSet::MlKem512, 800, 768),
        (MlKemParameterSet::MlKem768, 1184, 1088),
        (MlKemParameterSet::MlKem1024, 1568, 1568),
    ];
    assert_eq!(MlKemParameterSet::ALL, expected.map(|(parameter, _, _)| parameter));
    for (parameter, public_width, ciphertext_width) in expected {
        assert_eq!(parameter.public_key_length(), public_width);
        assert_eq!(parameter.ciphertext_length(), ciphertext_width);
    }
}

#[test]
fn all_standard_signature_parameter_sets_are_present_once() {
    let expected = [
        PqcAlgorithm::MlDsa(MlDsaParameterSet::MlDsa44),
        PqcAlgorithm::MlDsa(MlDsaParameterSet::MlDsa65),
        PqcAlgorithm::MlDsa(MlDsaParameterSet::MlDsa87),
        PqcAlgorithm::SlhDsa(SlhDsaParameterSet::Sha2_128s),
        PqcAlgorithm::SlhDsa(SlhDsaParameterSet::Sha2_128f),
        PqcAlgorithm::SlhDsa(SlhDsaParameterSet::Sha2_192s),
        PqcAlgorithm::SlhDsa(SlhDsaParameterSet::Sha2_192f),
        PqcAlgorithm::SlhDsa(SlhDsaParameterSet::Sha2_256s),
        PqcAlgorithm::SlhDsa(SlhDsaParameterSet::Sha2_256f),
        PqcAlgorithm::SlhDsa(SlhDsaParameterSet::Shake128s),
        PqcAlgorithm::SlhDsa(SlhDsaParameterSet::Shake128f),
        PqcAlgorithm::SlhDsa(SlhDsaParameterSet::Shake192s),
        PqcAlgorithm::SlhDsa(SlhDsaParameterSet::Shake192f),
        PqcAlgorithm::SlhDsa(SlhDsaParameterSet::Shake256s),
        PqcAlgorithm::SlhDsa(SlhDsaParameterSet::Shake256f),
    ];
    assert_eq!(PqcAlgorithm::ALL.len(), expected.len());
    for parameter in expected {
        assert_eq!(PqcAlgorithm::ALL.iter().filter(|value| **value == parameter).count(), 1);
    }
}
