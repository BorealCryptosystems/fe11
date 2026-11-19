// SPDX-License-Identifier: Apache-2.0
//! FIPS 203 ByteDecode12 boundary inputs; these are public encodings, not key KATs.
use fe11::{Error, KemPublicKey, KeyEncapsulationRejection, MlKemParameterSet, RejectionReason};

pub fn check_coefficients(parameter_set: MlKemParameterSet, width: usize) {
    for position in 0..(width - 32) / 3 {
        for half in 0..2 {
            for coefficient in [0_u16, 3328, 3329, 3330, 4095] {
                for rho in [0_u8, 255] {
                    let mut input = vec![0; width];
                    input[width - 32..].fill(rho);
                    let (a, b) = if half == 0 { (coefficient, 0) } else { (0, coefficient) };
                    // Pack two independent 12-bit values, retaining the other at zero.
                    input[position * 3] = (a & 255) as u8;
                    input[position * 3 + 1] = ((a >> 8) | ((b & 15) << 4)) as u8;
                    input[position * 3 + 2] = (b >> 4) as u8;
                    let actual = KemPublicKey::from_raw(parameter_set, &input);
                    if coefficient < 3329 {
                        let actual = actual.expect("canonical coefficient encoding");
                        assert_eq!(actual.parameter_set(), parameter_set);
                        assert_eq!(actual.as_raw(), input);
                    } else {
                        assert!(matches!(actual, Err(Error::Rejected(
                            RejectionReason::KeyEncapsulation(
                                KeyEncapsulationRejection::MlKemPublicCoefficientEncoding
                            )
                        ))));
                    }
                }
            }
        }
    }
}
