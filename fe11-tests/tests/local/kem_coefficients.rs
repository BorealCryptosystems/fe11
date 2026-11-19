// SPDX-License-Identifier: Apache-2.0
//! Public constructor boundaries and owned-value observations.
use fe11::MlKemParameterSet;

use super::kem_coefficient_support::check_coefficients;

#[test]
fn kem_coefficients_mlkem512() {
    check_coefficients(MlKemParameterSet::MlKem512, 800);
}

#[test]
fn kem_coefficients_mlkem768() {
    check_coefficients(MlKemParameterSet::MlKem768, 1184);
}

#[test]
fn kem_coefficients_mlkem1024() {
    check_coefficients(MlKemParameterSet::MlKem1024, 1568);
}
