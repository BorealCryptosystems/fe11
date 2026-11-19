// SPDX-License-Identifier: Apache-2.0
pub fn check(value: &fe11::SavedOperationState) {
    std::hint::black_box(value.provenance());
}
