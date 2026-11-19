// SPDX-License-Identifier: Apache-2.0
pub fn consume(_: fe11::Session) {}
pub fn check(value: fe11::Session) {
    consume(value);
}
