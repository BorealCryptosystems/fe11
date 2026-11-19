// SPDX-License-Identifier: Apache-2.0
pub fn consume(_: fe11::OperationTicket) {}
pub fn check(value: fe11::OperationTicket) {
    consume(value);
    consume(value);
}
