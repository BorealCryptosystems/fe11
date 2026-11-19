// SPDX-License-Identifier: Apache-2.0
//! Public binary examples exercise framing without opening a native module.
use crate::credentials::{read, InputError};

#[test]
fn binary_exact() {
    let input: &[u8] = &[0x00, 0x00, 0x00, 0x04, 0x00, 0xff, 0x00, 0x61, 0x00, 0x00, 0x00, 0x04, 0x20, 0x62, 0x00, 0x0a];
    let actual = read(&mut &input[..], 4);
    let actual = actual.unwrap_or_else(|error| panic!("framing error: {error:?}"));
    let expected_officer: &[u8] = &[0x00, 0xff, 0x00, 0x61];
    let expected_user: &[u8] = &[0x20, 0x62, 0x00, 0x0a];
    assert_eq!(actual.officer.as_slice(), expected_officer);
    assert_eq!(actual.user.as_slice(), expected_user);
}

#[test]
fn truncated_0() {
    let input: &[u8] = &[];
    let actual = read(&mut &input[..], 4);
    assert!(matches!(actual, Err(InputError::TruncatedFrame)));
}

#[test]
fn truncated_1() {
    let input: &[u8] = &[0x00];
    let actual = read(&mut &input[..], 4);
    assert!(matches!(actual, Err(InputError::TruncatedFrame)));
}

#[test]
fn truncated_2() {
    let input: &[u8] = &[0x00, 0x00];
    let actual = read(&mut &input[..], 4);
    assert!(matches!(actual, Err(InputError::TruncatedFrame)));
}

#[test]
fn truncated_3() {
    let input: &[u8] = &[0x00, 0x00, 0x00];
    let actual = read(&mut &input[..], 4);
    assert!(matches!(actual, Err(InputError::TruncatedFrame)));
}

#[test]
fn truncated_4() {
    let input: &[u8] = &[0x00, 0x00, 0x00, 0x04];
    let actual = read(&mut &input[..], 4);
    assert!(matches!(actual, Err(InputError::TruncatedFrame)));
}

#[test]
fn truncated_5() {
    let input: &[u8] = &[0x00, 0x00, 0x00, 0x04, 0x00];
    let actual = read(&mut &input[..], 4);
    assert!(matches!(actual, Err(InputError::TruncatedFrame)));
}

#[test]
fn truncated_6() {
    let input: &[u8] = &[0x00, 0x00, 0x00, 0x04, 0x00, 0xff];
    let actual = read(&mut &input[..], 4);
    assert!(matches!(actual, Err(InputError::TruncatedFrame)));
}

#[test]
fn truncated_7() {
    let input: &[u8] = &[0x00, 0x00, 0x00, 0x04, 0x00, 0xff, 0x00];
    let actual = read(&mut &input[..], 4);
    assert!(matches!(actual, Err(InputError::TruncatedFrame)));
}

#[test]
fn truncated_8() {
    let input: &[u8] = &[0x00, 0x00, 0x00, 0x04, 0x00, 0xff, 0x00, 0x61];
    let actual = read(&mut &input[..], 4);
    assert!(matches!(actual, Err(InputError::TruncatedFrame)));
}

#[test]
fn truncated_9() {
    let input: &[u8] = &[0x00, 0x00, 0x00, 0x04, 0x00, 0xff, 0x00, 0x61, 0x00];
    let actual = read(&mut &input[..], 4);
    assert!(matches!(actual, Err(InputError::TruncatedFrame)));
}

#[test]
fn truncated_10() {
    let input: &[u8] = &[0x00, 0x00, 0x00, 0x04, 0x00, 0xff, 0x00, 0x61, 0x00, 0x00];
    let actual = read(&mut &input[..], 4);
    assert!(matches!(actual, Err(InputError::TruncatedFrame)));
}

#[test]
fn truncated_11() {
    let input: &[u8] = &[0x00, 0x00, 0x00, 0x04, 0x00, 0xff, 0x00, 0x61, 0x00, 0x00, 0x00];
    let actual = read(&mut &input[..], 4);
    assert!(matches!(actual, Err(InputError::TruncatedFrame)));
}

#[test]
fn truncated_12() {
    let input: &[u8] = &[0x00, 0x00, 0x00, 0x04, 0x00, 0xff, 0x00, 0x61, 0x00, 0x00, 0x00, 0x04];
    let actual = read(&mut &input[..], 4);
    assert!(matches!(actual, Err(InputError::TruncatedFrame)));
}

#[test]
fn truncated_13() {
    let input: &[u8] = &[0x00, 0x00, 0x00, 0x04, 0x00, 0xff, 0x00, 0x61, 0x00, 0x00, 0x00, 0x04, 0x20];
    let actual = read(&mut &input[..], 4);
    assert!(matches!(actual, Err(InputError::TruncatedFrame)));
}

#[test]
fn truncated_14() {
    let input: &[u8] = &[0x00, 0x00, 0x00, 0x04, 0x00, 0xff, 0x00, 0x61, 0x00, 0x00, 0x00, 0x04, 0x20, 0x62];
    let actual = read(&mut &input[..], 4);
    assert!(matches!(actual, Err(InputError::TruncatedFrame)));
}

#[test]
fn truncated_15() {
    let input: &[u8] = &[0x00, 0x00, 0x00, 0x04, 0x00, 0xff, 0x00, 0x61, 0x00, 0x00, 0x00, 0x04, 0x20, 0x62, 0x00];
    let actual = read(&mut &input[..], 4);
    assert!(matches!(actual, Err(InputError::TruncatedFrame)));
}

#[test]
fn trailing_0() {
    let input: &[u8] = &[0x00, 0x00, 0x00, 0x04, 0x00, 0xff, 0x00, 0x61, 0x00, 0x00, 0x00, 0x04, 0x20, 0x62, 0x00, 0x0a, 0x00];
    let actual = read(&mut &input[..], 4);
    assert!(matches!(actual, Err(InputError::TrailingBytes)));
}

#[test]
fn trailing_10() {
    let input: &[u8] = &[0x00, 0x00, 0x00, 0x04, 0x00, 0xff, 0x00, 0x61, 0x00, 0x00, 0x00, 0x04, 0x20, 0x62, 0x00, 0x0a, 0x0a];
    let actual = read(&mut &input[..], 4);
    assert!(matches!(actual, Err(InputError::TrailingBytes)));
}

#[test]
fn trailing_255() {
    let input: &[u8] = &[0x00, 0x00, 0x00, 0x04, 0x00, 0xff, 0x00, 0x61, 0x00, 0x00, 0x00, 0x04, 0x20, 0x62, 0x00, 0x0a, 0xff];
    let actual = read(&mut &input[..], 4);
    assert!(matches!(actual, Err(InputError::TrailingBytes)));
}

#[test]
fn bound_exceeded() {
    let input: &[u8] = &[0x00, 0x00, 0x00, 0x04, 0x00, 0xff, 0x00, 0x61, 0x00, 0x00, 0x00, 0x04, 0x20, 0x62, 0x00, 0x0a];
    let actual = read(&mut &input[..], 3);
    assert!(matches!(actual, Err(InputError::LengthExceedsBound)));
}

#[test]
fn oversize_before_allocation() {
    let input: &[u8] = &[0xff, 0xff, 0xff, 0xff];
    let actual = read(&mut &input[..], 4);
    assert!(matches!(actual, Err(InputError::LengthExceedsBound)));
}

#[test]
fn both_empty() {
    let input: &[u8] = &[0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00];
    let actual = read(&mut &input[..], 0);
    let actual = actual.unwrap_or_else(|error| panic!("framing error: {error:?}"));
    let expected_officer: &[u8] = &[];
    let expected_user: &[u8] = &[];
    assert_eq!(actual.officer.as_slice(), expected_officer);
    assert_eq!(actual.user.as_slice(), expected_user);
}
