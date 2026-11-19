// SPDX-License-Identifier: Apache-2.0
//! Field-by-field construction of public scalar records. Each change affects one field.
use fe11::*;

macro_rules! vary {
    ($base:expr, $field:ident, $values:expr) => {
        for expected in $values {
            let mut value = $base;
            value.$field = expected;
            assert_eq!(value.$field, expected);
            assert_eq!(value == $base, expected == $base.$field);
            assert_eq!(value.clone(), value);
        }
    };
}

#[test]
fn attribute_batch_call() {
    const ZERO: AttributeBatchCall = AttributeBatchCall {
        attribute_count: 0,
        code: 0,
    };
    let copied = ZERO;
    assert!(matches!(copied, ZERO));
    assert_eq!(copied, ZERO);
    assert!(!format!("{copied:?}").is_empty());
    vary!(ZERO, attribute_count, [0, 1, 2, usize::MAX]);
    vary!(ZERO, code, [0, 1, 3, u64::MAX]);
}

#[test]
fn attribute_template_limits() {
    const ZERO: AttributeTemplateLimits = AttributeTemplateLimits {
        maximum_attributes: 0,
        maximum_depth: 0,
        maximum_value_bytes: 0,
    };
    let copied = ZERO;
    assert!(matches!(copied, ZERO));
    assert_eq!(copied, ZERO);
    assert!(!format!("{copied:?}").is_empty());
    vary!(ZERO, maximum_attributes, [0, 1, 2, usize::MAX]);
    vary!(ZERO, maximum_depth, [0, 1, 3, usize::MAX]);
    vary!(ZERO, maximum_value_bytes, [0, 1, 4, usize::MAX]);
}

#[test]
fn current_key_protection() {
    const ZERO: CurrentKeyProtection = CurrentKeyProtection {
        extractable: false,
        sensitive: false,
    };
    let copied = ZERO;
    assert!(matches!(copied, ZERO));
    assert_eq!(copied, ZERO);
    assert!(!format!("{copied:?}").is_empty());
    vary!(ZERO, extractable, [false, true]);
    vary!(ZERO, sensitive, [false, true]);
}

#[test]
fn foreign_status() {
    const ZERO: ForeignStatus = ForeignStatus {
        callbacks: 0,
        participants: 0,
        progressable: 0,
        sessions: 0,
        uncertain: 0,
    };
    let copied = ZERO;
    assert!(matches!(copied, ZERO));
    assert_eq!(copied, ZERO);
    assert!(!format!("{copied:?}").is_empty());
    vary!(ZERO, callbacks, [0, 1, 2, usize::MAX]);
    vary!(ZERO, participants, [0, 1, 3, usize::MAX]);
    vary!(ZERO, progressable, [0, 1, 4, usize::MAX]);
    vary!(ZERO, sessions, [0, 1, 5, usize::MAX]);
    vary!(ZERO, uncertain, [0, 1, 6, usize::MAX]);
}

#[test]
fn history_observation_plan() {
    const ZERO: HistoryObservationPlan = HistoryObservationPlan {
        always_sensitive: false,
        extractable: false,
        generation: false,
        local: false,
        maximum_bytes: 0,
        never_extractable: false,
        sensitive: false,
    };
    let copied = ZERO;
    assert!(matches!(copied, ZERO));
    assert_eq!(copied, ZERO);
    assert!(!format!("{copied:?}").is_empty());
    vary!(ZERO, always_sensitive, [false, true]);
    vary!(ZERO, extractable, [false, true]);
    vary!(ZERO, generation, [false, true]);
    vary!(ZERO, local, [false, true]);
    vary!(ZERO, maximum_bytes, [0, 1, 6, usize::MAX]);
    vary!(ZERO, never_extractable, [false, true]);
    vary!(ZERO, sensitive, [false, true]);
}

#[test]
fn interface_discovery_limits() {
    const ZERO: InterfaceDiscoveryLimits = InterfaceDiscoveryLimits {
        attempts: 0,
        interfaces: 0,
    };
    let copied = ZERO;
    assert!(matches!(copied, ZERO));
    assert_eq!(copied, ZERO);
    assert!(!format!("{copied:?}").is_empty());
    vary!(ZERO, attempts, [0, 1, 2, usize::MAX]);
    vary!(ZERO, interfaces, [0, 1, 3, usize::MAX]);
}

#[test]
fn notify_diagnostics() {
    const ZERO: NotifyDiagnostics = NotifyDiagnostics {
        activity_exhausted: false,
        binding_mismatch: false,
        callback_panicked: false,
    };
    let copied = ZERO;
    assert!(matches!(copied, ZERO));
    assert_eq!(copied, ZERO);
    assert!(!format!("{copied:?}").is_empty());
    vary!(ZERO, activity_exhausted, [false, true]);
    vary!(ZERO, binding_mismatch, [false, true]);
    vary!(ZERO, callback_panicked, [false, true]);
}

#[test]
fn object_observation_plan() {
    const ZERO: ObjectObservationPlan = ObjectObservationPlan {
        always_authenticate: false,
        always_sensitive: false,
        copyable: false,
        decapsulate: false,
        decrypt: false,
        derive: false,
        destroyable: false,
        encapsulate: false,
        encrypt: false,
        extractable: false,
        local: false,
        maximum_bytes: 0,
        modifiable: false,
        never_extractable: false,
        private: false,
        sensitive: false,
        sign: false,
        sign_recover: false,
        token: false,
        trusted: false,
        unwrap: false,
        verify: false,
        verify_recover: false,
        wrap: false,
        wrap_with_trusted: false,
    };
    let copied = ZERO;
    assert!(matches!(copied, ZERO));
    assert_eq!(copied, ZERO);
    assert!(!format!("{copied:?}").is_empty());
    vary!(ZERO, always_authenticate, [false, true]);
    vary!(ZERO, always_sensitive, [false, true]);
    vary!(ZERO, copyable, [false, true]);
    vary!(ZERO, decapsulate, [false, true]);
    vary!(ZERO, decrypt, [false, true]);
    vary!(ZERO, derive, [false, true]);
    vary!(ZERO, destroyable, [false, true]);
    vary!(ZERO, encapsulate, [false, true]);
    vary!(ZERO, encrypt, [false, true]);
    vary!(ZERO, extractable, [false, true]);
    vary!(ZERO, local, [false, true]);
    vary!(ZERO, maximum_bytes, [0, 1, 13, usize::MAX]);
    vary!(ZERO, modifiable, [false, true]);
    vary!(ZERO, never_extractable, [false, true]);
    vary!(ZERO, private, [false, true]);
    vary!(ZERO, sensitive, [false, true]);
    vary!(ZERO, sign, [false, true]);
    vary!(ZERO, sign_recover, [false, true]);
    vary!(ZERO, token, [false, true]);
    vary!(ZERO, trusted, [false, true]);
    vary!(ZERO, unwrap, [false, true]);
    vary!(ZERO, verify, [false, true]);
    vary!(ZERO, verify_recover, [false, true]);
    vary!(ZERO, wrap, [false, true]);
    vary!(ZERO, wrap_with_trusted, [false, true]);
}

#[test]
fn record_limits() {
    const ZERO: RecordLimits = RecordLimits {
        bytes: 0,
        fragments: 0,
        messages: 0,
    };
    let copied = ZERO;
    assert!(matches!(copied, ZERO));
    assert_eq!(copied, ZERO);
    assert!(!format!("{copied:?}").is_empty());
    vary!(ZERO, bytes, [0, 1, 2, usize::MAX]);
    vary!(ZERO, fragments, [0, 1, 3, usize::MAX]);
    vary!(ZERO, messages, [0, 1, 4, usize::MAX]);
}

#[test]
fn session_limit() {
    const ZERO: SessionLimit = SessionLimit {
        read_write: 0,
        total: 0,
    };
    let copied = ZERO;
    assert!(matches!(copied, ZERO));
    assert_eq!(copied, ZERO);
    assert!(!format!("{copied:?}").is_empty());
    vary!(ZERO, read_write, [0, 1, 2, usize::MAX]);
    vary!(ZERO, total, [0, 1, 3, usize::MAX]);
}

#[test]
fn session_usage() {
    const ZERO: SessionUsage = SessionUsage {
        closing: 0,
        deferred_close: 0,
        open: 0,
        opening: 0,
        quarantined: 0,
        read_write: 0,
        recovering: 0,
        reserved: 0,
        retained_returned: 0,
        total: 0,
    };
    let copied = ZERO;
    assert!(matches!(copied, ZERO));
    assert_eq!(copied, ZERO);
    assert!(!format!("{copied:?}").is_empty());
    vary!(ZERO, closing, [0, 1, 2, usize::MAX]);
    vary!(ZERO, deferred_close, [0, 1, 3, usize::MAX]);
    vary!(ZERO, open, [0, 1, 4, usize::MAX]);
    vary!(ZERO, opening, [0, 1, 5, usize::MAX]);
    vary!(ZERO, quarantined, [0, 1, 6, usize::MAX]);
    vary!(ZERO, read_write, [0, 1, 7, usize::MAX]);
    vary!(ZERO, recovering, [0, 1, 8, usize::MAX]);
    vary!(ZERO, reserved, [0, 1, 9, usize::MAX]);
    vary!(ZERO, retained_returned, [0, 1, 10, usize::MAX]);
    vary!(ZERO, total, [0, 1, 11, usize::MAX]);
}

#[test]
fn sp800_counter_format() {
    const ZERO: Sp800CounterFormat = Sp800CounterFormat {
        little_endian: false,
        width_bits: 0,
    };
    let copied = ZERO;
    assert!(matches!(copied, ZERO));
    assert_eq!(copied, ZERO);
    assert!(!format!("{copied:?}").is_empty());
    vary!(ZERO, little_endian, [false, true]);
    vary!(ZERO, width_bits, [0, 1, 3, u64::MAX]);
}

#[test]
fn sp800_length_format() {
    const ZERO: Sp800LengthFormat = Sp800LengthFormat {
        little_endian: false,
        method: 0,
        width_bits: 0,
    };
    let copied = ZERO;
    assert!(matches!(copied, ZERO));
    assert_eq!(copied, ZERO);
    assert!(!format!("{copied:?}").is_empty());
    vary!(ZERO, little_endian, [false, true]);
    vary!(ZERO, method, [0, 1, 3, u64::MAX]);
    vary!(ZERO, width_bits, [0, 1, 4, u64::MAX]);
}

#[test]
fn crypto_limits() {
    const BASE: CryptoLimits = CryptoLimits {
        maximum_parts: 2,
        maximum_total_bytes: 3,
    };
    for expected in [0, 1, usize::MAX] {
        let value = CryptoLimits { maximum_parts: expected, ..BASE };
        let copied = value;
        assert_eq!(value.maximum_parts, copied.maximum_parts);
        let cloned = copied.clone();
        assert!(!format!("{cloned:?}").is_empty());
        assert_eq!(cloned.maximum_parts, expected);
        assert_eq!(cloned.maximum_total_bytes, 3);
    }
    for expected in [0, 1, usize::MAX] {
        let value = CryptoLimits { maximum_total_bytes: expected, ..BASE };
        let copied = value;
        assert_eq!(value.maximum_total_bytes, copied.maximum_total_bytes);
        let cloned = copied.clone();
        assert!(!format!("{cloned:?}").is_empty());
        assert_eq!(cloned.maximum_parts, 2);
        assert_eq!(cloned.maximum_total_bytes, expected);
    }
}

#[test]
fn input_limits() {
    const BASE: InputLimits = InputLimits {
        maximum_parts: 2,
        maximum_total_bytes: 3,
    };
    for expected in [0, 1, usize::MAX] {
        let value = InputLimits { maximum_parts: expected, ..BASE };
        let copied = value;
        assert_eq!(value.maximum_parts, copied.maximum_parts);
        let cloned = copied.clone();
        assert!(!format!("{cloned:?}").is_empty());
        assert_eq!(cloned.maximum_parts, expected);
        assert_eq!(cloned.maximum_total_bytes, 3);
    }
    for expected in [0, 1, usize::MAX] {
        let value = InputLimits { maximum_total_bytes: expected, ..BASE };
        let copied = value;
        assert_eq!(value.maximum_total_bytes, copied.maximum_total_bytes);
        let cloned = copied.clone();
        assert!(!format!("{cloned:?}").is_empty());
        assert_eq!(cloned.maximum_parts, 2);
        assert_eq!(cloned.maximum_total_bytes, expected);
    }
}

#[test]
fn interface_inventory_limits() {
    const BASE: InterfaceInventoryLimits = InterfaceInventoryLimits {
        attempts: 2,
        interfaces: 3,
        name_bytes: 4,
        total_name_bytes: 5,
    };
    for expected in [0, 1, usize::MAX] {
        let value = InterfaceInventoryLimits { attempts: expected, ..BASE };
        let copied = value;
        assert_eq!(value.attempts, copied.attempts);
        let cloned = copied.clone();
        assert!(!format!("{cloned:?}").is_empty());
        assert_eq!(cloned.attempts, expected);
        assert_eq!(cloned.interfaces, 3);
        assert_eq!(cloned.name_bytes, 4);
        assert_eq!(cloned.total_name_bytes, 5);
    }
    for expected in [0, 1, usize::MAX] {
        let value = InterfaceInventoryLimits { interfaces: expected, ..BASE };
        let copied = value;
        assert_eq!(value.interfaces, copied.interfaces);
        let cloned = copied.clone();
        assert!(!format!("{cloned:?}").is_empty());
        assert_eq!(cloned.attempts, 2);
        assert_eq!(cloned.interfaces, expected);
        assert_eq!(cloned.name_bytes, 4);
        assert_eq!(cloned.total_name_bytes, 5);
    }
    for expected in [0, 1, usize::MAX] {
        let value = InterfaceInventoryLimits { name_bytes: expected, ..BASE };
        let copied = value;
        assert_eq!(value.name_bytes, copied.name_bytes);
        let cloned = copied.clone();
        assert!(!format!("{cloned:?}").is_empty());
        assert_eq!(cloned.attempts, 2);
        assert_eq!(cloned.interfaces, 3);
        assert_eq!(cloned.name_bytes, expected);
        assert_eq!(cloned.total_name_bytes, 5);
    }
    for expected in [0, 1, usize::MAX] {
        let value = InterfaceInventoryLimits { total_name_bytes: expected, ..BASE };
        let copied = value;
        assert_eq!(value.total_name_bytes, copied.total_name_bytes);
        let cloned = copied.clone();
        assert!(!format!("{cloned:?}").is_empty());
        assert_eq!(cloned.attempts, 2);
        assert_eq!(cloned.interfaces, 3);
        assert_eq!(cloned.name_bytes, 4);
        assert_eq!(cloned.total_name_bytes, expected);
    }
}

#[test]
fn limits() {
    const BASE: Limits = Limits {
        discovery_attempts: 2,
        mechanisms: 3,
        sessions: 4,
        slots: 5,
    };
    for expected in [0, 1, usize::MAX] {
        let value = Limits { discovery_attempts: expected, ..BASE };
        let copied = value;
        assert_eq!(value.discovery_attempts, copied.discovery_attempts);
        let cloned = copied.clone();
        assert!(!format!("{cloned:?}").is_empty());
        assert_eq!(cloned.discovery_attempts, expected);
        assert_eq!(cloned.mechanisms, 3);
        assert_eq!(cloned.sessions, 4);
        assert_eq!(cloned.slots, 5);
    }
    for expected in [0, 1, usize::MAX] {
        let value = Limits { mechanisms: expected, ..BASE };
        let copied = value;
        assert_eq!(value.mechanisms, copied.mechanisms);
        let cloned = copied.clone();
        assert!(!format!("{cloned:?}").is_empty());
        assert_eq!(cloned.discovery_attempts, 2);
        assert_eq!(cloned.mechanisms, expected);
        assert_eq!(cloned.sessions, 4);
        assert_eq!(cloned.slots, 5);
    }
    for expected in [0, 1, usize::MAX] {
        let value = Limits { sessions: expected, ..BASE };
        let copied = value;
        assert_eq!(value.sessions, copied.sessions);
        let cloned = copied.clone();
        assert!(!format!("{cloned:?}").is_empty());
        assert_eq!(cloned.discovery_attempts, 2);
        assert_eq!(cloned.mechanisms, 3);
        assert_eq!(cloned.sessions, expected);
        assert_eq!(cloned.slots, 5);
    }
    for expected in [0, 1, usize::MAX] {
        let value = Limits { slots: expected, ..BASE };
        let copied = value;
        assert_eq!(value.slots, copied.slots);
        let cloned = copied.clone();
        assert!(!format!("{cloned:?}").is_empty());
        assert_eq!(cloned.discovery_attempts, 2);
        assert_eq!(cloned.mechanisms, 3);
        assert_eq!(cloned.sessions, 4);
        assert_eq!(cloned.slots, expected);
    }
}

#[test]
fn mechanism_info() {
    const BASE: MechanismInfo = MechanismInfo {
        flags: 2,
        maximum: 3,
        minimum: 4,
    };
    for expected in [0, 1, u64::MAX] {
        let value = MechanismInfo { flags: expected, ..BASE };
        let cloned = value.clone();
        assert!(!format!("{cloned:?}").is_empty());
        assert_eq!(cloned.flags, expected);
        assert_eq!(cloned.maximum, 3);
        assert_eq!(cloned.minimum, 4);
        assert_eq!(value, cloned);
        assert_eq!(matches!(value, BASE), expected == BASE.flags);
    }
    for expected in [0, 1, u64::MAX] {
        let value = MechanismInfo { maximum: expected, ..BASE };
        let cloned = value.clone();
        assert!(!format!("{cloned:?}").is_empty());
        assert_eq!(cloned.flags, 2);
        assert_eq!(cloned.maximum, expected);
        assert_eq!(cloned.minimum, 4);
        assert_eq!(value, cloned);
        assert_eq!(matches!(value, BASE), expected == BASE.maximum);
    }
    for expected in [0, 1, u64::MAX] {
        let value = MechanismInfo { minimum: expected, ..BASE };
        let cloned = value.clone();
        assert!(!format!("{cloned:?}").is_empty());
        assert_eq!(cloned.flags, 2);
        assert_eq!(cloned.maximum, 3);
        assert_eq!(cloned.minimum, expected);
        assert_eq!(value, cloned);
        assert_eq!(matches!(value, BASE), expected == BASE.minimum);
    }
}

#[test]
fn native_otp_limits() {
    const BASE: NativeOtpLimits = NativeOtpLimits {
        maximum_parameters: 2,
        maximum_value_bytes: 3,
    };
    for expected in [0, 1, usize::MAX] {
        let value = NativeOtpLimits { maximum_parameters: expected, ..BASE };
        let copied = value;
        assert_eq!(value.maximum_parameters, copied.maximum_parameters);
        let cloned = copied.clone();
        assert!(!format!("{cloned:?}").is_empty());
        assert_eq!(cloned.maximum_parameters, expected);
        assert_eq!(cloned.maximum_value_bytes, 3);
    }
    for expected in [0, 1, usize::MAX] {
        let value = NativeOtpLimits { maximum_value_bytes: expected, ..BASE };
        let copied = value;
        assert_eq!(value.maximum_value_bytes, copied.maximum_value_bytes);
        let cloned = copied.clone();
        assert!(!format!("{cloned:?}").is_empty());
        assert_eq!(cloned.maximum_parameters, 2);
        assert_eq!(cloned.maximum_value_bytes, expected);
    }
}

#[test]
fn object_search_selection() {
    const BASE: ObjectSearchSelection = ObjectSearchSelection {
        index: 2,
    };
    for expected in [0, 1, usize::MAX] {
        let value = ObjectSearchSelection { index: expected, ..BASE };
        let cloned = value.clone();
        assert!(!format!("{cloned:?}").is_empty());
        assert_eq!(cloned.index, expected);
        assert_eq!(value, cloned);
        assert_eq!(matches!(value, BASE), expected == BASE.index);
    }
}

#[test]
fn pss_params() {
    const BASE: PssParams = PssParams {
        hash: 2,
        mgf: 3,
        salt_length: 4,
    };
    for expected in [0, 1, u64::MAX] {
        let value = PssParams { hash: expected, ..BASE };
        let copied = value;
        assert_eq!(value.hash, copied.hash);
        let cloned = copied.clone();
        assert!(!format!("{cloned:?}").is_empty());
        assert_eq!(cloned.hash, expected);
        assert_eq!(cloned.mgf, 3);
        assert_eq!(cloned.salt_length, 4);
    }
    for expected in [0, 1, u64::MAX] {
        let value = PssParams { mgf: expected, ..BASE };
        let copied = value;
        assert_eq!(value.mgf, copied.mgf);
        let cloned = copied.clone();
        assert!(!format!("{cloned:?}").is_empty());
        assert_eq!(cloned.hash, 2);
        assert_eq!(cloned.mgf, expected);
        assert_eq!(cloned.salt_length, 4);
    }
    for expected in [0, 1, usize::MAX] {
        let value = PssParams { salt_length: expected, ..BASE };
        let copied = value;
        assert_eq!(value.salt_length, copied.salt_length);
        let cloned = copied.clone();
        assert!(!format!("{cloned:?}").is_empty());
        assert_eq!(cloned.hash, 2);
        assert_eq!(cloned.mgf, 3);
        assert_eq!(cloned.salt_length, expected);
    }
}

#[test]
fn session_info() {
    const BASE: SessionInfo = SessionInfo {
        device_error: 2,
        flags: 3,
        slot: 4,
        state: 5,
    };
    for expected in [0, 1, u64::MAX] {
        let value = SessionInfo { device_error: expected, ..BASE };
        assert!(!format!("{value:?}").is_empty());
        assert_eq!(value.device_error, expected);
        assert_eq!(value.flags, 3);
        assert_eq!(value.slot, 4);
        assert_eq!(value.state, 5);
    }
    for expected in [0, 1, u64::MAX] {
        let value = SessionInfo { flags: expected, ..BASE };
        assert!(!format!("{value:?}").is_empty());
        assert_eq!(value.device_error, 2);
        assert_eq!(value.flags, expected);
        assert_eq!(value.slot, 4);
        assert_eq!(value.state, 5);
    }
    for expected in [0, 1, u64::MAX] {
        let value = SessionInfo { slot: expected, ..BASE };
        assert!(!format!("{value:?}").is_empty());
        assert_eq!(value.device_error, 2);
        assert_eq!(value.flags, 3);
        assert_eq!(value.slot, expected);
        assert_eq!(value.state, 5);
    }
    for expected in [0, 1, u64::MAX] {
        let value = SessionInfo { state: expected, ..BASE };
        assert!(!format!("{value:?}").is_empty());
        assert_eq!(value.device_error, 2);
        assert_eq!(value.flags, 3);
        assert_eq!(value.slot, 4);
        assert_eq!(value.state, expected);
    }
}

#[test]
fn symmetric_limits() {
    const BASE: SymmetricLimits = SymmetricLimits {
        maximum_buffer_bytes: 2,
    };
    for expected in [0, 1, usize::MAX] {
        let value = SymmetricLimits { maximum_buffer_bytes: expected, ..BASE };
        let copied = value;
        assert_eq!(value.maximum_buffer_bytes, copied.maximum_buffer_bytes);
        let cloned = copied.clone();
        assert!(!format!("{cloned:?}").is_empty());
        assert_eq!(cloned.maximum_buffer_bytes, expected);
    }
}

#[test]
fn wrap_limits() {
    const BASE: WrapLimits = WrapLimits {
        maximum_output_bytes: 2,
    };
    for expected in [0, 1, usize::MAX] {
        let value = WrapLimits { maximum_output_bytes: expected, ..BASE };
        let copied = value;
        assert_eq!(value.maximum_output_bytes, copied.maximum_output_bytes);
        let cloned = copied.clone();
        assert!(!format!("{cloned:?}").is_empty());
        assert_eq!(cloned.maximum_output_bytes, expected);
    }
}
