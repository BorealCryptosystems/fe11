# Preserve errors, effects and cleanup outcomes

Keep the original typed `Error` for programmatic handling. A short diagnostic can
identify the native function and return value without dumping inputs or secret
buffers:

```rust
use fe11::*;

pub fn diagnostic_summary(error: &Error) -> String {
    match error {
        Error::Native { function, code, may_have_effect } =>
            format!("{function}: code=0x{code:x}, may_have_effect={may_have_effect}"),
        Error::OperationCompleted { function, .. } =>
            format!("{function} completed; reconcile native effects and publication"),
        Error::SignatureBufferRequired(_) =>
            "Signature output capacity required; preserve the session and continuation".into(),
        Error::CipherBufferRequired(_) =>
            "Cipher output capacity required; preserve the session and continuation".into(),
        Error::Busy(reason) => format!("Resource or lifecycle unavailable: {reason:?}"),
        _ => format!("{error}"),
    }
}
```

This helper is a summary, not an exhaustive recovery dispatcher. Creation and
compound failures can wrap additional native/local causes; inspect those variants
in the [Error reference](https://borealcryptosystems.github.io/fe11/0.1.1/api/fe11/enum.Error.html). Record non-secret operation
identifiers and preserve all nested diagnostics for controlled reconciliation.

| Outcome | Application action |
| --- | --- |
| Native error | Preserve function, return code and effect uncertainty; decide recovery from the operation contract |
| `may_have_effect: true` | Reconcile possible native effects before retrying or destroying objects |
| `OperationCompleted` | The native call completed; resolve publication/observation failure without replaying it |
| Signature/cipher capacity result | Retain the request and operation owner; use the documented continuation |
| `CreatedObjects` observation failure | Retain created references and remainder; resolve observations or clean up explicitly |
| Cleanup failure | Keep it alongside the primary result and use the session/module recovery API |

The effect flag is not a transaction rollback guarantee. For example, a failed
creation observation can coexist with real native objects. A fresh initialization
or blind retry can duplicate effects. `BusyReason` and `RejectionReason` provide
typed local diagnoses; native failures retain their PKCS#11 codes.

Close resources in dependency order: complete or recover operations, release or
explicitly destroy objects according to their lifetime, close sessions, then close
the runtime owner. Preserve each failure. For incomplete native calls or loss of
the module, follow [error recovery](../error-recovery.md) and the corresponding
owner/drain API rather than assuming that dropping a reference proves cleanup.

[All How To guides](index.md)
