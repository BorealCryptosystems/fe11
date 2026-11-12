# Ownership and confidentiality boundaries

These types impose ownership and confidentiality boundaries. Borrowing bytes
explicitly remains possible where documented; caller-made copies remain
the caller's responsibility. No formatting or duplication is implicit.

`Module` does not implement `Clone`.

`SecretPin` does not implement `Clone`.

`SecretBytes` does not implement `Clone`.

`SecretPlaintext` does not implement `Clone`.

`AeadPlaintext` does not implement `Clone`.

`PqcPrivateInput` does not implement `Clone`.

`PqcPrivateExport` does not implement `Clone`.

`DetachedOperation` does not implement `Clone`.

`DetachedOperationRecord` does not implement `Clone`.

`NativeStateRecord` does not implement `Clone`.

`CallerAssertedAuthenticatedRecord` does not implement `Clone`.

`SavedOperationState` does not implement `Clone`.

`OperationTicket` does not implement `Clone`.

`SecretPin` does not implement `Debug`.

`SecretBytes` does not implement `Debug`.

`SecretPlaintext` does not implement `Debug`.

`AeadPlaintext` does not implement `Debug`.

`PqcPrivateInput` does not implement `Debug`.

`PqcPrivateExport` does not implement `Debug`.

`DetachedOperation` does not implement `Debug`.

`DetachedOperationRecord` does not implement `Debug`.

`NativeStateRecord` does not implement `Debug`.

`CallerAssertedAuthenticatedRecord` does not implement `Debug`.

`SavedOperationState` does not implement `Debug`.

`GcmRecoveryRecord` does not implement `Debug`.

`DualRecoveryRecord` does not implement `Debug`.

`WrappedKey` does not implement `Debug`.

`GcmPlaintexts` does not implement `Debug`.

`UnauthenticatedPlaintext` does not implement `Debug`.

Native references do not expose their private identity storage.

Internal PKCS#11 declarations are not a public Rust module.

