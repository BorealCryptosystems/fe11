# Authenticate and close a session

Obtain PIN bytes from the application's secret-input facility and transfer the
owned bytes to `SecretPin::new`. Keep PINs out of command lines, source files and
logs. `SecretPin` manages its owned storage; copies previously made by your
application remain your responsibility. A protected authentication path uses
`PinRequest::ProtectedPath` when supported by the token.

Use `Session::login_as(LoginRole::User, pin)` to authenticate through the exact
session. Login and Logout change token-wide authentication. Use the helper below
only when your application coordinates that authentication lifecycle. An
already-logged-in native result does not validate a newly supplied PIN.

```rust
use fe11::*;

pub struct SessionRun<T> {
    pub operation: Result<T>,
    pub logout: Option<Result<()>>,
    pub close: Result<()>,
}

pub fn authenticated_run<T>(
    session: &Session, pin: SecretPin,
    work: impl FnOnce(&Session) -> Result<T>,
) -> SessionRun<T> {
    let login = session.login_as(LoginRole::User, pin);
    let logged_in = login.is_ok();
    let operation = login.and_then(|()| work(session));
    let logout = if logged_in { Some(session.logout()) } else { None };
    let close = session.close();
    SessionRun { operation, logout, close }
}
```

The closure should finish its native operations, release session-bound references
and return application-owned values, such as signature bytes. Examine all three
results independently: an operation failure does not hide a Logout or Close
failure. The borrowed session remains available for explicit recovery. This
helper covers normal Rust returns, including `Err`; panic handling is a separate
application boundary.

An operation requiring `CKA_ALWAYS_AUTHENTICATE` uses the operation's
`ContextAuthentication` path, such as `sign_pqc_with_context`. That authentication
is distinct from a PQC signature's binary domain-separation context.

## Share initialization within an application

```rust
use fe11::*;

pub fn shared_runtime(
    config: ModuleConfig, options: ModuleOptions,
) -> Result<(RuntimeOwner, Module)> {
    Module::builder(config, options).open_shared()
}
```

Retain `RuntimeOwner` for the initialization lifetime. Create additional ordinary
clients with `owner.client()`. Close each client's sessions and release its
objects before finalizing through `owner.module().close()`. Coordinate foreign
PKCS#11 participants using the explicit [coexistence contract](https://borealcryptosystems.github.io/fe11/0.1.0/COEXISTENCE.txt).
Reference: [RuntimeOwner](https://borealcryptosystems.github.io/fe11/0.1.0/api/fe11/struct.RuntimeOwner.html),
[Session](https://borealcryptosystems.github.io/fe11/0.1.0/api/fe11/struct.Session.html), [ModuleDrain](https://borealcryptosystems.github.io/fe11/0.1.0/api/fe11/struct.ModuleDrain.html).

[All How To guides](index.md)
