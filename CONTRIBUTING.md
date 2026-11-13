# Contributing

Maintained by **Boreal Cryptosystems**. Contact: Benoit de Mulder <bendemulder@borealcryptosystems.com>.
Use the [issue tracker](https://github.com/BorealCryptosystems/fe11/issues), or contact the maintainer
for coordination. Security reports go privately to security@borealcryptosystems.com.

Describe the expected PKCS#11 behavior, applicable specification section, affected
version and platform, and observed behavior. Distinguish library defects, module
behavior and unconfirmed hypotheses. Remove all secrets and identifying token data.

Keep changes focused, preserve API capabilities, explain ownership and unsafe
invariants, and document behavior and compatibility changes. Keep source files
under 1,000 physical lines by splitting responsibilities, not compressing code.
Do not introduce vendor-specific branches or silently retry failed operations.
Contributions are reviewed under Apache-2.0; preserve applicable third-party notices.

## Local validation

Use Rust 1.81 and 1.100 for compatibility checks. From a clean checkout, run the
public build/documentation driver described in [BUILDING.txt](BUILDING.txt).
On Linux, the [SoftHSM suite](ci/softhsm/README.md) creates disposable tokens
and checks ten named scenarios. Its package is `publish = false` and its sources
are separate from the library. `--workspace` also selects this package and the
optional verification engine; the default member remains `library`.

Pull requests run four build jobs (two operating systems and two compilers) and
two Linux SoftHSM jobs. Review each result and its recorded checkout identity.
The checked-in Cargo.lock fixes CI dependency versions. Release validation also
builds a fresh application without inheriting that lock, using the package
prepared for crates.io, to check the minimum compiler against registry resolution.
