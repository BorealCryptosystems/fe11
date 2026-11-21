# Fe11 public test suite 0.1.1

This source package exercises the public Rust API of Fe11 0.1.1 and its
interoperability with SoftHSM. It includes local contracts, native scenarios,
attributed reference vectors and the runner used to interpret each result.
Minimum Rust is 1.81; the validation matrix also includes Rust 1.100.

## Local API contracts

From the repository workspace:

```text
cargo test --locked -p fe11-tests --test local
```

From an extracted crate, use the included lockfile and the same command. It pins
the released `fe11 = 0.1.1` dependency. To intentionally resolve a new dependency
graph, run `cargo generate-lockfile` first and record the resulting lockfile.

## Native scenarios

Native cases run on Linux with a real module and disposable tokens. They create
and destroy test objects in isolated storage. Keys and vectors in this
package are public test fixtures, including private keys supplied solely for testing. The [suite guide](tests/README.md) describes token
provisioning, the module recipe, worker configuration and result interpretation.

An extracted Cargo package contains a compressed collection of native input
files. Restore and verify those files before building the native worker:

```text
python tests/driver/fixture_archive.py unpack
cargo test --locked --release -p fe11-tests --test native --no-run
```

The repository checkout already contains the expanded inputs. Native scenarios
are selected and launched by the case driver described in the guide; they are
kept separate from the default local test target.

Browse the [case catalogue](tests/vectors/CASES.md), each family's manifest and
its Rust assertions together. Results distinguish prerequisites, setup, body,
cleanup, native codes and process completion. The repository CI keeps raw
verdicts when it recognizes a documented module divergence or marks an affected
operation domain as unqualified. Read the [validation policy](https://github.com/BorealCryptosystems/fe11/blob/v0.1.1/VALIDATION.md)
alongside the original result.
