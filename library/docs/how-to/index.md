# How To

These recipes use the Fe11 0.1.0 public API. Each explains the application inputs,
the native operation, the result and the ownership needed to handle failure.
The complete Rust sources are in [examples/how_to.rs](../../examples/how_to.rs)
and its modules: [setup](../../examples/how_to/setup.rs),
[operations](../../examples/how_to/operations.rs), [keys](../../examples/how_to/keys.rs),
[lifecycle](../../examples/how_to/lifecycle.rs) and [PQC](../../examples/how_to/pqc.rs).
They are ordinary library examples: the functions run
only when your application calls them.

| Task | Guide |
| --- | --- |
| Load a module, choose a token and open a session | [Module setup](module-setup.md) |
| Authenticate and preserve cleanup errors | [Authentication and lifecycle](authentication.md) |
| Hash messages and obtain random bytes | [Hashing and random data](hashing.md) |
| Find RSA objects, generate a pair and sign | [Keys and signatures](keys-and-signatures.md) |
| Encrypt and authenticate application records | [AES-GCM](aes-gcm.md) |
| Generate ML-DSA or SLH-DSA keys and sign | [PQC signatures](pqc-signatures.md) |
| Select external prehash or native message hashing | [PQC prehash modes](pqc-prehash.md) |
| Establish native shared keys with ML-KEM | [ML-KEM](ml-kem.md) |
| Select software public-key verification | [Verification engine](verification-engine.md) |
| Preserve native errors and incomplete outcomes | [Error handling](errors.md) |

## Use the examples

An application using all examples can declare:

```toml
[dependencies]
fe11 = "=0.1.0"
fe11-sys = "=0.1.0"
```

The direct `fe11-sys` dependency supplies standardized attribute constants in the
search example. The optional verification engine is built and loaded separately.
Choose a native module matching your application target and the required PKCS#11
interface. Module capability discovery helps select operations; their native
results determine whether a particular key and parameter combination succeeds.

From the Fe11 source workspace, type-check every recipe with:

```text
cargo check -p fe11 --example how_to
```

This command compiles the example library and its dependencies without calling a
PKCS#11 module. Supply paths, resource budgets, identities, credentials and key
policies from application configuration when integrating a recipe. Budget values
describe memory, handles and input sizes; derive them from the application workload.
The examples intentionally accept those values as arguments.

[All How To guides](index.md)
