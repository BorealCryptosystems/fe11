# Public Rust ownership contracts

Run `driver/compile_contracts.py` with the compiler and Fe11 rlib from the same build. Each negative is paired with a valid borrowed-access control and requires its exact diagnostic code at its target expression. The runner emits metadata only. These functions are never executed and do not construct fake native owners.

The secret-owner inventory includes protected byte buffers, private-key input/export, plaintext batches and sensitive persistence records. Public ciphertext, signatures, key handles and configuration values are not classified as secret bytes. Logical closure and ticket consumption remain runtime contracts; the move cases use ordinary Rust value consumption.
