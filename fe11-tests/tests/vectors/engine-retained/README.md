# Retained public verification evidence

These public NIST vectors use the Rust `PqcPublicKey::verify` API for each ML-DSA
and SLH-DSA parameter set. The initial engine is moved into a module and a clone
is retained. Verification then continues after both closing and dropping that
module. The same valid evidence is bound to its message, public key and context;
each changed binding must give `Verification::Invalid`, not an operational error.
The manifest retains both published key sources. No private key is included.
