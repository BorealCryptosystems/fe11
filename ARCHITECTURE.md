# Architecture and safety

The public `Module` and session owners control loaded images, native resources
and the memory lent to native calls. Raw declarations come from fe11-sys. Managed
objects retain their provenance; observations are not reservations of native state.
Typed parameters represent mechanisms and attributes while the module decides
their cryptographic acceptability. Native return codes remain observable.

Advanced operations retain buffers, completion records and resource credits
across continuation, cancellation or uncertain native outcomes. Four facts are
distinct: memory returned, sequence finished, native effect established, and
context retained. A native error does not universally establish all four.
See CONTRACTS.md and COEXISTENCE.txt for cleanup and recovery responsibilities.

Resource admission is explicit and configurable. Waiting for local capacity does
not interrupt a native C call. Calls on one session are serialized. External
intraprocess participants need the documented coordination contract; separate
processes may use the same token without sharing Fe11's local state.

Unsafe boundaries validate representation, lengths and ownership. They assume
a trustworthy native implementation and a compatible ABI. Retaining an image
does not prevent another owner from finalizing its runtime. Returned pointers,
callbacks, external initialization and module loading have specific Safety contracts.

The optional verification component is isolated behind a versioned C ABI. It is
explicitly selected and loaded, and has its own static OpenSSL build. The core
library does not depend on OpenSSL and does not silently fall back to this engine.

Secrets avoid implicit Debug/Clone where documented and owned secret buffers are
erased on their defined release paths. Caller copies, native-module copies and
buffers retained for unproven native execution remain outside that guarantee.
See library/docs/ownership.md for the exact public type boundaries.
