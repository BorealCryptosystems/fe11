# Byte-credit release after refused capture

A public oversized-request diagnostic sets the caller's budget, including
resident module storage. After an ordinary digest completes, a bounded binary
search measures the largest random request with the actual Advanced owner still
retained. The search uses only public requests and exact local budget refusals.
The upper bound is 64 MiB; 26 iterations reach adjacent byte counts. Each
iteration includes exactly one native random call: its successful probe, or a
separate zero-length control after a local Busy refusal. Every output is erased
and dropped before the next request. No secret bytes are logged.

The same owner then starts a fresh digest, observes the module's
`CKR_FUNCTION_NOT_SUPPORTED` capture refusal, and completes the original ticket
with the SHA-256 known answer for `abc`. After releasing its result and ticket,
the same maximal random request must still succeed. A retained byte would make
that request inadmissible. No private memory size, session-quota proxy or
process RSS is used, and no execution speed is required.
