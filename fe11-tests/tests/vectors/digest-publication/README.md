# Digest publication and consumed-ticket behavior

Both eager and cooperative pacing use the exact fragments `a`, `b`, `c`.
The first digest result must be published by `AdvancedSession::poll`. The same
ticket is polled again: it must be rejected as consumed without a native call.
The first owned result remains byte-exact after session and module closure.

The observer requires one Init, three Updates and one Final. The bounded poll
loop covers those five synchronous steps and publication; it is not a timeout
estimate or an asynchronous-module claim.
