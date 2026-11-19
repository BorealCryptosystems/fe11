# Preparation and observer ownership

All cases use a single allowed total/read-write session. A refused SHA256
preparation must make no native call and preserve the owned quota; a subsequent
digest still produces the exact SHA256 answer for `abc`. Explicit close and
owner drop must restore the initial public resource status.

Dropping the observer of a closed-input batch retains session ownership under
both pacing policies. Cooperative has submitted only Init; Eager has completed
Init, three Updates and Final but has not published its output. No second Init
may be dispatched while that owner remains. Explicit close settles its quota.
Public resource_status reports session reservations, not internal byte credits.
