# Cancellation of a waiting resource request

This Linux integration case observes its own worker through `/proc/thread-self`
and `/proc/<pid>/task/<tid>/wchan`. The worker publishes its identity before an
atomic phase interval containing only the Fe11 request. A futex wait in that
interval, no held Fe11 guard in another thread, occupied output storage and
zero native calls distinguish a blocked admission from a merely scheduled
thread. Restricted procfs visibility is a missing prerequisite, never a PASS.

The caller cancels before releasing the retained output, joins the worker,
checks `AdmissionCancelled`, and then reuses the same session after release.
The one-hour deadline bounds a failed observation; no execution speed is
required. The polling interval only avoids spinning the supervisor CPU.
