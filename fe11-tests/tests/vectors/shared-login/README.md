# Shared authentication

Two independently opened read-write sessions share one disposable token.
Session B authenticates; session A uses a private token key and must produce
the independent HMAC answer. After B logs out, A reports the public state and
cannot read the retained private reference. Cleanup authenticates again and
finds a fresh reference to the persistent object before destroying it.
