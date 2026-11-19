# Token persistence and store isolation

Independent Fe11 processes exchange ownership of a public token data object.
The first process closes its session and module; the second searches by label,
checks the exact bytes and destroys the object. A separate composition inserts
a second newly provisioned token store with identical token and object labels.
It must initially contain no matching object, hold its own distinct value, and
leave the first store unchanged. Every actor has a separate native trace and
cleanup verdict. Session handles and session objects are never transferred.
