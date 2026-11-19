# Trusted wrapping keys

The Security Officer provisions trusted and untrusted AES wrapping keys with
the same public test value on an isolated token. A WRAP_WITH_TRUSTED target
rejects the untrusted key. The trusted key is read back and must produce the
RFC3394 section4.1 envelope. Both public session owners execute the comparison.
Trust is supplied at creation; the scenario does not require that attribute
to be mutable later. Each object and session has independent cleanup.
