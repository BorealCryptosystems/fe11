# DH domain object identity

These cases reuse the public NIST FFC key material and shared-secret answers
whose exact provenance is recorded in the manifest. A domain object is created
and its class, key type, prime and generator are read back. The private-key
import consumes the returned domain bytes, then derives the published shared
secret. Domain, base and derived objects retain independent cleanup ownership.
