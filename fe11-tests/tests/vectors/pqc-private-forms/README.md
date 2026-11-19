# PQC private representations

Published NIST ACVP key-generation tuples bind the seed, expanded private key
and public key. Each fixture selects exactly one public import form. ML-KEM
seeds are d followed by z. Native signing/verification or encapsulation/
decapsulation checks correspondence to the supplied public key. Test reports
contain only assertions and error codes, never generated shared secrets.

A native refusal remains an attributed failure; creation metadata alone does
not establish operational use. No private representation is substituted.
