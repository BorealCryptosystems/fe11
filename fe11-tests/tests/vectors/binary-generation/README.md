# Named binary curves

Numerical domain parameters are extracted from OpenSSL `crypto/ec/ec_curve.c`.
The manifest records the exact source SHA-256, named table and OID. Polynomial
coefficients and generator coordinates are unchanged; redundant leading zeroes
are removed or added only to encode the field width.

Copyright 2002-2026 The OpenSSL Project Authors. All Rights Reserved.
Copyright (c) 2002, Oracle and/or its affiliates. All rights reserved.
Licensed under Apache License 2.0; see the repository LICENSE.

The public-point equation is checked independently using polynomial arithmetic.
Generation is followed by ECDH against the standard generator: its result must
equal the generated public x coordinate. Private scalars are never exported.
A bounded native generation refusal records a characterization outcome and
does not claim curve support.
