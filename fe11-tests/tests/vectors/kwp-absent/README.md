# Absent AES key-wrap-with-padding selector

The public key, plaintext and envelope reproduce RFC 5649 section 6, first example.
R. Housley and M. Dworkin. Copyright (c) 2009 IETF Trust and the persons
identified as document authors. [Source](https://www.rfc-editor.org/rfc/rfc5649.html#section-6).

The fixture requests CKM_AES_KEY_WRAP_KWP, independently of CKM_AES_KEY_WRAP_PAD.
Both native calls must reject the absent selector; the envelope itself is valid.
