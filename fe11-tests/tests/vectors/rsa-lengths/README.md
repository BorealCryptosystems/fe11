# RSA signature lengths

The public RSA-2048 SHA-256 reference key and signature are reused with the
original attribution. Each owner verifies the correct signature, then rejects
0-, 255- and 257-byte signatures with the native signature-length error.
The correct 256-byte signature is verified again after each refusal on the
same session. Single and Multipart paths have independently observed calls.
