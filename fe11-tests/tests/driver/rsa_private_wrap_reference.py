# SPDX-License-Identifier: Apache-2.0
"""Decode the envelope of a published RSA test key outside the PKCS#11 module."""
import ctypes
import hashlib
from pathlib import Path

from rsa_reference import decrypt_oaep
from run import digest


def unwrap(key, ciphertext, library):
    """Use the recipe's OpenSSL EVP entry points, keeping the AES key in memory."""
    widths = {16: "128", 24: "192", 32: "256"}
    if len(key) not in widths or not 16 <= len(ciphertext) <= 4096 or len(ciphertext) % 8:
        raise ValueError("invalid KWP fixture dimensions")
    pointer = ctypes.c_void_p
    integer = ctypes.c_int

    def bind(name, result, *arguments):
        function = getattr(library, name)
        function.restype = result
        function.argtypes = arguments
        return function

    allocate = bind("EVP_CIPHER_CTX_new", pointer)
    release = bind("EVP_CIPHER_CTX_free", None, pointer)
    allow = bind("EVP_CIPHER_CTX_set_flags", None, pointer, integer)
    cipher = bind("EVP_aes_" + widths[len(key)] + "_wrap_pad", pointer)
    init = bind("EVP_DecryptInit_ex", integer, pointer, pointer, pointer, pointer, pointer)
    update = bind("EVP_DecryptUpdate", integer, pointer, pointer,
                  ctypes.POINTER(integer), pointer, integer)
    finish = bind("EVP_DecryptFinal_ex", integer, pointer, pointer, ctypes.POINTER(integer))
    context = allocate()
    if not context:
        raise ValueError("KWP context allocation")
    try:
        # EVP_CIPHER_CTX_FLAG_WRAP_ALLOW is required for wrap-mode EVP ciphers.
        allow(context, 1)
        if init(context, cipher(), None, key, None) != 1:
            raise ValueError("KWP reference initialization")
        # EVP reserves one extra block per call. Leave separate space for Final.
        output = ctypes.create_string_buffer(len(ciphertext) + 32)
        n = integer()
        tail = integer()
        if update(context, output, ctypes.byref(n), ciphertext, len(ciphertext)) != 1:
            return None
        if not 0 <= n.value <= len(ciphertext) + 16:
            raise ValueError("KWP update length")
        if finish(context, ctypes.byref(output, n.value), ctypes.byref(tail)) != 1:
            return None
        if not 0 <= tail.value <= 16:
            raise ValueError("KWP final length")
        return output.raw[:n.value + tail.value]
    finally:
        release(context)


def verify(case, vector, directory, gate):
    for source in ["rsa_private_wrap_reference.py", "rsa_reference.py"]:
        if digest(Path(__file__).with_name(source)) != case["reference_sources"][source]:
            raise ValueError("private-wrap reference changed")
    images = [item for item in gate["dependencies"] if Path(item["path"]).name.startswith("libcrypto.so")]
    if len(images) != 1:
        raise ValueError("reference requires one pinned crypto image")
    image = Path(images[0]["path"])
    if not image.is_absolute() or image.resolve(strict=True) != image or digest(image) != images[0]["sha256"]:
        raise ValueError("unexpected reference image")
    library = ctypes.CDLL(str(image))
    # RFC 5649 section 6, 20-octet example. The same reference must also detect
    # a changed envelope before it can attest to a native output.
    known_key = bytes.fromhex("5840df6e29b02af1ab493b705bf16ea1ae8338f4dcc176a8")
    known_cipher = bytes.fromhex("138bdeaa9b8fa7fc61f97742e72248ee5ae6ae5360d1ae6a5f54f373fa543b6a")
    known = bytes.fromhex("c37b7e6492584340bed12207808941155068f738")
    if unwrap(known_key, known_cipher, library) != known:
        raise ValueError("RFC 5649 reference mismatch")
    if unwrap(known_key, known_cipher[:-1] + bytes([known_cipher[-1] ^ 1]), library) is not None:
        raise ValueError("KWP integrity control")
    fields = vector.read_text().splitlines()
    output = directory / "public-wrap-ciphertext.bin"
    if len(fields) != 12 or output.is_symlink() or not output.is_file() or not 272 <= output.stat().st_size <= 2048:
        raise ValueError("private wrapping fixture")
    wire = output.read_bytes()
    modulus, exponent = int(fields[2], 16), int(fields[4], 16)
    width = (modulus.bit_length() + 7) // 8
    key = decrypt_oaep(wire[:width], modulus, exponent, "SHA-256", "SHA-256", b"")
    plain = unwrap(key, wire[width:], library)
    valid = (len(key) * 8 == case["parameters"]["aes_bits"] and plain is not None and
             hashlib.sha256(plain).hexdigest() == case["parameters"]["pkcs8_sha256"])
    return dict(status="PASS" if valid else "FAIL", ciphertext_sha256=hashlib.sha256(wire).hexdigest(),
                library_sha256=images[0]["sha256"], boundary="Independent RSA decoding and EVP KWP; AES backend shared with the module")
