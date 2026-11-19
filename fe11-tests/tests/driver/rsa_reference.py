# SPDX-License-Identifier: Apache-2.0
"""RSA encoding references for explicitly public test keys, never production keys.

Integer exponentiation and RFC 8017 decoding do not call Fe11 or the module.
Hashlib may share its hash implementation with the module's OpenSSL backend;
published digest known answers provide the separate hash controls.
"""
import hashlib
import hmac


HASHES = {"SHA-1": "sha1", "SHA-224": "sha224", "SHA-256": "sha256",
          "SHA-384": "sha384", "SHA-512": "sha512",
          "SHA3-224": "sha3_224", "SHA3-256": "sha3_256",
          "SHA3-384": "sha3_384", "SHA3-512": "sha3_512"}


def hashed(name, data):
    return hashlib.new(HASHES[name], data).digest()


def mgf1(name, seed, length):
    """RFC 8017 B.2.1 with the selected hash, including its four-byte counter."""
    if not 0 <= length <= 16384:
        raise ValueError("reference mask exceeds the fixture bound")
    width = len(hashed(name, b""))
    blocks = (hashed(name, seed + i.to_bytes(4, "big"))
              for i in range((length + width - 1) // width))
    return b"".join(blocks)[:length]


def xor(left, right):
    if len(left) != len(right):
        raise ValueError("reference XOR dimensions")
    return bytes(a ^ b for a, b in zip(left, right))


def representative(blob, modulus, exponent):
    """Require an exact modulus-sized RSA input and its canonical range."""
    if not 512 <= modulus.bit_length() <= 16384 or not 0 < exponent < modulus:
        raise ValueError("reference key is outside the public fixture bounds")
    width = (modulus.bit_length() + 7) // 8
    value = int.from_bytes(blob, "big")
    if len(blob) != width or value >= modulus:
        raise ValueError("noncanonical RSA representative")
    return pow(value, exponent, modulus).to_bytes(width, "big")


def verify_pss(signature, modulus, exponent, hash_name, mgf_name, salt_length,
               message, prehashed=False):
    """RFC 8017 9.1.2, exact salt length, no automatic salt-length inference."""
    if not 0 <= salt_length <= 16384:
        raise ValueError("reference salt length")
    em_bits = modulus.bit_length() - 1
    em_length = (em_bits + 7) // 8
    encoded = representative(signature, modulus, exponent)
    if any(encoded[:len(encoded) - em_length]):
        return False
    encoded = encoded[-em_length:]
    width = len(hashed(hash_name, b""))
    digest = message if prehashed else hashed(hash_name, message)
    if len(digest) != width or em_length < width + salt_length + 2:
        return False
    if encoded[-1] != 0xbc:
        return False
    masked, value = encoded[:-width - 1], encoded[-width - 1:-1]
    unused = em_length * 8 - em_bits
    if masked[0] & (0xff << (8 - unused)) & 0xff:
        return False
    decoded = bytearray(xor(masked, mgf1(mgf_name, value, len(masked))))
    decoded[0] &= 0xff >> unused
    padding = em_length - width - salt_length - 2
    if any(decoded[:padding]) or decoded[padding] != 1:
        return False
    salt = bytes(decoded[padding + 1:])
    if len(salt) != salt_length:
        return False
    return hmac.compare_digest(value, hashed(hash_name, b"\x00" * 8 + digest + salt))


def decrypt_oaep(ciphertext, modulus, private_exponent, hash_name, mgf_name, label):
    """RFC 8017 7.1.2; reject every malformed prefix, label hash and delimiter."""
    encoded = representative(ciphertext, modulus, private_exponent)
    width = len(hashed(hash_name, b""))
    if len(encoded) < 2 * width + 2 or encoded[0] != 0:
        raise ValueError("invalid OAEP leading byte or length")
    masked_seed, masked_db = encoded[1:1 + width], encoded[1 + width:]
    seed = xor(masked_seed, mgf1(mgf_name, masked_db, width))
    decoded = xor(masked_db, mgf1(mgf_name, seed, len(masked_db)))
    if not hmac.compare_digest(decoded[:width], hashed(hash_name, label)):
        raise ValueError("invalid OAEP label hash")
    delimiter = width
    while delimiter < len(decoded) and decoded[delimiter] == 0:
        delimiter += 1
    if delimiter == len(decoded) or decoded[delimiter] != 1:
        raise ValueError("invalid OAEP padding delimiter")
    return decoded[delimiter + 1:]
