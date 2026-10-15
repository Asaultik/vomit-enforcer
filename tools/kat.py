#!/usr/bin/env python3
"""Independent reference implementation of vomit-core's derivations, using the
Python `cryptography` package. Prints the known-answer vectors the Rust tests
pin, so the two implementations check each other.

    pip install "cryptography>=44"
    python3 tools/kat.py           # print the vectors
    python3 tools/kat.py --check   # assert they match the ones the Rust tests pin
"""
import sys
import hmac
import hashlib
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms
from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305
from cryptography.hazmat.primitives.kdf.argon2 import Argon2id


def hkdf32(ikm: bytes, info: bytes) -> bytes:
    prk = hmac.new(bytes(32), ikm, hashlib.sha256).digest()
    return hmac.new(prk, info + b"\x01", hashlib.sha256).digest()


PRINTABLE = bytes(range(ord("!"), ord("~") + 1))
ALNUM = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789"
HEX = b"0123456789abcdef"


def render(seed: bytes, charset: bytes, length: int) -> bytes:
    key = hkdf32(seed, b"vomit-enforcer/v1/passphrase")
    # cryptography's ChaCha20 takes a 16 byte nonce: 4 byte LE counter + 12 byte nonce.
    enc = Cipher(algorithms.ChaCha20(key, bytes(16)), mode=None).encryptor()
    stream = enc.update(bytes(64 * 16))
    n = len(charset)
    limit = 256 - 256 % n
    return bytes(charset[b % n] for b in stream if b < limit)[:length]


def pin_bytes(pin) -> bytes:
    return bytes([len(pin)]) + b"".join(v.to_bytes(2, "big") for v in pin)


def stretch(pin, salt: bytes, blocks: int, passes: int) -> bytes:
    return Argon2id(salt=salt, length=32, iterations=passes, lanes=1, memory_cost=blocks).derive(pin_bytes(pin))


def seal_slot(pin, salt, slot, ctr, seed, charset_id, length, blocks, passes) -> bytes:
    k = stretch(pin, salt, blocks, passes)
    nonce = bytes([slot]) + ctr.to_bytes(4, "little") + bytes(7)
    aad = b"vomit-enforcer/v1/slot" + bytes([slot])
    return ChaCha20Poly1305(k).encrypt(nonce, seed + bytes([charset_id, length]), aad)


# The same values the Rust tests pin. Changing one side without the other fails CI.
EXPECTED = {
    "render printable 32": b"?*R+3r/dV%R!{k9e'1>WX-gK}\\lLh'<S",
    "render hex 16": b"c918f2800b17cd15",
    "argon2id": "3a51519ab8af15a8436ba94ce8f8fccede5ed1e037e814ee8f143a3dddf14203",
    "slot 3 seal": "52b9a3cb9e2532b9cf49141b2ce462dc8af311f46f50b0ada83672888df07612cbb01ba8c9cc602acbdcca238f13b1a3a6b2",
}


if __name__ == "__main__":
    got = {
        "render printable 32": render(bytes(32), PRINTABLE, 32),
        "render hex 16": render(bytes(32), HEX, 16),
        "argon2id": stretch([100, 64, 116], b"\x01" * 16, 8, 1).hex(),
        "slot 3 seal": seal_slot([5, 5], b"\x02" * 16, 3, 1, b"\x02" * 32, 2, 64, 8, 1).hex(),
    }
    for name, value in got.items():
        print(f"{name}: {value}")
    if "--check" in sys.argv:
        bad = [n for n in got if got[n] != EXPECTED[n]]
        if bad:
            sys.exit(f"MISMATCH: {', '.join(bad)}")
        print("all vectors match")
