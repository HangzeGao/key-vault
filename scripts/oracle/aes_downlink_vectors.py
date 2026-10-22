#!/usr/bin/env python3
"""Generate public TEST ONLY AES-256-ECB normative and data-field vectors."""

import hashlib
import sys
from pathlib import Path

import cryptography
from cryptography.hazmat.backends.openssl.backend import backend
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

VERSION = "50.0.2/OpenSSL-4.0.3"
REFERENCE = "https://nvlpubs.nist.gov/nistpubs/Legacy/SP/nistspecialpublication800-38a.pdf#F.1.5"
NIST_KEY = bytes.fromhex("603deb1015ca71be2b73aef0857d77811f352c073b6108d72d9810a30914dff4")
NIST_PLAIN = bytes.fromhex(
    "6bc1bee22e409f96e93d7e117393172aae2d8a571e03ac9c9eb76fac45af8e51"
    "30c81c46a35ce411e5fbc1191a0a52eff69f2445df4f9b17ad2b417be66c3710"
)
NIST_CIPHER = bytes.fromhex(
    "f3eed1bdb5d2a03c064b5a7e3db181f8591ccb10d410ed26dc5ba74a31362870"
    "b6ed21b99ca6f4f9f153e7b1beafed1d23304b7a39f9f3ff067d8d8f9e24ecc7"
)


def encrypt(key, plaintext):
    context = Cipher(algorithms.AES(key), modes.ECB()).encryptor()
    return context.update(plaintext) + context.finalize()


def row(identifier, source_class, source, key, plaintext, ciphertext):
    fields = [identifier, source_class, source, "AES_256_ECB", "VERIFY", key.hex(),
              "-", "-", plaintext.hex(), ciphertext.hex(), "-", "-", "-", "-", "OK",
              "pyca-cryptography", VERSION]
    canonical = "\t".join(fields)
    return canonical + "\t" + hashlib.sha256(canonical.encode("ascii")).hexdigest()


def main(destination):
    if cryptography.__version__ != "50.0.2" or backend.openssl_version_text() != "OpenSSL 4.0.3 29 Sep 2026":
        raise RuntimeError("AES oracle requires cryptography 50.0.2 / OpenSSL 4.0.3")
    if encrypt(NIST_KEY, NIST_PLAIN) != NIST_CIPHER:
        raise RuntimeError("AES oracle failed NIST SP 800-38A F.1.5")
    lines = ["# AES-256-ECB v1; public TEST ONLY; no IV, padding or Tag",
             "# generator_sha256=" + hashlib.sha256(Path(__file__).read_bytes()).hexdigest()]
    for block in range(4):
        start = block * 16
        lines.append(row(f"nist-ecb256-{block + 1}", "NORMATIVE", REFERENCE,
                         NIST_KEY, NIST_PLAIN[start:start + 16], NIST_CIPHER[start:start + 16]))
    cases = [("zero", bytes(32), bytes(880)),
             ("ones", bytes([255]) * 32, bytes([255]) * 880),
             ("incrementing", bytes(range(32)), bytes(i % 256 for i in range(880))),
             ("repeat", NIST_KEY, (NIST_PLAIN[:16] * 55))]
    # Every bit in the 256-bit key, plus a bit in every data block, is varied.
    for bit in range(256):
        key = bytearray(32)
        key[bit // 8] = 1 << (bit % 8)
        cases.append((f"key-bit-{bit}", bytes(key), bytes(880)))
    for block in range(55):
        plaintext = bytearray(880)
        plaintext[block * 16 + block % 16] = 1 << (block % 8)
        cases.append((f"data-block-{block}", bytes(32), bytes(plaintext)))
    for index in range(64):
        sample = hashlib.shake_256(f"kvlt-aes-downlink-v1/{index}".encode("ascii")).digest(912)
        cases.append((f"random-{index}", sample[:32], sample[32:]))
    for identifier, key, plaintext in cases:
        lines.append(row(identifier, "INDEPENDENT", "pyca-cryptography-50.0.2/OpenSSL-4.0.3",
                         key, plaintext, encrypt(key, plaintext)))
    content = ("\n".join(lines) + "\n").encode("ascii")
    destination.write_bytes(content)
    digest = hashlib.sha256(content).hexdigest()
    destination.with_suffix(destination.suffix + ".sha256").write_bytes(
        f"{digest}  {destination.name}\n".encode("ascii"))
    print(f"AES downlink oracle: {len(lines) - 2} records; sha256={digest}")


if __name__ == "__main__":
    main(Path(sys.argv[1]))
