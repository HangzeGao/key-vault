#!/usr/bin/env python3
"""Generate public TEST ONLY vectors with pyca/cryptography's OpenSSL backend."""

from __future__ import annotations

import hashlib
import sys
from dataclasses import dataclass
from pathlib import Path


import cryptography
from cryptography.hazmat.backends.openssl.backend import backend
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.cmac import CMAC


EXPECTED_CRYPTOGRAPHY_VERSION = "49.0.0"
EXPECTED_OPENSSL_VERSION = "OpenSSL 4.0.1 9 Jun 2026"
RFC8998 = "https://www.rfc-editor.org/rfc/rfc8998.html#appendix-A.1"
SM4_REFERENCE = "GB/T-32907-2016-example-1"
HCTR_REFERENCE = "GB/T-17964-2021-chapter-11-project-profile-v1"
KDF_REFERENCE = "NIST-SP-800-108r1-counter-mode-project-encoding-v1"
CRYPTOGRAPHY_REFERENCE = "https://cryptography.io/en/49.0.0/hazmat/primitives/symmetric-encryption/#cryptography.hazmat.primitives.ciphers.algorithms.SM4"
VERSION = f"{cryptography.__version__}/OpenSSL-4.0.1"


@dataclass(frozen=True)
class Vector:
    id: str
    source_class: str
    source_reference: str
    algorithm: str
    key: bytes = b""
    nonce: bytes = b""
    aad: bytes = b""
    plaintext: bytes = b""
    ciphertext: bytes = b""
    tag: bytes = b""
    label: bytes = b""
    context: bytes = b""
    output: bytes = b""
    generator: str = "pyca-cryptography"
    generator_version: str = VERSION

    def line(self) -> str:
        fields = [
            self.id, self.source_class, self.source_reference, self.algorithm,
            "VERIFY", encode(self.key), encode(self.nonce), encode(self.aad),
            encode(self.plaintext), encode(self.ciphertext), encode(self.tag),
            encode(self.label), encode(self.context), encode(self.output), "OK",
            self.generator, self.generator_version,
        ]
        canonical = "\t".join(fields)
        return f"{canonical}\t{hashlib.sha256(canonical.encode('ascii')).hexdigest()}"


def encode(value: bytes) -> str:
    return value.hex() if value else "-"


def decode(value: str) -> bytes:
    return bytes.fromhex(value)


def sm4_block(key: bytes, block: bytes, encrypt: bool = True) -> bytes:
    if len(key) != 16 or len(block) != 16:
        raise ValueError("SM4 block input must be 16 bytes")
    context = Cipher(algorithms.SM4(key), modes.ECB()).encryptor() if encrypt else \
        Cipher(algorithms.SM4(key), modes.ECB()).decryptor()
    output = context.update(block) + context.finalize()
    if len(output) != 16:
        raise RuntimeError("cryptography SM4 block output length mismatch")
    return output


def cmac(key: bytes, message: bytes) -> bytes:
    context = CMAC(algorithms.SM4(key))
    context.update(message)
    tag = context.finalize()
    if len(tag) != 16:
        raise RuntimeError("cryptography SM4-CMAC output length mismatch")
    return tag


def gcm(key: bytes, nonce: bytes, aad: bytes, plaintext: bytes) -> tuple[bytes, bytes]:
    context = Cipher(algorithms.SM4(key), modes.GCM(nonce)).encryptor()
    context.authenticate_additional_data(aad)
    ciphertext = context.update(plaintext) + context.finalize()
    if len(context.tag) != 16:
        raise RuntimeError("cryptography SM4-GCM tag length mismatch")
    return ciphertext, context.tag


def xor(left: bytes, right: bytes) -> bytes:
    if len(left) != len(right):
        raise ValueError("xor length mismatch")
    return bytes(a ^ b for a, b in zip(left, right, strict=True))


def multiply(left: bytes, right: bytes) -> bytes:
    accumulator = bytearray(16)
    value = bytearray(right)
    for bit in range(128):
        if left[bit // 8] & (0x80 >> (bit % 8)):
            for index in range(16):
                accumulator[index] ^= value[index]
        lsb = value[15] & 1
        carry = 0
        for index in range(16):
            next_carry = value[index] & 1
            value[index] = (value[index] >> 1) | (carry << 7)
            carry = next_carry
        if lsb:
            value[0] ^= 0xE1
    return bytes(accumulator)


def universal_hash(hash_key: bytes, tweak: bytes, message: bytes) -> bytes:
    state = bytes(16)
    offset = 0
    while len(message) - offset >= 16:
        state = multiply(xor(state, message[offset:offset + 16]), hash_key)
        offset += 16
    remaining = len(message) - offset
    if remaining == 0:
        state = multiply(xor(state, tweak), hash_key)
    else:
        block = bytearray(message[offset:] + tweak[:16 - remaining])
        state = multiply(xor(state, bytes(block)), hash_key)
        block[:16 - remaining] = tweak[remaining:]
        block[remaining:] = bytes(16 - remaining)
        state = multiply(xor(state, bytes(block)), hash_key)
    length_block = bytes(8) + ((len(message) + 16) * 8).to_bytes(8, "big")
    return multiply(xor(state, length_block), hash_key)


def ctr_xor(key: bytes, base: bytes, value: bytes) -> bytes:
    output = bytearray(len(value))
    for offset in range(0, len(value), 16):
        number = offset // 16 + 1
        stream = sm4_block(key, xor(base, bytes(8) + number.to_bytes(8, "big")))
        count = min(16, len(value) - offset)
        for index in range(count):
            output[offset + index] = value[offset + index] ^ stream[index]
    return bytes(output)


def hctr(working_key: bytes, tweak: bytes, value: bytes, encrypt: bool) -> bytes:
    cipher_key, hash_key = working_key[:16], working_key[16:]
    tail = value[16:]
    if encrypt:
        z1 = xor(universal_hash(hash_key, tweak, tail), value[:16])
        z2 = sm4_block(cipher_key, z1)
        base = xor(z1, z2)
        output_tail = ctr_xor(cipher_key, base, tail)
        return xor(z2, universal_hash(hash_key, tweak, output_tail)) + output_tail
    z2 = xor(universal_hash(hash_key, tweak, tail), value[:16])
    z1 = sm4_block(cipher_key, z2, False)
    base = xor(z2, z1)
    output_tail = ctr_xor(cipher_key, base, tail)
    return xor(z1, universal_hash(hash_key, tweak, output_tail)) + output_tail


def counter_kdf(key: bytes, label: bytes, context: bytes, output_length: int) -> bytes:
    output = bytearray()
    counter = 1
    while len(output) < output_length:
        value = (
            counter.to_bytes(4, "big") + label + b"\x00" + context +
            (output_length * 8).to_bytes(4, "big")
        )
        output.extend(cmac(key, value))
        counter += 1
    return bytes(output[:output_length])


def pattern(length: int, seed: int) -> bytes:
    output = bytearray(length)
    state = seed
    for index in range(length):
        state = (state * 33 + 17) & 0xFF
        output[index] = state
    return bytes(output)


def vectors() -> list[Vector]:
    result: list[Vector] = []
    standard_key = decode("0123456789abcdeffedcba9876543210")
    standard_ciphertext = sm4_block(standard_key, standard_key)
    if standard_ciphertext.hex() != "681edf34d206965e86b3e94f536e4246":
        raise RuntimeError("cryptography failed the normative SM4 KAT")
    result.append(Vector("sm4-block-gbt-example-1", "NORMATIVE", SM4_REFERENCE,
                         "SM4_BLOCK", standard_key, plaintext=standard_key,
                         ciphertext=standard_ciphertext))
    for index in range(4):
        key = pattern(16, index * 0x31)
        plaintext = pattern(16, 0xA5 ^ index)
        result.append(Vector(f"sm4-block-cryptography-{index}", "INDEPENDENT",
                             CRYPTOGRAPHY_REFERENCE, "SM4_BLOCK", key,
                             plaintext=plaintext, ciphertext=sm4_block(key, plaintext)))

    for length in (0, 1, 15, 16, 17, 31, 32, 64):
        message = pattern(length, 0x40 + length)
        result.append(Vector(f"sm4-cmac-cryptography-len-{length}", "INDEPENDENT",
                             CRYPTOGRAPHY_REFERENCE, "SM4_CMAC", standard_key,
                             plaintext=message, tag=cmac(standard_key, message)))

    rfc_plaintext = decode(
        "aaaaaaaaaaaaaaaabbbbbbbbbbbbbbbbccccccccccccccccdddddddddddddddd"
        "eeeeeeeeeeeeeeeeffffffffffffffffeeeeeeeeeeeeeeeeaaaaaaaaaaaaaaaa"
    )
    result.append(Vector(
        "sm4-gcm-rfc8998-a1", "NORMATIVE", RFC8998, "SM4_GCM", standard_key,
        nonce=decode("00001234567800000000abcd"),
        aad=decode("feedfacedeadbeeffeedfacedeadbeefabaddad2"),
        plaintext=rfc_plaintext,
        ciphertext=decode(
            "17f399f08c67d5ee19d0dc9969c4bb7d5fd46fd3756489069157b282bb200735"
            "d82710ca5c22f0ccfa7cbf93d496ac15a56834cbcf98c397b4024a2691233b8d"
        ),
        tag=decode("83de3541e4c2b58177e065a9bf7b62ec"),
        generator="RFC-8998", generator_version="Appendix-A.1",
    ))
    for length in (0, 1, 15, 17, 33):
        key = pattern(16, 0x10 + length)
        nonce = pattern(12, 0x70 + length)
        aad = pattern(0 if length % 5 == 0 else length + 3, 0x90 + length)
        plaintext = pattern(length, 0xC0 + length)
        ciphertext, tag = gcm(key, nonce, aad, plaintext)
        result.append(Vector(f"sm4-gcm-cryptography-len-{length}", "INDEPENDENT",
                             CRYPTOGRAPHY_REFERENCE, "SM4_GCM", key,
                             nonce=nonce, aad=aad, plaintext=plaintext,
                             ciphertext=ciphertext, tag=tag))

    working_key = decode(
        "2b7e151628aed2a6abf7158809cf4f3c000102030405060708090a0b0c0d0e0f"
    )
    tweak = decode("f0f1f2f3f4f5f6f7f8f9fafbfcfdfeff")
    for length in (16, 17, 31, 32, 33, 64, 1011):
        plaintext = pattern(length, 0x20 + length)
        ciphertext = hctr(working_key, tweak, plaintext, True)
        if hctr(working_key, tweak, ciphertext, False) != plaintext:
            raise RuntimeError(f"independent HCTR reference failed length {length}")
        result.append(Vector(f"sm4-hctr-cryptography-ref-len-{length}", "INDEPENDENT",
                             HCTR_REFERENCE + "+" + CRYPTOGRAPHY_REFERENCE,
                             "SM4_HCTR", working_key, nonce=tweak,
                             plaintext=plaintext, ciphertext=ciphertext,
                             generator="pyca-cryptography+independent-HCTR-reference",
                             generator_version=f"{VERSION}/profile-v1"))

    ordinary_label = b"TC-TRAFFIC"
    ordinary_context = decode("123401001320010000000700000009")
    result.append(Vector("sm4-kdf-cryptography-tc-traffic", "INDEPENDENT",
                         KDF_REFERENCE + "+" + CRYPTOGRAPHY_REFERENCE,
                         "SP800_108_SM4_CMAC", standard_key,
                         label=ordinary_label, context=ordinary_context,
                         output=counter_kdf(standard_key, ordinary_label, ordinary_context, 32),
                         generator="pyca-cryptography+SP800-108-reference",
                         generator_version=f"{VERSION}/profile-v1"))
    recovery_label = b"TC-RECOVERY-GCM"
    recovery_context = decode("12340002700200000003")
    result.append(Vector("sm4-kdf-cryptography-recovery", "INDEPENDENT",
                         KDF_REFERENCE + "+" + CRYPTOGRAPHY_REFERENCE,
                         "SP800_108_SM4_CMAC", standard_key,
                         label=recovery_label, context=recovery_context,
                         output=counter_kdf(standard_key, recovery_label, recovery_context, 16),
                         generator="pyca-cryptography+SP800-108-reference",
                         generator_version=f"{VERSION}/profile-v1"))
    return result


def render() -> bytes:
    if cryptography.__version__ != EXPECTED_CRYPTOGRAPHY_VERSION:
        raise RuntimeError(
            f"expected cryptography {EXPECTED_CRYPTOGRAPHY_VERSION}, got {cryptography.__version__}"
        )
    if backend.openssl_version_text() != EXPECTED_OPENSSL_VERSION:
        raise RuntimeError(
            f"expected {EXPECTED_OPENSSL_VERSION}, got {backend.openssl_version_text()}"
        )
    rows = vectors()
    generator_sha256 = hashlib.sha256(Path(__file__).read_bytes()).hexdigest()
    lines = [
        "# format=kvlt-external-crypto-v1",
        f"# generator=pyca/cryptography {VERSION}; RFC 8998 Appendix A.1",
        f"# generator_sha256={generator_sha256}",
        "# all key material is public TEST ONLY material",
        "# id\tsource_class\tsource_reference\talgorithm\toperation\tkey\tnonce_or_tweak\taad\tplaintext\tciphertext\ttag\tlabel\tcontext\toutput\texpected_status\tgenerator\tgenerator_version\tsha256",
        *(vector.line() for vector in rows),
    ]
    return ("\n".join(lines) + "\n").encode("ascii")


def main() -> None:
    content = render()
    if len(sys.argv) == 1 or sys.argv[1] == "-":
        sys.stdout.buffer.write(content)
        print(f"SHA256={hashlib.sha256(content).hexdigest()}", file=sys.stderr)
        return
    if len(sys.argv) != 2:
        raise SystemExit("usage: cryptography_vector_generator.py [OUTPUT|-]")
    output = Path(sys.argv[1])
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_bytes(content)
    output.with_suffix(output.suffix + ".sha256").write_bytes(
        f"{hashlib.sha256(content).hexdigest()}  {output.name}\n".encode("ascii")
    )
    print(f"generated {len(vectors())} vectors: {output}")


if __name__ == "__main__":
    main()
