#!/usr/bin/env python3
"""Regenerate the public TC interoperability frames with a legal test SCID."""

from pathlib import Path
from struct import pack

from cryptography import __version__
from cryptography.hazmat.backends.openssl.backend import backend
from cryptography_vector_generator import counter_kdf, gcm


def crc16(value: bytes) -> bytes:
    crc = 0xffff
    for byte in value:
        crc ^= byte << 8
        for _ in range(8):
            crc = ((crc << 1) ^ (0x1021 if crc & 0x8000 else 0)) & 0xffff
    return pack(">H", crc)


def regenerate(path: Path) -> None:
    lines = path.read_text().splitlines()
    values = dict(line.split("=", 1) for line in lines if line and not line.startswith("#"))
    root = bytes.fromhex(values["root"])
    data = bytes.fromhex(values["plaintext"])
    prefix = bytes.fromhex(values["nonce_prefix"])
    spi = int(values["spi"], 16)
    iv = int(values["iv_counter"], 16)
    root_version = int(values["root_version"])
    header = bytes.fromhex(values["protected_frame"])[:5]
    spacecraft = int.from_bytes(header[:2], "big") & 0x03ff
    spi_iv = pack(">HI", spi, iv)
    if values["suite_id"] == "SM4_GCM_32":
        iv=9
        epoch = int(values["security_epoch"])
        context = pack(">HBHHII", spacecraft, 1, 3, spi, epoch, root_version)
        key = counter_kdf(root, b"TC-GCM32-V1", context, 16)
        control=pack(">H", (epoch%3)<<14|iv)
        encrypted,tag=gcm(key,prefix+pack(">HI",spi,iv),header+control,data)
        frame=header+control+tag[:4]+encrypted
    elif values["suite_id"] == "SM4_GCM":
        data=bytes([2])+data[1:23]+pack(">H",3)+data[25:]
        context = pack(">HHHI", spacecraft, 2, spi, root_version)
        key = counter_kdf(root, b"TC-GCM128-RECOVERY-V1", context, 16)
        security=pack(">HI",0xc000,iv)
        encrypted,tag=gcm(key,prefix+spi_iv,header+security,data)
        frame=header+security+encrypted+tag
    else:
        raise ValueError("unsupported TC vector suite")
    replacements = {
        "iv_counter": f"{iv:08x}",
        "plaintext": data.hex(),
        "spacecraft_id": f"{spacecraft:04x}",
        "protected_frame": (frame + crc16(frame)).hex(),
    }
    output = [line for line in lines if not line.startswith("# Frame oracle:")]
    output.insert(1, "# Frame oracle: pyca/cryptography 50.0.2 / OpenSSL 4.0.3; refresh_tc_frame_vectors.py; TEST ONLY.")
    for index, line in enumerate(output):
        key = line.split("=", 1)[0]
        if key in replacements:
            output[index] = f"{key}={replacements[key]}"
    path.write_bytes(("\n".join(output) + "\n").encode("ascii"))


if __name__ == "__main__":
    if __version__ != "50.0.2" or not backend.openssl_version_text().startswith("OpenSSL 4.0.3 "):
        raise SystemExit("requires pyca/cryptography 50.0.2 with OpenSSL 4.0.3")
    data_dir = Path(__file__).resolve().parents[2] / "testdata"
    for name in ("ccsds_tc_sm4_gcm_ordinary.txt", "ccsds_tc_sm4_gcm_recovery.txt"):
        regenerate(data_dir / name)
