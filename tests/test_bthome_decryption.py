"""
Regression tests for BTHome v2 AES-CCM decryption.

Uses the canonical test vectors from the BTHome specification:
https://bthome.io/encryption
"""
import struct

from Cryptodome.Cipher import AES
import pytest

# --- BTHome v2 canonical test vectors ---
KEY        = bytes.fromhex("231d39c1d7cc1ab1aee224cd096db932")
MAC        = bytes.fromhex("5448E68F80A5")   # 54:48:E6:8F:80:A5
UUID       = bytes.fromhex("D2FC")
DEV_INFO   = bytes.fromhex("41")
COUNTER    = bytes.fromhex("33221100")
CIPHERTEXT = bytes.fromhex("e445f3c9962b")
MIC        = bytes.fromhex("6c7c4519")
PLAINTEXT  = bytes.fromhex("02ca0903bf13")   # temp + humidity

# Full service data as it appears in a BLE advertisement:
# device_info(1) + ciphertext(6) + counter(4) + MIC(4) = 15 bytes
SERVICE_DATA = DEV_INFO + CIPHERTEXT + COUNTER + MIC

# BTHome v2 service UUID
BTHOME_SERVICE_UUID = 0xFCD2

# Encrypted flag in device_info byte
BTHOME_ENCRYPTED_MASK = 0x01

# BTHome v2 object type definitions: {object_id: (data_bytes, signed, factor)}
OBJECT_TYPES = {
    0x02: (2, True,  0.01),  # temperature
    0x03: (2, False, 0.01),  # humidity
}


# --- Helpers that mirror the C++ implementation ---

def mac_from_address(address: int) -> bytes:
    """Extract MAC in big-endian (display order) from a 48-bit integer address,
    matching the fixed C++ code: mac[i] = (address >> ((5 - i) * 8)) & 0xFF"""
    return bytes((address >> ((5 - i) * 8)) & 0xFF for i in range(6))


def mac_from_address_buggy(address: int) -> bytes:
    """Old (buggy) extraction that produced little-endian MAC:
    mac[i] = (address >> (i * 8)) & 0xFF"""
    return bytes((address >> (i * 8)) & 0xFF for i in range(6))


def build_nonce(mac: bytes, device_info: int, counter: int) -> bytes:
    """Build 13-byte AES-CCM nonce per BTHome v2 spec:
    MAC(6) + UUID(2, little-endian) + device_info(1) + counter(4, little-endian)"""
    return (
        mac
        + struct.pack("<H", BTHOME_SERVICE_UUID)
        + bytes([device_info])
        + struct.pack("<I", counter)
    )


def decrypt_payload(key: bytes, nonce: bytes, ciphertext: bytes, mic: bytes) -> bytes:
    """AES-128-CCM decrypt with 4-byte MIC, matching the C++ decrypt_payload_."""
    cipher = AES.new(key, AES.MODE_CCM, nonce=nonce, mac_len=4)
    return cipher.decrypt_and_verify(ciphertext, mic)


def parse_measurements(plaintext: bytes) -> list:
    """Parse BTHome v2 measurement objects from decrypted payload,
    mirroring parse_measurements_ in bthome_receiver.cpp."""
    results = []
    pos = 0
    while pos < len(plaintext):
        object_id = plaintext[pos]
        pos += 1
        if object_id not in OBJECT_TYPES:
            break
        data_bytes, signed, factor = OBJECT_TYPES[object_id]
        if pos + data_bytes > len(plaintext):
            break
        raw = int.from_bytes(plaintext[pos:pos + data_bytes], "little", signed=signed)
        pos += data_bytes
        results.append((object_id, round(raw * factor, 2)))
    return results


def process_service_data(key: bytes, mac: bytes, service_data: bytes) -> list:
    """End-to-end processing of encrypted BTHome v2 service data,
    mirroring process_service_data_ in bthome_receiver.cpp."""
    device_info = service_data[0]
    assert device_info & BTHOME_ENCRYPTED_MASK, "Expected encrypted payload"

    # Encrypted format: device_info(1) + ciphertext(N) + counter(4) + MIC(4)
    counter = struct.unpack_from("<I", service_data, len(service_data) - 8)[0]
    ciphertext = service_data[1:-8]
    mic = service_data[-4:]

    nonce = build_nonce(mac, device_info, counter)
    plaintext = decrypt_payload(key, nonce, ciphertext, mic)
    return parse_measurements(plaintext)


# --- Tests ---

class TestNonceConstruction:
    """Unit tests for nonce MAC byte order."""

    def test_decrypt_with_correct_nonce_mac_bigendian(self):
        """MAC in display order (big-endian) as per BTHome v2 spec."""
        nonce = MAC + UUID + DEV_INFO + COUNTER
        assert decrypt_payload(KEY, nonce, CIPHERTEXT, MIC) == PLAINTEXT

    def test_decrypt_fails_with_reversed_mac(self):
        """Reversed MAC — documents the bug fixed in this PR."""
        nonce = MAC[::-1] + UUID + DEV_INFO + COUNTER
        with pytest.raises(ValueError, match="MAC check failed"):
            decrypt_payload(KEY, nonce, CIPHERTEXT, MIC)


class TestMacExtraction:
    """Verify MAC extraction from a 48-bit address integer."""

    # 54:48:E6:8F:80:A5 as a 48-bit integer (MSB first)
    ADDRESS = 0x5448E68F80A5

    def test_fixed_extraction_produces_bigendian_mac(self):
        assert mac_from_address(self.ADDRESS) == MAC

    def test_buggy_extraction_produces_reversed_mac(self):
        assert mac_from_address_buggy(self.ADDRESS) == MAC[::-1]


class TestEndToEnd:
    """Complete BTHome v2 example: service data → decrypt → sensor values."""

    def test_full_decryption_and_measurement_parsing(self):
        """Validate the entire flow using canonical BTHome v2 test vectors.

        Service data (hex): 41 e445f3c9962b 33221100 6c7c4519
          device_info = 0x41 (encrypted, BTHome v2)
          ciphertext  = e4 45 f3 c9 96 2b
          counter     = 0x00112233 (little-endian: 33 22 11 00)
          MIC         = 6c 7c 45 19

        Decrypted payload: 02 CA 09 03 BF 13
          0x02 temperature = 0x09CA (signed LE) = 2506 → 25.06 °C
          0x03 humidity    = 0x13BF (unsigned LE) = 5055 → 50.55 %
        """
        measurements = process_service_data(KEY, MAC, SERVICE_DATA)

        assert len(measurements) == 2
        assert measurements[0] == (0x02, 25.06)   # temperature
        assert measurements[1] == (0x03, 50.55)   # humidity

    def test_full_flow_fails_with_reversed_mac(self):
        """End-to-end test confirming reversed MAC causes decryption failure."""
        with pytest.raises(ValueError, match="MAC check failed"):
            process_service_data(KEY, MAC[::-1], SERVICE_DATA)
