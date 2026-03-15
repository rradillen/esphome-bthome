# pip install pycryptodome pytest
from Cryptodome.Cipher import AES
import pytest

KEY        = bytes.fromhex("231d39c1d7cc1ab1aee224cd096db932")
MAC        = bytes.fromhex("5448E68F80A5")   # 54:48:E6:8F:80:A5
UUID       = bytes.fromhex("D2FC")
DEV_INFO   = bytes.fromhex("41")
COUNTER    = bytes.fromhex("33221100")
CIPHERTEXT = bytes.fromhex("e445f3c9962b")
MIC        = bytes.fromhex("6c7c4519")
PLAINTEXT  = bytes.fromhex("02ca0903bf13")   # temp + humidity


def _decrypt(nonce):
    cipher = AES.new(KEY, AES.MODE_CCM, nonce=nonce, mac_len=4)
    return cipher.decrypt_and_verify(CIPHERTEXT, MIC)


def test_decrypt_with_correct_nonce_mac_bigendian():
    """MAC in display order (big-endian) as per BTHome v2 spec."""
    nonce = MAC + UUID + DEV_INFO + COUNTER
    assert _decrypt(nonce) == PLAINTEXT


def test_decrypt_fails_with_reversed_mac():
    """Reversed MAC — documents the bug fixed in this PR."""
    nonce = MAC[::-1] + UUID + DEV_INFO + COUNTER
    with pytest.raises(ValueError, match="MAC check failed"):
        _decrypt(nonce)
