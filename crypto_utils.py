"""crypto_utils.py

Small helpers for: key derivation (PBKDF2), PKCS#7 padding,
SM4-CBC encryption/decryption and HMAC-SHA256 tagging.
"""

# OS utilities for random IV generation
import os
# HMAC utilities for authentication tags
import hmac
# Hash functions used by PBKDF2 and HMAC
import hashlib
# Type hints
from typing import Tuple

# SM4 bindings (CryptSM4) and mode constants from gmssl
from gmssl.sm4 import CryptSM4, SM4_ENCRYPT, SM4_DECRYPT

# Fixed salt for PBKDF2 (note: fixed salt is simple but not ideal for multiple users)
PBKDF2_SALT = b"secure-chat-sm4-salt"
# PBKDF2 iteration count to slow brute-force
PBKDF2_ITERATIONS = 100_000
# Key sizes used for SM4 and HMAC
SM4_KEY_SIZE = 16  # bytes
HMAC_KEY_SIZE = 32  # bytes
# SM4 block size / IV size
IV_SIZE = 16  # bytes (SM4 block size)


def derive_keys(password: str) -> Tuple[bytes, bytes]:
    """Derive SM4 key and HMAC key from a password using PBKDF2-HMAC-SHA256.

    Returns a tuple: (sm4_key, hmac_key).
    """
    # Run PBKDF2 to produce combined key material of required total length
    key_material = hashlib.pbkdf2_hmac(
        "sha256",
        password.encode("utf-8"),
        PBKDF2_SALT,
        PBKDF2_ITERATIONS,
        dklen=SM4_KEY_SIZE + HMAC_KEY_SIZE,
    )
    # Split the derived material into SM4 key and HMAC key
    sm4_key = key_material[:SM4_KEY_SIZE]
    hmac_key = key_material[SM4_KEY_SIZE:]
    return sm4_key, hmac_key


def _pkcs7_pad(data: bytes, block_size: int = 16) -> bytes:
    # Compute number of padding bytes required and append that many bytes
    pad_len = block_size - (len(data) % block_size)
    return data + bytes([pad_len] * pad_len)


def _pkcs7_unpad(data: bytes, block_size: int = 16) -> bytes:
    # Validate length and padding bytes, then strip padding
    if not data or len(data) % block_size != 0:
        raise ValueError("Invalid padding length.")
    pad_len = data[-1]
    if pad_len < 1 or pad_len > block_size:
        raise ValueError("Invalid padding value.")
    if data[-pad_len:] != bytes([pad_len] * pad_len):
        raise ValueError("Invalid padding bytes.")
    return data[:-pad_len]


def encrypt_and_tag(plaintext: bytes, sm4_key: bytes, hmac_key: bytes) -> Tuple[bytes, bytes, bytes]:
    """Encrypt a plaintext with SM4-CBC and compute an HMAC-SHA256 over iv + ciphertext.
    Returns (iv, ciphertext, tag).
    """
    # Generate a fresh random IV for CBC mode
    iv = os.urandom(IV_SIZE)
    # Instantiate SM4 cipher and set key for encryption
    crypt = CryptSM4()
    crypt.set_key(sm4_key, SM4_ENCRYPT)
    # Pad plaintext to block size using PKCS#7
    padded = _pkcs7_pad(plaintext, 16)
    # Encrypt in CBC mode using the generated IV
    ciphertext = crypt.crypt_cbc(iv, padded)
    # Compute HMAC over IV + ciphertext for integrity/authentication
    tag = hmac.new(hmac_key, iv + ciphertext, hashlib.sha256).digest()
    return iv, ciphertext, tag


def verify_and_decrypt(iv: bytes, ciphertext: bytes, tag: bytes, sm4_key: bytes, hmac_key: bytes) -> bytes:
    """Verify HMAC and decrypt SM4-CBC ciphertext.

    Raises ValueError on HMAC mismatch or invalid padding.
    """
    # Recompute expected tag and compare in constant time
    expected = hmac.new(hmac_key, iv + ciphertext, hashlib.sha256).digest()
    if not hmac.compare_digest(expected, tag):
        raise ValueError("HMAC verification failed.")

    # Decrypt with SM4 in CBC mode and then unpad
    crypt = CryptSM4()
    crypt.set_key(sm4_key, SM4_DECRYPT)
    padded = crypt.crypt_cbc(iv, ciphertext)
    return _pkcs7_unpad(padded, 16)