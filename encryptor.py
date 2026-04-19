# encryptor.py
import os
import struct
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes, padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

MAGIC = b"ENC1"   # 4 bytes magic header

def derive_key(password: str, salt: bytes, iterations: int = 200_000) -> bytes:
    """
    PBKDF2-HMAC-SHA256 -> derive a 16-byte key (AES-128).
    """
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=16,            # AES-128
        salt=salt,
        iterations=iterations,
    )
    return kdf.derive(password.encode("utf-8"))

def encrypt_bytes(data: bytes, password: str, filename: str = "") -> bytes:
    """
    Returns bytes: MAGIC + salt(16) + iv(16) + name_len(2) + name_bytes + ciphertext
    """
    salt = os.urandom(16)
    key = derive_key(password, salt)
    iv = os.urandom(16)

    padder = padding.PKCS7(128).padder()
    padded = padder.update(data) + padder.finalize()

    cipher = Cipher(algorithms.AES(key), modes.CBC(iv))
    encryptor = cipher.encryptor()
    ct = encryptor.update(padded) + encryptor.finalize()

    name_bytes = filename.encode("utf-8")
    name_len = struct.pack(">H", len(name_bytes))   # 2 bytes big-endian
    header = MAGIC + salt + iv + name_len + name_bytes
    return header + ct

def decrypt_bytes(enc_blob: bytes, password: str) -> (bytes, str):
    """
    Parse header, derive key, decrypt. Returns (plaintext_bytes, original_filename_or_empty).
    Throws ValueError on invalid format or wrong password (or a cryptography error).
    """
    if not enc_blob.startswith(MAGIC):
        raise ValueError("Not a valid encrypted file (magic mismatch)")

    offset = len(MAGIC)
    salt = enc_blob[offset:offset+16]; offset += 16
    iv = enc_blob[offset:offset+16]; offset += 16
    name_len = struct.unpack(">H", enc_blob[offset:offset+2])[0]; offset += 2
    name = enc_blob[offset:offset+name_len].decode("utf-8"); offset += name_len
    ct = enc_blob[offset:]

    key = derive_key(password, salt)

    cipher = Cipher(algorithms.AES(key), modes.CBC(iv))
    decryptor = cipher.decryptor()
    padded = decryptor.update(ct) + decryptor.finalize()

    unpadder = padding.PKCS7(128).unpadder()
    data = unpadder.update(padded) + unpadder.finalize()

    return data, name
