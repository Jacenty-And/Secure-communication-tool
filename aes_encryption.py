from typing import Tuple

from Crypto.Random import get_random_bytes
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad


def generate_random_key(size: int) -> bytes:
    return get_random_bytes(size)


def encrypt_ECB(message: bytes, key: bytes) -> bytes:
    cipher = AES.new(key, AES.MODE_ECB)
    return cipher.encrypt(pad(message, AES.block_size))


def decrypt_ECB(data: bytes, key: bytes) -> bytes:
    cipher = AES.new(key, AES.MODE_ECB)
    return unpad(cipher.decrypt(data), AES.block_size)


def encrypt_CBC(message: bytes, key: bytes, iv: bytes = None) -> Tuple[bytes, bytes]:
    cipher = AES.new(key, AES.MODE_CBC, iv=iv)
    return cipher.encrypt(pad(message, AES.block_size)), cipher.iv


def decrypt_CBC(data: bytes, key: bytes, iv: bytes) -> bytes:
    cipher = AES.new(key, AES.MODE_CBC, iv=iv)
    return unpad(cipher.decrypt(data), AES.block_size)
