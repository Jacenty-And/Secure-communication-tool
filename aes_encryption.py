from typing import Tuple

from Crypto.Random import get_random_bytes
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad


def generate_random_key(size: int) -> bytes:
    return get_random_bytes(size)


def encrypt_ECB(message: str, key: bytes) -> bytes:
    cipher = AES.new(key, AES.MODE_ECB)
    return cipher.encrypt(pad(message.encode(), AES.block_size))


def decrypt_ECB(data: bytes, key: bytes) -> str:
    cipher = AES.new(key, AES.MODE_ECB)
    return unpad(cipher.decrypt(data), AES.block_size).decode()


def encrypt_CBC(message: str, key: bytes) -> Tuple[bytes, bytes]:
    cipher = AES.new(key, AES.MODE_CBC)
    return cipher.encrypt(pad(message.encode(), AES.block_size)), cipher.iv


def decrypt_CBC(data: bytes, key: bytes, iv: bytes) -> str:
    cipher = AES.new(key, AES.MODE_CBC, iv=iv)
    return unpad(cipher.decrypt(data), AES.block_size).decode()
