from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad


def encrypt_ECB(message: bytes, key: bytes, _) -> bytes:
    cipher = AES.new(key, AES.MODE_ECB)
    return cipher.encrypt(pad(message, AES.block_size))


def decrypt_ECB(data: bytes, key: bytes, _) -> bytes:
    cipher = AES.new(key, AES.MODE_ECB)
    return unpad(cipher.decrypt(data), AES.block_size)


def encrypt_CBC(message: bytes, key: bytes, iv: bytes) -> bytes:
    cipher = AES.new(key, AES.MODE_CBC, iv=iv)
    return cipher.encrypt(pad(message, AES.block_size))


def decrypt_CBC(data: bytes, key: bytes, iv: bytes) -> bytes:
    cipher = AES.new(key, AES.MODE_CBC, iv=iv)
    return unpad(cipher.decrypt(data), AES.block_size)
