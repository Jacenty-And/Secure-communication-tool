from typing import Tuple

from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP


def generate_keys() -> Tuple[RSA.RsaKey, RSA.RsaKey]:
    private_key = RSA.generate(1024)
    public_key = private_key.public_key()
    return public_key, private_key


def save_public_key(public_key: RSA.RsaKey, file_path: str) -> None:
    with open(file_path, "wb") as file:
        file.write(public_key.export_key("PEM"))


def save_private_key(private_key: RSA.RsaKey, file_path: str, password: str) -> None:
    with open(file_path, "wb") as file:
        file.write(private_key.export_key("PEM",
                                          passphrase=password,
                                          protection="PBKDF2WithHMAC-SHA1AndDES-EDE3-CBC",
                                          pkcs=8))


def load_public_key(file_path: str) -> RSA.RsaKey:
    with open(file_path, "rb") as file:
        public_key = RSA.import_key(file.read())
    return public_key


def load_private_key(file_path: str, password: str) -> RSA.RsaKey:
    with open(file_path, "rb") as file:
        private_key = RSA.import_key(file.read(), passphrase=password)
    return private_key


def encrypt(message: bytes, public_key: RSA.RsaKey) -> bytes:
    cipher = PKCS1_OAEP.new(public_key)
    return cipher.encrypt(message)


def decrypt(ciphertext: bytes, private_key: RSA.RsaKey) -> bytes:
    cipher = PKCS1_OAEP.new(private_key)
    return cipher.decrypt(ciphertext)
