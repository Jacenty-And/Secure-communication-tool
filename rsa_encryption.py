from typing import Tuple

from rsa import newkeys, PublicKey, PrivateKey
from rsa import encrypt as rsa_encrypt
from rsa import decrypt as rsa_decrypt

from aes_encryption import encrypt_CBC

from Crypto.PublicKey import RSA
from Crypto.Cipher.PKCS1_OAEP import


def generate_keys() -> Tuple[RSA.RsaKey, RSA.RsaKey]:
    private_key = RSA.generate(1024)
    public_key = private_key.public_key()
    return public_key, private_key


def save_public_key(public_key: RSA.RsaKey, path: str) -> None:
    with open(f"{path}/public_key.pem", "wb") as file:
        file.write(public_key.export_key("PEM"))


def save_private_key(private_key: RSA.RsaKey, path: str, password: str) -> None:
    with open(f"{path}/private_key.pem", "wb") as file:
        file.write(private_key.export_key("PEM",
                                          passphrase=password,
                                          protection="PBKDF2WithHMAC-SHA1AndDES-EDE3-CBC",
                                          pkcs=8))


def load_public_key(path: str) -> RSA.RsaKey:
    with open(f"{path}/public_key.pem", "rb") as file:
        public_key = RSA.import_key(file.read())
    return public_key


def load_private_key(path: str, password: str) -> RSA.RsaKey:
    with open(f"{path}/private_key.pem", "rb") as file:
        private_key = RSA.import_key(file.read(), passphrase=password)
    return private_key


def generate_keys() -> Tuple[PublicKey, PrivateKey]:
    public_key, private_key = newkeys(1024)
    return public_key, private_key


def encrypt_private_key(private_key: PrivateKey, local_key: bytes) -> bytes:
    private_key_begin = b"-----BEGIN RSA PRIVATE KEY-----\n"
    private_key_end = b"\n-----END RSA PRIVATE KEY-----\n"
    pem = private_key.save_pkcs1("PEM")
    stripped_pem = pem.replace(private_key_begin, b"")\
                      .replace(private_key_end, b"")
    encrypted_pem, iv = encrypt_CBC(stripped_pem, local_key)
    print("iv\n", iv, "\n", len(iv))
    # TODO add iv to encrypted key
    encrypted_pem = private_key_begin + iv + encrypted_pem + private_key_end
    return encrypted_pem


def save_keys(public_key: PublicKey, private_key: PrivateKey, path: str = ".") -> None:
    with open(f'{path}/public_key.pem', 'wb') as file:
        file.write(public_key.save_pkcs1('PEM'))
    with open(f'{path}/private_key.pem', 'wb') as file:
        file.write(private_key.save_pkcs1('PEM'))


def load_public_key(file_path: str) -> PublicKey:
    with open(file_path, 'rb') as file:
        public_key = PublicKey.load_pkcs1(file.read())
    return public_key


def load_private_key(file_path: str) -> PrivateKey:
    with open(file_path, 'rb') as file:
        private_key = PrivateKey.load_pkcs1(file.read())
    return private_key


def encrypt(message: bytes, public_key: PublicKey) -> bytes:
    return rsa_encrypt(message, public_key)


def decrypt(ciphertext: bytes, private_key: PrivateKey) -> bytes:
    return rsa_decrypt(ciphertext, private_key)
