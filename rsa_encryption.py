from rsa import newkeys, PublicKey, PrivateKey
from rsa import encrypt as rsa_encrypt
from rsa import decrypt as rsa_decrypt


def generate_keys(path: str):
    public_key, private_key = newkeys(1024)
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
