from Crypto.Random import get_random_bytes
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad


def generate_random_key(size: int) -> bytes:
    return get_random_bytes(size)


def encrypt(message: str, key, mode="ECB"):
    if mode == "ECB":
        cipher = AES.new(key, AES.MODE_ECB)
        return cipher.encrypt(pad(message.encode(), AES.block_size))
    elif mode == "CBC":
        cipher = AES.new(key, AES.MODE_CBC)
        return cipher.encrypt(pad(message.encode(), AES.block_size)), cipher.iv
    else:
        raise Exception("Mode not implemented!")


def decrypt(data: bytes, key, mode="ECB", iv=None):
    if mode == "ECB":
        cipher = AES.new(key, AES.MODE_ECB)
    elif mode == "CBC":
        cipher = AES.new(key, AES.MODE_CBC, iv=iv)
    else:
        raise Exception("Mode not implemented!")
    return unpad(cipher.decrypt(data), AES.block_size).decode()


# key = generate_random_key()
# message = input("Message: ")
# ciphered = encrypt(message, key, mode="ECB")
# print(ciphered)
# decrypted = decrypt(ciphered, key, mode="ECB")
# print(decrypted)
