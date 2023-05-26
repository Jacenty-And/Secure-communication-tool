from Crypto.Hash import SHA256


def get_local_key(password: str) -> bytes:
    data = password.encode()
    hash_object = SHA256.new(data=data)
    hashed = hash_object.digest()
    return hashed
