import rsa


def generate_keys():
    (public_key, private_key) = rsa.newkeys(1024)
    with open('keys/public_key.pem', 'wb') as p:
        p.write(public_key.save_pkcs1('PEM'))
    with open('keys/private_key.pem', 'wb') as p:
        p.write(private_key.save_pkcs1('PEM'))


def load_keys():
    with open('keys/public_key.pem', 'rb') as p:
        public_key = rsa.PublicKey.load_pkcs1(p.read())
    with open('keys/private_key.pem', 'rb') as p:
        private_key = rsa.PrivateKey.load_pkcs1(p.read())
    return private_key, public_key


def encrypt(message, key):
    return rsa.encrypt(message.encode('ascii'), key)


def decrypt(ciphertext, key):
    return rsa.decrypt(ciphertext, key).decode('ascii')

