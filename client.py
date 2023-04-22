import socket
from encryption import encrypt


class Client:
    def __init__(self, host, port, public_key):
        self.host = host
        self.port = port
        self.public_key = public_key

    def send(self) -> None:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            try:
                s.connect((self.host, self.port))
            except ConnectionRefusedError:
                print("No one is listening!")
                return
            m = input("Message: ")
            ciphertext = encrypt(m, self.public_key)
            s.sendall(ciphertext)
