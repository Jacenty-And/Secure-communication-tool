import socket
from encryption import *
from threading import Thread

HOST = "127.0.0.1"
PORT = 65432


class Client(Thread):
    def __init__(self, public_key):
        super().__init__()
        self.public_key = public_key

    def run(self) -> None:
        while True:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.connect((HOST, PORT))
                m = input("Message: ")
                ciphertext = encrypt(m, self.public_key)
                s.sendall(ciphertext)
            if input("Quit? Y/N ").capitalize() == 'Y':
                break
