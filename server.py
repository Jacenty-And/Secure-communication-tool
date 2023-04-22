import socket
from threading import Thread
from encryption import *

HOST = "127.0.0.1"
PORT = 65432


class Listener(Thread):
    def __init__(self, private_key):
        super().__init__()
        self.private_key = private_key

    def run(self) -> None:
        while True:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.bind((HOST, PORT))
                s.listen()
                conn, addr = s.accept()
                with conn:
                    print(f"Connected by {addr}")
                    while True:
                        data = conn.recv(1024)
                        if not data:
                            break
                        print(f"Raw data: {data}")
                        decrypted = decrypt(data, self.private_key)
                        print(f"Decrypted: {decrypted}")
