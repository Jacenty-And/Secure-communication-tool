import socket
from encryption import encrypt
from threading import Thread
from queue import Queue


class Client(Thread):
    def __init__(self, host, port, public_key):
        super().__init__(daemon=True)
        self.host = host
        self.port = port
        self.public_key = public_key
        self.messages_to_send = Queue()
        self.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.connected = False

    def add_message(self, message) -> None:
        self.messages_to_send.put(message)

    def connect(self) -> bool:
        try:
            self.socket.connect((self.host, self.port))
        except ConnectionRefusedError:
            return False
        self.connected = True
        return True

    def send(self, message) -> bool:
        ciphertext = encrypt(message, self.public_key)
        self.socket.sendall(ciphertext)
        return True

    def run(self) -> None:
        while True:
            message = self.messages_to_send.get()
            sent = False
            while not sent:
                if not self.connected:
                    self.connect()
                else:
                    sent = self.send(message)
