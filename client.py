import socket
from encryption import encrypt, decrypt
from threading import Thread
from queue import Queue


class Client:
    def __init__(self, host, port, private_key, public_key):
        self.private_key = private_key
        self.public_key = public_key
        self.messages_to_send = Queue()
        self.messages_received = Queue()
        self.running = False
        try:
            # Client is hosting the connection if possible
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as server_socket:
                server_socket.bind((host, port))
                print("I'm hosting!")
                server_socket.listen()
                self.client_socket, address = server_socket.accept()
        except:
            # If there is already a host, client is connecting to it
            self.client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.client_socket.connect((host, port))
            print("I connected to the host!")

    def add_message(self, message) -> None:
        self.messages_to_send.put(message)

    def get_messages(self) -> list:
        messages = list()
        while not self.messages_received.empty():
            messages.append(self.messages_received.get())
        return messages

    def send_threading(self) -> None:
        while True:
            message = self.messages_to_send.get()
            ciphertext = encrypt(message, self.public_key)
            self.client_socket.send(ciphertext)

    # TODO ConnectionResetError: [WinError 10054] An existing connection was forcibly closed by the remote host
    def receive_threading(self) -> None:
        while True:
            message = self.client_socket.recv(1024)
            decrypted = decrypt(message, self.private_key)
            self.messages_received.put(decrypted)

    def run(self) -> None:
        if not self.running:
            Thread(target=self.send_threading, daemon=True).start()
            Thread(target=self.receive_threading, daemon=True).start()
            self.running = True
        else:
            print("Client is already running")

