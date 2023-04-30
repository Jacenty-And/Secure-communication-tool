import socket
from encryption import encrypt, decrypt
from threading import Thread, Event
from queue import Queue


class Client:
    def __init__(self, host, port, private_key, public_key):
        self.host_num = host
        self.port_num = port
        self.private_key = private_key
        self.public_key = public_key
        self.messages_to_send = Queue()
        self.messages_received = Queue()
        self.client_socket = self.try_host_else_connect()
        self.running = False

    def try_host_else_connect(self) -> socket.socket:
        try:
            # Client is hosting the connection if possible
            client_socket = self.host()
        except WindowsError:
            # If there is already a host, client is connecting to it
            client_socket = self.connect()
        return client_socket

    def host(self) -> socket.socket:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as server_socket:
            server_socket.bind((self.host_num, self.port_num))
            print("I'm hosting!")
            server_socket.listen()
            print("Waiting for someone to connect...")
            client_socket, address = server_socket.accept()
            print(f"{address} connected!")
        return client_socket

    def connect(self) -> socket.socket:
        client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        client_socket.connect((self.host_num, self.port_num))
        print("I connected to the host!")
        return client_socket

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

    def receive_threading(self) -> None:
        while True:
            try:
                # Client is trying to receive a message
                message = self.client_socket.recv(1024)
                decrypted = decrypt(message, self.private_key)
                self.messages_received.put(decrypted)
            except WindowsError:
                # If the existing connection is closed, client become a host
                print("Connection lost!")
                self.client_socket = self.try_host_else_connect()

    def run(self) -> None:
        if not self.running:
            Thread(target=self.send_threading, daemon=True).start()
            Thread(target=self.receive_threading, daemon=True).start()
            self.running = True
        else:
            raise Exception("Client can't be run multiple times")

