import socket
from typing import Tuple

from rsa_encryption import generate_keys, load_public_key, load_private_key, PublicKey, PrivateKey
from rsa_encryption import encrypt as asym_encrypt
from rsa_encryption import decrypt as asym_decrypt

from aes_encryption import generate_random_key
from aes_encryption import encrypt as sym_encrypt
from aes_encryption import decrypt as sym_decrypt

from threading import Thread
from queue import Queue


class Client:
    def __init__(self, host, port):
        self.host_num = host
        self.port_num = port

        self.messages_to_send = Queue()
        self.messages_received = Queue()

        self.is_hosting = None
        self.client_socket = self.try_host_else_connect()
        self.session_key = self.generate_or_receive_session_key()
        self.running = False

    def try_host_else_connect(self) -> socket.socket:
        try:
            # Client is hosting the connection if possible
            client_socket = self.host()
            self.is_hosting = True
        except WindowsError:
            # If there is already a host, client is connecting to it
            client_socket = self.connect()
            self.is_hosting = False
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

    def generate_or_receive_session_key(self) -> bytes:
        if self.is_hosting:
            # If the client is hosting the connection
            # public and private keys are generated
            # session key is received from another client
            public_key, private_key = self.generate_and_load_keys("./keys")
            self.send_public_key("./keys/public_key.pem")
            encrypted_key = self.client_socket.recv(1024)
            session_key = asym_decrypt(encrypted_key, private_key)
            print("Session key received!")
        else:
            # If the client is connected to the host
            # public key is received from another client
            # session key is generated
            public_key = self.receive_public_key("./received_keys/public_key.pem")
            print("Generating session key")
            session_key = generate_random_key(32)
            encrypted_key = asym_encrypt(session_key, public_key)
            self.client_socket.send(encrypted_key)
            print("Session key sent!")
        return session_key

    @staticmethod
    def generate_and_load_keys(path) -> Tuple[PublicKey, PrivateKey]:
        print("Generating public and private keys")
        generate_keys(path)
        public_key = load_public_key(f"{path}/public_key.pem")
        private_key = load_private_key(f"{path}/private_key.pem")
        return public_key, private_key

    def send_public_key(self, file_path) -> None:
        self.client_socket.send("PUBLIC_KEY".encode())
        with open(file_path, "rb") as file:
            data = file.read()
        self.client_socket.sendall(data)
        self.client_socket.send("<END>".encode())
        print("Public key sent!")

    def receive_public_key(self, file_path) -> PublicKey:
        if not self.client_socket.recv(1024).decode().startswith("PUBLIC_KEY"):
            print("Public key not received. Exiting the program")
            exit()
        file_bytes = b""
        while not file_bytes.decode().endswith("<END>"):
            data = self.client_socket.recv(1024)
            file_bytes += data
        file_bytes = file_bytes.replace(b"<END>", b"")
        with open(file_path, "wb") as file:
            file.write(file_bytes)
        print("Public key received!")
        public_key = load_public_key(file_path)
        return public_key

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
            ciphertext = sym_encrypt(message, self.session_key)
            self.client_socket.send(ciphertext)

    def receive_threading(self) -> None:
        while True:
            try:
                # Client is trying to receive a message
                message = self.client_socket.recv(1024)
                decrypted = sym_decrypt(message, self.session_key)
                self.messages_received.put(decrypted)
            except WindowsError:
                # If the existing connection is closed, client become a host
                print("Connection lost!")
                self.client_socket = self.try_host_else_connect()
                self.session_key = self.generate_or_receive_session_key()

    def run(self) -> None:
        if not self.running:
            Thread(target=self.send_threading, daemon=True).start()
            Thread(target=self.receive_threading, daemon=True).start()
            self.running = True
        else:
            raise Exception("Client can't be run multiple times")
