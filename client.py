import socket
from typing import Tuple

from rsa_encryption import generate_keys, save_public_key, save_private_key, load_public_key, load_private_key
from rsa_encryption import encrypt as asym_encrypt
from rsa_encryption import decrypt as asym_decrypt
from Crypto.PublicKey.RSA import RsaKey, import_key

from aes_encryption import generate_random_key, encrypt_ECB, decrypt_ECB, encrypt_CBC, decrypt_CBC
from Crypto.Cipher.AES import block_size as aes_block_size
from Crypto.Random import get_random_bytes

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

        self.algorithm_type = None
        self.key_size = None
        self.block_size = None
        self.cipher_mode = None
        self.initial_vector = None
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
            if input("Do you want to load public and private keys? Y/N ").upper() == "Y":
                try:
                    public_key, private_key = self.load_rsa_keys()
                except ValueError:
                    print("The password is not correct. Exiting the program")
                    exit()
                except Exception as e:
                    print(str(e.args[1]) + ". Exiting the program")
                    exit()
            else:
                print("Generating public and private keys")
                public_key, private_key = generate_keys()
                if input("Do you want to save public and private keys? Y/N ").upper() == "Y":
                    self.save_rsa_keys(public_key, private_key)
            self.send_public_key(public_key)
            session_key = self.receive_session_key(private_key)
            print("Session key received!")
        else:
            # If the client is connected to the host
            # public key is received from another client
            # session key is generated
            public_key = self.receive_public_key()
            print("Generating session key")
            while True:
                key_size = int(input("Enter the session key size [32, 512, 1024, 2048]: "))
                if key_size in [32, 512, 1024, 2048]:
                    break
                print("Wrong value! Select key size from printed values")
            session_key = generate_random_key(key_size)
            while True:
                cipher_mode = input("Enter the cipher mode [ECB, CBC]: ")
                if cipher_mode in ["ECB", "CBC"]:
                    break
                print("Wrong cipher mode! Select cipher mode from printed modes")
            initial_vector = get_random_bytes(aes_block_size)
            self.send_session_key(session_key, public_key, "AES", key_size, aes_block_size, cipher_mode, initial_vector)
            print("Session key sent!")
        return session_key

    @staticmethod
    def load_rsa_keys() -> Tuple[RsaKey, RsaKey]:
        public_key_path = input("Enter the path where the public key is saved: ")
        public_key = load_public_key(public_key_path)
        private_key_path = input("Enter the path where the private key is saved: ")
        password = input("Enter the password to decrypt the private key: ")
        private_key = load_private_key(private_key_path, password)
        return public_key, private_key

    @staticmethod
    def save_rsa_keys(public_key: RsaKey, private_key: RsaKey) -> None:
        public_key_path = input("Enter the path where to save the public key: ")
        save_public_key(public_key, public_key_path)
        private_key_path = input("Enter the path where to save the private key: ")
        password = input("Enter the password to encrypt the private key: ")
        save_private_key(private_key, private_key_path, password)

    def send_public_key(self, public_key: RsaKey) -> None:
        self.client_socket.send(b"<PUBLIC_KEY>")
        key_bytes = public_key.export_key("PEM")
        self.client_socket.sendall(key_bytes)
        self.client_socket.send(b"<END>")
        print("Public key sent!")

    def receive_public_key(self) -> RsaKey:
        if not self.client_socket.recv(1024).decode().startswith("<PUBLIC_KEY>"):
            print("Public key not received. Exiting the program")
            exit()
        key_bytes = b""
        while not key_bytes.decode().endswith("<END>"):
            data = self.client_socket.recv(1024)
            key_bytes += data
        key_bytes = key_bytes.replace(b"<END>", b"")
        print("Public key received!")
        public_key = import_key(key_bytes)
        return public_key

    def send_session_key(self,
                         session_key: bytes,
                         public_key: RsaKey,
                         algorithm_type: str,
                         key_size: int,
                         block_size: int,
                         cipher_mode: str,
                         initial_vector: bytes) -> None:
        encrypted = asym_encrypt(b"<CIPHER_PARAMS>", public_key)
        print("<CIPHER_PARAMS>", len(b"<CIPHER_PARAMS>"))
        print("encrypted", len(encrypted))
        self.client_socket.send(encrypted)

        encrypted = asym_encrypt(b"<ALGORITHM_TYPE>", public_key)
        print("<ALGORITHM_TYPE>", len(b"<ALGORITHM_TYPE>"))
        print("encrypted", len(encrypted))
        self.client_socket.sendall(encrypted)
        self.algorithm_type = algorithm_type
        encrypted = asym_encrypt(algorithm_type.encode(), public_key)
        self.client_socket.send(encrypted)

        encrypted = asym_encrypt(b"<KEY_SIZE>", public_key)
        self.client_socket.send(encrypted)
        self.key_size = key_size
        key_size_bytes = key_size.to_bytes(64, "little")
        encrypted = asym_encrypt(key_size_bytes, public_key)
        self.client_socket.send(encrypted)

        encrypted = asym_encrypt(b"<BLOCK_SIZE>", public_key)
        self.client_socket.send(encrypted)
        self.block_size = block_size
        block_size_bytes = block_size.to_bytes(64, "little")
        encrypted = asym_encrypt(block_size_bytes, public_key)
        self.client_socket.send(encrypted)

        encrypted = asym_encrypt(b"<CIPHER_MODE>", public_key)
        self.client_socket.send(encrypted)
        self.cipher_mode = cipher_mode
        encrypted = asym_encrypt(cipher_mode.encode(), public_key)
        self.client_socket.send(encrypted)

        encrypted = asym_encrypt(b"<INITIAL_VECTOR>", public_key)
        self.client_socket.send(encrypted)
        self.initial_vector = initial_vector
        encrypted = asym_encrypt(initial_vector, public_key)
        self.client_socket.send(encrypted)

        encrypted = asym_encrypt(b"<SESSION_KEY>", public_key)
        self.client_socket.send(encrypted)
        encrypted = asym_encrypt(session_key, public_key)
        self.client_socket.send(encrypted)

        encrypted = asym_encrypt(b"<END>", public_key)
        self.client_socket.send(encrypted)

    def receive_session_key(self, private_key: RsaKey) -> bytes:
        received = self.client_socket.recv(1024)
        print("received", len(received))
        decrypted = asym_decrypt(received, private_key)
        print("decrypted", decrypted)
        if not decrypted.decode().startswith("<CIPHER_PARAMS>"):
            print("Cipher params not received. Exiting the program")
            exit()

        received = self.client_socket.recv(1024)
        print("received", len(received))
        # TODO Fix the error ValueError("Ciphertext with incorrect length.")
        decrypted = asym_decrypt(received, private_key)
        if not decrypted.decode().startswith("<ALGORITHM_TYPE>"):
            print("Algorithm type not received. Exiting the program")
            exit()
        decrypted = asym_decrypt(self.client_socket.recv(1024), private_key)
        self.algorithm_type = decrypted.decode()

        decrypted = asym_decrypt(self.client_socket.recv(1024), private_key)
        if not decrypted.decode().startswith("<KEY_SIZE>"):
            print("Key size not received. Exiting the program")
            exit()
        decrypted = asym_decrypt(self.client_socket.recv(1024), private_key)
        self.key_size = int.from_bytes(decrypted, byteorder='little')

        decrypted = asym_decrypt(self.client_socket.recv(1024), private_key)
        if not decrypted.decode().startswith("<BLOCK_SIZE>"):
            print("Block size not received. Exiting the program")
            exit()
        decrypted = asym_decrypt(self.client_socket.recv(1024), private_key)
        self.block_size = int.from_bytes(decrypted, byteorder='little')

        decrypted = asym_decrypt(self.client_socket.recv(1024), private_key)
        if not decrypted.decode().startswith("<CIPHER_MODE>"):
            print("Cipher mode not received. Exiting the program")
            exit()
        decrypted = asym_decrypt(self.client_socket.recv(1024), private_key)
        self.cipher_mode = decrypted.decode()

        decrypted = asym_decrypt(self.client_socket.recv(1024), private_key)
        if not decrypted.decode().startswith("<INITIAL_VECTOR>"):
            print("Initial vector not received. Exiting the program")
            exit()
        self.initial_vector = asym_decrypt(self.client_socket.recv(1024), private_key)

        decrypted = asym_decrypt(self.client_socket.recv(1024), private_key)
        if not decrypted.decode().startswith("<SESSION_KEY>"):
            print("Session key not received. Exiting the program")
            exit()
        key_bytes = b""
        while not key_bytes.decode().endswith("<END>"):
            data = self.client_socket.recv(1024)
            key_bytes += data
        key_bytes = key_bytes.replace(b"<END>", b"")
        session_key = asym_decrypt(key_bytes, private_key)
        return session_key

    def add_message(self, message: str) -> None:
        self.messages_to_send.put(message)

    def get_messages(self) -> list:
        messages = list()
        while not self.messages_received.empty():
            messages.append(self.messages_received.get())
        return messages

    def send_threading(self) -> None:
        while True:
            message = self.messages_to_send.get()
            message_bytes = message.encode()
            ciphertext = encrypt_ECB(message_bytes, self.session_key)
            self.client_socket.send(ciphertext)

    def receive_threading(self) -> None:
        while True:
            try:
                # Client is trying to receive a message
                encrypted = self.client_socket.recv(1024)
                decrypted = decrypt_ECB(encrypted, self.session_key)
                message = decrypted.decode()
                self.messages_received.put(message)
            except WindowsError:
                # If the existing connection is closed, client become a host
                # TODO Fix reconnecting
                #  Console inputs for menu and for loading and saving rsa keys overlaps
                print("Connection lost!")
                self.client_socket = self.try_host_else_connect()
                self.session_key = self.generate_or_receive_session_key()

    def console_menu_threading(self) -> None:
        while True:
            print("1. Send")
            print("2. Receive")
            print("3. Quit")
            menu = input(": ")
            if menu == "1":
                message = input("Message: ")
                self.add_message(message)
            elif menu == "2":
                for message in self.get_messages():
                    print(message)
            elif menu == "3":
                exit()

    def run(self) -> None:
        if not self.running:
            Thread(target=self.send_threading, daemon=True).start()
            Thread(target=self.receive_threading, daemon=True).start()
            Thread(target=self.console_menu_threading(), daemon=True).start()
            self.running = True
        else:
            raise Exception("Client can't be run multiple times")
