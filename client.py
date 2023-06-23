import socket
from typing import Tuple

from rsa_encryption import generate_keys, save_public_key, save_private_key, load_public_key, load_private_key
from rsa_encryption import encrypt as asym_encrypt
from rsa_encryption import decrypt as asym_decrypt
from Crypto.PublicKey.RSA import RsaKey, import_key

from aes_encryption import encrypt_ECB, decrypt_ECB, encrypt_CBC, decrypt_CBC
from Crypto.Cipher.AES import block_size as aes_block_size
from Crypto.Random import get_random_bytes

from threading import Thread, Event
from queue import Queue

from tqdm import tqdm

import gc

FILE_PARTITION_SIZE = 1_048_576  # MB


class Client:
    def __init__(self, host, port):
        self.host_num = host
        self.port_num = port

        self.logs = Queue()
        self.messages_to_send = Queue()
        self.messages_received = Queue()
        self.files_to_send = Queue()
        self.files_bytes_received = Queue()

        self.client_socket, self.is_hosting = self.try_host_else_connect()

        # TODO: Make outside function to specify generate_or_receive_session_key_and_params parameters
        self.algorithm_type, self.key_size, self.block_size, self.cipher_mode, self.initial_vector, self.session_key = \
            self.generate_or_receive_session_key_and_params()
        self.sym_encrypt = encrypt_ECB if self.cipher_mode == "ECB" else encrypt_CBC
        self.sym_decrypt = decrypt_ECB if self.cipher_mode == "ECB" else decrypt_CBC

        self.console_menu_stop = Event()
        self.running = False

    def try_host_else_connect(self) -> Tuple[socket.socket, bool]:
        try:
            # Client is hosting the connection if possible
            client_socket = self.host()
            is_hosting = True
        except WindowsError:
            # If there is already a host, client is connecting to it
            client_socket = self.connect()
            is_hosting = False
        return client_socket, is_hosting

    def host(self) -> socket.socket:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as server_socket:
            server_socket.bind((self.host_num, self.port_num))
            # print("I'm hosting!")
            self.logs.put("I'm hosting!")
            server_socket.listen()
            # print("Waiting for someone to connect...")
            self.logs.put("Waiting for someone to connect...")
            client_socket, address = server_socket.accept()
            # print(f"{address} connected!")
            self.logs.put(f"{address} connected!")
        return client_socket

    def connect(self) -> socket.socket:
        client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        client_socket.connect((self.host_num, self.port_num))
        # print("I connected to the host!")
        self.logs.put("I connected to the host!")
        return client_socket

    def generate_or_receive_session_key_and_params(self,
                                                   load: bool = False,
                                                   save: bool = False,
                                                   public_key_path: str = None,
                                                   private_key_path: str = None,
                                                   password: str = None,
                                                   algorithm_type: str = "AES",
                                                   key_size: int = 32,
                                                   block_size: int = aes_block_size,
                                                   cipher_mode: str = "ECB") -> Tuple[str, int, int, str, bytes, bytes]:
        if self.is_hosting:
            # If the client is hosting the connection
            # public and private keys are generated
            # session key is received from another client
            if load:
                try:
                    public_key, private_key = self.load_rsa_keys(public_key_path, private_key_path, password)
                except ValueError:
                    # print("The password is not correct. Exiting the program")
                    self.logs.put("The password is not correct. Exiting the program")
                    exit()
                except Exception as e:
                    # print(str(e.args[1]) + ". Exiting the program")
                    self.logs.put(str(e.args[1]) + ". Exiting the program")
                    exit()
            else:
                # print("Generating public and private keys")
                self.logs.put("Generating public and private keys...")
                public_key, private_key = generate_keys()
                if save:
                    self.save_rsa_keys(public_key, private_key, public_key_path, private_key_path, password)
            self.send_public_key(public_key)
            algorithm_type, key_size, block_size, cipher_mode, initial_vector, session_key = \
                self.receive_session_key_and_params(private_key)
            # print("Session key received!")
            self.logs.put("Session key received!")
        else:
            # If the client is connected to the host
            # public key is received from another client
            # session key is generated
            public_key = self.receive_public_key()
            # print("Generating session key")
            self.logs.put("Generating session key...")
            session_key = get_random_bytes(key_size)
            initial_vector = get_random_bytes(block_size)
            self.send_session_key(session_key, public_key, algorithm_type, key_size,
                                  block_size, cipher_mode, initial_vector)
            # print("Session key sent!")
            self.logs.put("Session key sent!")
        return algorithm_type, key_size, block_size, cipher_mode, initial_vector, session_key

    @staticmethod
    def load_rsa_keys(public_key_path: str, private_key_path: str, password: str) -> Tuple[RsaKey, RsaKey]:
        public_key = load_public_key(public_key_path)
        private_key = load_private_key(private_key_path, password)
        return public_key, private_key

    @staticmethod
    def save_rsa_keys(public_key: RsaKey, private_key: RsaKey,
                      public_key_path: str, private_key_path: str, password: str) -> None:
        save_public_key(public_key, public_key_path)
        save_private_key(private_key, private_key_path, password)

    def send_public_key(self, public_key: RsaKey) -> None:
        self.client_socket.send(b"<PUBLIC_KEY>")
        key_bytes = public_key.export_key("PEM")
        self.client_socket.sendall(key_bytes)
        self.client_socket.send(b"<END>")
        # print("Public key sent!")
        self.logs.put("Public key sent!")

    def receive_public_key(self) -> RsaKey:
        received = self.client_socket.recv(1024)
        if not received.decode().startswith("<PUBLIC_KEY>"):
            # print("Public key not received. Exiting the program")
            self.logs.put("Public key not received. Exiting the program")
            exit()
        key_bytes = b""
        while not key_bytes.decode().endswith("<END>"):
            data = self.client_socket.recv(1024)
            key_bytes += data
        key_bytes = key_bytes.replace(b"<END>", b"")
        # print("Public key received!")
        self.logs.put("Public key received!")
        public_key = import_key(key_bytes)
        return public_key

    def send_session_key(self, session_key: bytes, public_key: RsaKey, algorithm_type: str, key_size: int,
                         block_size: int, cipher_mode: str, initial_vector: bytes = None) -> None:

        def encrypt_and_send(message_bytes: bytes):
            encrypted = asym_encrypt(message_bytes, public_key)
            self.client_socket.sendall(encrypted)

        encrypt_and_send(b"<CIPHER_PARAMS>")

        encrypt_and_send(b"<ALGORITHM_TYPE>")
        algorithm_type_bytes = algorithm_type.encode()
        encrypt_and_send(algorithm_type_bytes)

        encrypt_and_send(b"<KEY_SIZE>")
        key_size_bytes = key_size.to_bytes(64, "little")
        encrypt_and_send(key_size_bytes)

        encrypt_and_send(b"<BLOCK_SIZE>")
        block_size_bytes = block_size.to_bytes(64, "little")
        encrypt_and_send(block_size_bytes)

        encrypt_and_send(b"<CIPHER_MODE>")
        cipher_mode_bytes = cipher_mode.encode()
        encrypt_and_send(cipher_mode_bytes)

        encrypt_and_send(b"<INITIAL_VECTOR>")
        encrypt_and_send(initial_vector)

        encrypt_and_send(b"<SESSION_KEY>")
        encrypt_and_send(session_key)

        encrypt_and_send(b"<END>")

    def receive_session_key_and_params(self, private_key: RsaKey) -> Tuple[str, int, int, str, bytes, bytes]:

        def receive_and_decrypt(message_header: str) -> bytes:
            recv = self.client_socket.recv(128)
            dec = asym_decrypt(recv, private_key)
            if not dec.decode().startswith(message_header):
                message_text = message_header.strip("<>").replace("_", " ").capitalize()
                # print(f"{message_text} not received. Exiting the program")
                self.logs.put(f"{message_text} not received. Exiting the program")
                exit()
            recv = self.client_socket.recv(128)
            dec = asym_decrypt(recv, private_key)
            return dec

        received = self.client_socket.recv(128)
        decrypted = asym_decrypt(received, private_key)
        if not decrypted.decode().startswith("<CIPHER_PARAMS>"):
            # print("Cipher params not received. Exiting the program")
            self.logs.put("Cipher params not received. Exiting the program")
            exit()

        received = receive_and_decrypt("<ALGORITHM_TYPE>")
        algorithm_type = received.decode()

        received = receive_and_decrypt("<KEY_SIZE>")
        key_size = int.from_bytes(received, byteorder='little')

        received = receive_and_decrypt("<BLOCK_SIZE>")
        block_size = int.from_bytes(received, byteorder='little')

        received = receive_and_decrypt("<CIPHER_MODE>")
        cipher_mode = received.decode()

        received = receive_and_decrypt("<INITIAL_VECTOR>")
        initial_vector = received

        received = self.client_socket.recv(128)
        decrypted = asym_decrypt(received, private_key)
        if not decrypted.decode().startswith("<SESSION_KEY>"):
            # print("Session key not received. Exiting the program")
            self.logs.put("Session key not received. Exiting the program")
            exit()
        key_bytes = b""
        while True:
            data = self.client_socket.recv(128)
            key_bytes += asym_decrypt(data, private_key)
            # TODO end receiving based on sent session key size
            if key_bytes[-5:] == b"<END>":
                break
        session_key = key_bytes.replace(b"<END>", b"")
        return algorithm_type, key_size, block_size, cipher_mode, initial_vector, session_key

    def receive_threading(self):
        while True:
            try:
                # Client is trying to receive a message
                encrypted = self.client_socket.recv(1024)
                decrypted = self.sym_decrypt(encrypted, self.session_key, self.initial_vector)
                if decrypted == b"<MESSAGE>":
                    self.receive_message()
                elif decrypted == b"<FILE>":
                    self.receive_file()
                else:
                    # print("Incorrect data received. Exiting the program")
                    self.logs.put("Incorrect data received. Exiting the program")
                    exit()
            except WindowsError:
                # If the existing connection is closed, client become a host
                # print("Connection lost!")
                self.logs.put("Connection lost!")
                self.reconnect()

    def reconnect(self) -> None:
        self.console_menu_stop.set()
        self.client_socket, self.is_hosting = self.try_host_else_connect()
        # TODO: Make outside function to specify generate_or_receive_session_key_and_params parameters
        self.algorithm_type, self.key_size, self.block_size, self.cipher_mode, self.initial_vector, self.session_key \
            = self.generate_or_receive_session_key_and_params()
        self.sym_encrypt = encrypt_ECB if self.cipher_mode == "ECB" else encrypt_CBC
        self.sym_decrypt = decrypt_ECB if self.cipher_mode == "ECB" else decrypt_CBC
        self.console_menu_stop = Event()

    def add_message_to_send(self, message: str) -> None:
        self.messages_to_send.put(message)

    def get_messages_received(self) -> list:
        messages = list()
        while not self.messages_received.empty():
            messages.append(self.messages_received.get())
        return messages

    def send_messages_threading(self) -> None:
        while True:
            message = self.messages_to_send.get()

            ciphertext = self.sym_encrypt(b"<MESSAGE>", self.session_key, self.initial_vector)
            self.client_socket.sendall(ciphertext)

            message_bytes = message.encode()
            ciphertext = self.sym_encrypt(message_bytes, self.session_key, self.initial_vector)
            self.client_socket.sendall(ciphertext)

    def receive_message(self) -> None:
        encrypted = self.client_socket.recv(1024)
        decrypted = self.sym_decrypt(encrypted, self.session_key, self.initial_vector)
        message = decrypted.decode()
        self.messages_received.put(message)

    # TODO Move reading from the file to send_files_threading function
    def add_file_to_send(self, filename: str) -> None:
        self.files_to_send.put(filename)

    def get_file_receiving_progress(self, tracked_file_name: str = None) -> Tuple[str, int]:
        while True:
            file_name, total_size, received_size = self.files_bytes_received.get()
            if file_name != tracked_file_name and tracked_file_name is not None:
                file = (file_name, total_size, received_size)
                self.files_bytes_received.put(file)
                continue
            progress_percent = int(received_size / total_size * 100)
            return file_name, progress_percent

    # TODO Optimize memory usage
    #  Read FILE_PARTITION_SIZE bytes from the file, encrypt, send
    def send_files_threading(self) -> None:
        while True:
            filename = self.files_to_send.get()
            self.console_menu_stop.set()

            ciphertext = self.sym_encrypt(b"<FILE>", self.session_key, self.initial_vector)
            self.client_socket.sendall(ciphertext)

            file_name = filename.split("/")[-1]
            file_name_bytes = file_name.encode()
            ciphertext = self.sym_encrypt(file_name_bytes, self.session_key, self.initial_vector)
            self.client_socket.sendall(ciphertext)

            # print("Reading the file...")
            self.logs.put("Reading the file...")
            with open(filename, "rb") as file:
                file_bytes = file.read()
            # print("File read!")
            self.logs.put("File read!")

            # print("Encrypting the file...")
            self.logs.put("Encrypting the file...")
            ciphered_file_bytes = self.sym_encrypt(file_bytes, self.session_key, self.initial_vector)
            # print("File encrypted!")
            self.logs.put("File encrypted!")
            ciphered_file_size = len(ciphered_file_bytes)

            del file_bytes

            file_size_bytes = ciphered_file_size.to_bytes(64, "little")
            ciphertext = self.sym_encrypt(file_size_bytes, self.session_key, self.initial_vector)
            self.client_socket.sendall(ciphertext)

            progress = tqdm(range(ciphered_file_size), f"Sending {file_name}",
                            unit="B", unit_scale=True, unit_divisor=1024)
            send_size = FILE_PARTITION_SIZE
            partitioned_data = [ciphered_file_bytes[i:i + send_size] for i in range(0, ciphered_file_size, send_size)]

            del ciphered_file_bytes

            for data in partitioned_data:
                self.client_socket.sendall(data)
                progress.update(len(data))
            progress.close()

            del progress
            gc.collect()

            # print("File sent!")
            self.logs.put("File sent!")
            self.console_menu_stop = Event()

    def receive_file(self) -> None:
        received = self.client_socket.recv(1024)
        decrypted = self.sym_decrypt(received, self.session_key, self.initial_vector)
        file_name = decrypted.decode()

        received = self.client_socket.recv(1024)
        decrypted = self.sym_decrypt(received, self.session_key, self.initial_vector)
        file_size = int.from_bytes(decrypted, byteorder='little')

        progress = tqdm(range(file_size), f"Receiving {file_name}",
                        unit="B", unit_scale=True, unit_divisor=1024)

        file_bytes = b""

        file = (file_name, file_size, len(file_bytes))
        self.files_bytes_received.put(file)

        while True:
            data = self.client_socket.recv(FILE_PARTITION_SIZE)
            file_bytes += data
            progress.update(len(data))

            file = (file_name, file_size, len(file_bytes))
            self.files_bytes_received.put(file)

            if len(file_bytes) == file_size:
                break
        progress.close()
        del progress

        # print("Decrypting the file...")
        self.logs.put("Decrypting the file...")
        decrypted_file = self.sym_decrypt(file_bytes, self.session_key, self.initial_vector)
        # print("File decrypted!")
        self.logs.put("File decrypted!")

        # print("Saving the file...")
        self.logs.put("Saving the file...")
        # TODO: Directory for received from function parameter
        with open(f"received/{file_name}", "wb") as file:
            file.write(decrypted_file)
        # print("File saved!")
        self.logs.put("File saved!")

    # TODO Cancel menu input after reconnecting
    # TODO: Make outside class for console menu
    def console_menu_loop(self) -> None:
        while True:
            if self.console_menu_stop.is_set():
                continue
            print("1. Send")
            print("2. Receive")
            print("3. Send file")
            print("4. Quit")
            menu = input(": ")
            if menu == "1":
                message = input("Message: ")
                self.add_message_to_send(message)
            elif menu == "2":
                for message in self.get_messages_received():
                    print(message)
            elif menu == "3":
                file_path = input("File path: ")
                self.add_file_to_send(file_path)
            elif menu == "4":
                exit()

    def run(self) -> None:
        if not self.running:
            Thread(target=self.send_messages_threading, daemon=True).start()
            Thread(target=self.send_files_threading, daemon=True).start()
            Thread(target=self.receive_threading, daemon=True).start()
            self.running = True
        else:
            raise Exception("Client can't be run multiple times")
