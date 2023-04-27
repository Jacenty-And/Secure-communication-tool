import socket
from encryption import decrypt
from threading import Thread
from queue import Queue


class Server(Thread):
    def __init__(self, host, port, private_key):
        super().__init__(daemon=True)
        self.host = host
        self.port = port
        self.private_key = private_key
        self.queue = Queue()

    def get_messages(self) -> list:
        messages = list()
        while not self.queue.empty():
            messages.append(self.queue.get())
        return messages

    def run(self) -> None:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as server_socket:
            server_socket.bind((self.host, self.port))
            server_socket.listen()
            client_socket, address = server_socket.accept()
            with client_socket:
                # print(f"Connected by {address}")
                while True:
                    try:
                        data = client_socket.recv(1024)
                    except ConnectionResetError as err:
                        print(err)
                    decrypted = decrypt(data, self.private_key)
                    self.queue.put(decrypted)
