import socket
from encryption import decrypt


class Server:
    def __init__(self, host, port, private_key):
        self.host = host
        self.port = port
        self.private_key = private_key

    def receive(self) -> None:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as server_socket:
            server_socket.bind((self.host, self.port))
            server_socket.listen()
            print("Waiting for connection...")
            client_socket, address = server_socket.accept()
            with client_socket:
                print(f"Connected by {address}")
                while True:
                    data = client_socket.recv(1024)
                    if not data:
                        break
                    print(f"Raw data: {data}")
                    decrypted = decrypt(data, self.private_key)
                    print(f"Decrypted: {decrypted}")
