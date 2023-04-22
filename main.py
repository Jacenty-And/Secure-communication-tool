from encryption import load_keys
from server import Server
from client import Client

HOST = "127.0.0.1"
PORT = 65432

if __name__ == '__main__':
    private_key, public_key = load_keys()
    client = Client(HOST, PORT, public_key)
    server = Server(HOST, PORT, private_key)
    while True:
        print("1. Send")
        print("2. Receive")
        print("3. Quit")
        menu = input(": ")
        if menu == "1":
            client.send()
        elif menu == "2":
            server.receive()
        elif menu == "3":
            break

