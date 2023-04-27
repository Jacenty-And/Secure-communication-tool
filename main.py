from encryption import load_keys
from server import Server
from client import Client

HOST = "127.0.0.1"
PORT = 65432

if __name__ == '__main__':
    private_key, public_key = load_keys()
    port_client = int(input("Enter port to which messages will be sent: "))
    client = Client(HOST, port_client, public_key)
    client.start()
    port_server = int(input("Enter port from which messages will be received: "))
    server = Server(HOST, port_server, private_key)
    server.start()
    while True:
        print("1. Send")
        print("2. Receive")
        print("3. Quit")
        menu = input(": ")
        if menu == "1":
            message = input("Message: ")
            client.add_message(message)
        elif menu == "2":
            for message in server.get_messages():
                print(message)
        elif menu == "3":
            exit()
