from client import Client

HOST = "127.0.0.1"
PORT = 65432


if __name__ == '__main__':
    client = Client(HOST, PORT)
    client.run()
    client.console_menu_loop()
