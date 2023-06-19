from client import Client
from gui import Gui

HOST = "127.0.0.1"
PORT = 65432


if __name__ == '__main__':
    client = Client(HOST, PORT)
    client.run()
    while True:
        print("1. Run gui")
        print("2. Run in console")
        menu = input(": ")
        if menu == "1":
            gui = Gui(client)
        elif menu == "2":
            client.console_menu_loop()
        else:
            break
