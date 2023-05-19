from client import Client

HOST = "127.0.0.1"
PORT = 65432


# TODO encrypting symmetrically, using hash as a key,
#  public and private keys before saving them to a file

if __name__ == '__main__':
    client = Client(HOST, PORT)
    client.run()
    while True:
        print("1. Send")
        print("2. Receive")
        print("3. Quit")
        menu = input(": ")
        if menu == "1":
            message = input("Message: ")
            client.add_message(message)
        elif menu == "2":
            for message in client.get_messages():
                print(message)
        elif menu == "3":
            exit()
