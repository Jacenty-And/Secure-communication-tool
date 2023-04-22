from server import Listener
from client import Client
from encryption import *

if __name__ == '__main__':
    if input("Do you want to generate new keys? Y/N ").capitalize() == 'Y':
        generate_keys()
        print("New keys generated")
    private_key, public_key = load_keys()
    listener = Listener(private_key)
    client = Client(public_key)
    listener.start()
    client.start()
