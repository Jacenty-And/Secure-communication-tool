from client import Client


class ConsoleMenu:
    def __init__(self, client: Client):
        self.client = client
        self.console_menu_loop()

    def console_menu_loop(self) -> None:
        while True:
            print("1. Send")
            print("2. Receive")
            print("3. Send file")
            print("4. Print logs")
            print("5. Quit")
            menu = input(": ")
            if menu == "1":
                message = input("Message: ")
                self.client.add_message_to_send(message)
            elif menu == "2":
                for message in self.client.get_messages_received():
                    print(message.strip('\n'))
            elif menu == "3":
                file_path = input("File path: ").replace('\\', '/').strip('\"')
                self.client.add_file_to_send(file_path)
            elif menu == "4":
                while not self.client.logs.empty():
                    log = self.client.logs.get()
                    print(log)
            elif menu == "5":
                exit()
