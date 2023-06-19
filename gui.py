import tkinter
import tkinter.scrolledtext
from threading import Thread

from client import Client


class Gui:
    def __init__(self, client: Client):
        self.client = client

        self.window = tkinter.Tk()
        self.window.configure(background="lightgray")

        self.chat_label = tkinter.Label(self.window, text="Chat: ", background="lightgray")
        self.chat_label.config(font=("Arial", 12))
        self.chat_label.pack(padx=20, pady=5)

        self.text_area = tkinter.scrolledtext.ScrolledText(self.window)
        self.text_area.config(state="disabled")
        self.text_area.pack(padx=20, pady=5)

        self.message_label = tkinter.Label(self.window, text="Message: ", background="lightgray")
        self.message_label.config(font=("Arial", 12))
        self.message_label.pack(padx=20, pady=5)

        self.input_area = tkinter.Text(self.window, height=3)
        self.input_area.pack(padx=20, pady=5)

        self.send_button = tkinter.Button(self.window, text="Send", command=self.get_message_to_send)
        self.send_button.config(font=("Arial", 12))
        self.send_button.pack(padx=20, pady=5)

        self.window.protocol("WM_DELETE_WINDOW", self.stop)

        self.running = True
        Thread(target=self.print_received_messages_threading, daemon=True).start()

        self.window.mainloop()

    def get_message_to_send(self) -> None:
        message = self.input_area.get("1.0", "end")
        self.text_area.config(state="normal")
        self.text_area.insert("end", f"Me: {message}")
        self.text_area.yview("end")
        self.text_area.config(state="disabled")
        self.client.add_message_to_send(message)
        self.input_area.delete("1.0", "end")

    def print_received_messages_threading(self) -> None:
        while self.running:
            message = self.client.messages_received.get()
            self.text_area.config(state="normal")
            if not message.endswith('\n'):
                message += '\n'
            self.text_area.insert("end", f"User: {message}")
            self.text_area.yview("end")
            self.text_area.config(state="disabled")

    def stop(self):
        self.running = False
        self.window.destroy()
        exit()
