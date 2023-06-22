import tkinter
import tkinter.scrolledtext
from threading import Thread
from tkinter.filedialog import askopenfilename
from tkinter.ttk import Progressbar
from tkinter.messagebox import showinfo

from client import Client


class Gui:
    def __init__(self, client: Client):
        self.client = client

        self.window = tkinter.Tk()
        self.window.title("Secure Communication Tool")
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

        self.send_message_button = tkinter.Button(self.window, text="Send", command=self.get_message_to_send)
        self.send_message_button.config(font=("Arial", 12))
        self.send_message_button.pack(padx=20, pady=5)

        self.send_file_button = tkinter.Button(self.window, text="Send file", command=self.get_file_to_send)
        self.send_file_button.config(font=("Arial", 12))
        self.send_file_button.pack(padx=20, pady=5)

        self.window.protocol("WM_DELETE_WINDOW", self.stop)

        self.running = True
        Thread(target=self.print_received_messages_threading, daemon=True).start()
        Thread(target=self.track_file_receiving_progress_threading, daemon=True).start()
        Thread(target=self.receive_logs_threading, daemon=True).start()

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

    def get_file_to_send(self) -> None:
        filename = askopenfilename(filetypes=(("All files", " *.* "),))
        self.text_area.config(state="normal")
        self.text_area.insert("end", f"Sending: {filename}\n")
        self.text_area.yview("end")
        self.text_area.config(state="disabled")
        self.client.add_file_to_send(filename)

    def track_file_receiving_progress_threading(self) -> None:
        while True:
            tracked_file_name, progress = self.client.get_file_receiving_progress()
            file_name_label = tkinter.Label(self.window, text=f"Receiving: {tracked_file_name}", background="lightgray")
            file_name_label.pack()
            progress_bar = Progressbar(self.window, orient="horizontal", mode="determinate", length=280)
            progress_bar.pack()
            progress_label = tkinter.Label(self.window, text=f"{progress_bar['value']}%", background="lightgray")
            progress_label.pack()
            while True:
                if progress_bar["value"] <= progress:
                    progress_bar["value"] = progress
                    progress_label["text"] = f"{progress}%"
                    _, progress = self.client.get_file_receiving_progress(tracked_file_name)
                if progress >= 100:
                    file_name_label.destroy()
                    progress_bar.destroy()
                    progress_label.destroy()
                    showinfo(title=f"Receiving: {tracked_file_name}",
                             message=f"{tracked_file_name} received!")
                    break

    def receive_logs_threading(self) -> None:
        while True:
            # message = self.client.messages_received.get()
            log = self.client.logs.get()
            self.text_area.config(state="normal")
            log += '\n'
            self.text_area.insert("end", log)
            self.text_area.yview("end")
            self.text_area.config(state="disabled")

    def stop(self):
        self.running = False
        self.window.destroy()
        exit()
