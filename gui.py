import tkinter as tk

window = tk.Tk()

lbl_send = tk.Label(text="Send")
lbl_send.grid(row=0, column=0)
btn_send = tk.Button(text="Send", width=10)
btn_send.grid(row=1, column=0)
txt_send = tk.Text()
txt_send.grid(row=2, column=0)

lbl_receive = tk.Label(text="Receive")
lbl_receive.grid(row=0, column=1)
btn_receive = tk.Button(text="Receive", width=10)
btn_receive.grid(row=1, column=1)
txt_receive = tk.Text()
txt_receive.grid(row=2, column=1)

window.mainloop()
