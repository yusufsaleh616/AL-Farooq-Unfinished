import tkinter as tk
import webbrowser
from tkinter import messagebox

import api_client


def run():
    root = tk.Tk()
    root.title("Al-Farooq")
    root.resizable(False, False)

    frame = tk.Frame(root, padx=20, pady=16)
    frame.pack()

    tk.Label(frame, text="Username").pack(anchor="w")
    username = tk.Entry(frame, width=32)
    username.pack()

    tk.Label(frame, text="Password").pack(anchor="w", pady=(10, 0))
    password = tk.Entry(frame, width=32, show="*")
    password.pack()

    def do_login():
        try:
            url = api_client.login(username.get().strip(), password.get())
        except api_client.ApiError as exc:
            messagebox.showerror("Login failed", str(exc))
            return
        webbrowser.open(url)
        password.delete(0, tk.END)

    def do_enroll():
        try:
            device_id = api_client.enroll_device(username.get().strip(), password.get())
        except api_client.ApiError as exc:
            messagebox.showerror("Enrollment failed", str(exc))
            return
        messagebox.showinfo(
            "Request sent",
            f"This PC is registered as device {device_id}.\n"
            "A super admin has to approve it before you can log in.")

    buttons = tk.Frame(frame)
    buttons.pack(pady=(14, 0))
    tk.Button(buttons, text="Login", width=14, command=do_login).pack(side="left", padx=4)
    tk.Button(buttons, text="Enroll this device", width=16, command=do_enroll).pack(side="left", padx=4)

    root.mainloop()
