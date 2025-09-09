# gui/error_window.py
import customtkinter as ctk

class ErrorWindow(ctk.CTkToplevel):
    def __init__(self, master, title="Error", message="An unknown error occurred."):
        super().__init__(master)
        self.title(title)
        self.geometry("400x150")
        self.transient(master) # Keep window on top of the main app
        self.grab_set() # Block interaction with the main window

        self.grid_columnconfigure(0, weight=1)
        self.grid_rowconfigure(0, weight=1)

        main_frame = ctk.CTkFrame(self)
        main_frame.grid(row=0, column=0, padx=20, pady=20, sticky="nsew")
        main_frame.grid_columnconfigure(0, weight=1)

        error_label = ctk.CTkLabel(main_frame, text=message, wraplength=350)
        error_label.pack(pady=10, padx=10, expand=True)

        ok_button = ctk.CTkButton(main_frame, text="OK", command=self.destroy, width=100)
        ok_button.pack(pady=10)
