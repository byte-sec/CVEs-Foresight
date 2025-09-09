# gui/dialog_window.py
import customtkinter as ctk

class DialogWindow(ctk.CTkToplevel):
    def __init__(self, master, title, message, buttons, entry_fields=None):
        super().__init__(master)
        self.title(title)
        self.transient(master)
        self.grab_set()
        self.protocol("WM_DELETE_WINDOW", self.on_close)
        
        self.result = None
        self.entries = {}

        main_frame = ctk.CTkFrame(self, fg_color="transparent")
        main_frame.pack(padx=20, pady=20, expand=True, fill="both")

        info_label = ctk.CTkLabel(main_frame, text=message, wraplength=450, font=ctk.CTkFont(size=14))
        info_label.pack(pady=(0, 20))

        if entry_fields:
            for field in entry_fields:
                frame = ctk.CTkFrame(main_frame, fg_color="transparent")
                frame.pack(fill="x", padx=10, pady=5)
                label = ctk.CTkLabel(frame, text=field["label"], width=180, anchor="w")
                label.pack(side="left")
                entry = ctk.CTkEntry(frame, width=250)
                entry.pack(side="left", expand=True)
                self.entries[field["key"]] = entry

        self.error_label = ctk.CTkLabel(main_frame, text="", text_color="red")
        self.error_label.pack(pady=(5, 10))

        button_frame = ctk.CTkFrame(main_frame, fg_color="transparent")
        button_frame.pack(pady=(10, 0))

        for btn_text, btn_command, btn_fg_color in buttons:
            button = ctk.CTkButton(button_frame, text=btn_text, command=lambda cmd=btn_command: self.handle_button(cmd), fg_color=btn_fg_color if btn_fg_color else None)
            button.pack(side="left", padx=10)

    def handle_button(self, command):
        if command == "save_keys":
            nvd_key = self.entries["nvd"].get()
            if not nvd_key:
                self.error_label.configure(text="Error: NVD API Key is required.")
                return
            self.result = {"nvd": nvd_key, "gemini": self.entries["gemini"].get()}
        
        if command == "start_sync":
            self.result = "start_sync"
        
        if command == "skip":
            self.result = "skip"

        self.destroy()

    def on_close(self):
        self.result = "skip" # Default action if closed
        self.destroy()
