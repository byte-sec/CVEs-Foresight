# gui/setup_window.py
import customtkinter as ctk

class SetupWindow(ctk.CTkToplevel):
    def __init__(self, master, callback):
        super().__init__(master)
        self.title("API Key Setup - CVE Dashboard")
        self.geometry("500x400")
        self.transient(master)
        self.grab_set()
        self.protocol("WM_DELETE_WINDOW", self.on_close)
        
        self.callback = callback
        self.setup_complete = False
        
        # Center the window
        self.after(100, self.center_window)
        
        self.create_widgets()

    def center_window(self):
        """Center the window on the screen"""
        self.update_idletasks()
        x = (self.winfo_screenwidth() // 2) - (self.winfo_width() // 2)
        y = (self.winfo_screenheight() // 2) - (self.winfo_height() // 2)
        self.geometry(f"+{x}+{y}")

    def create_widgets(self):
        main_frame = ctk.CTkFrame(self)
        main_frame.pack(fill="both", expand=True, padx=20, pady=20)
        
        # Title
        title_label = ctk.CTkLabel(
            main_frame, 
            text="Welcome to CVE Dashboard", 
            font=ctk.CTkFont(size=20, weight="bold")
        )
        title_label.pack(pady=(10, 20))
        
        # Info text
        info_text = (
            "To get started, you need to provide API keys:\n\n"
            "• NVD API Key (Required): Get from https://nvd.nist.gov/developers/request-an-api-key\n"
            "• Gemini API Key (Optional): For AI-powered CVE analysis\n\n"
            "The NVD API key is essential for fetching vulnerability data."
        )
        
        info_label = ctk.CTkLabel(
            main_frame,
            text=info_text,
            justify="left",
            wraplength=450
        )
        info_label.pack(pady=(0, 20))
        
        # NVD API Key
        nvd_frame = ctk.CTkFrame(main_frame, fg_color="transparent")
        nvd_frame.pack(fill="x", pady=10)
        
        ctk.CTkLabel(nvd_frame, text="NVD API Key *", anchor="w").pack(anchor="w")
        self.nvd_entry = ctk.CTkEntry(nvd_frame, placeholder_text="Enter your NVD API key", show="*")
        self.nvd_entry.pack(fill="x", pady=(5, 0))
        
        # Gemini API Key
        gemini_frame = ctk.CTkFrame(main_frame, fg_color="transparent")
        gemini_frame.pack(fill="x", pady=10)
        
        ctk.CTkLabel(gemini_frame, text="Gemini API Key (Optional)", anchor="w").pack(anchor="w")
        self.gemini_entry = ctk.CTkEntry(gemini_frame, placeholder_text="Enter your Gemini API key (optional)", show="*")
        self.gemini_entry.pack(fill="x", pady=(5, 0))
        
        # Show/Hide password checkboxes
        checkbox_frame = ctk.CTkFrame(main_frame, fg_color="transparent")
        checkbox_frame.pack(fill="x", pady=5)
        
        self.show_keys_var = ctk.BooleanVar()
        self.show_keys_checkbox = ctk.CTkCheckBox(
            checkbox_frame, 
            text="Show API keys", 
            variable=self.show_keys_var,
            command=self.toggle_key_visibility
        )
        self.show_keys_checkbox.pack(anchor="w")
        
        # Error label
        self.error_label = ctk.CTkLabel(main_frame, text="", text_color="red")
        self.error_label.pack(pady=(10, 0))
        
        # Buttons
        button_frame = ctk.CTkFrame(main_frame, fg_color="transparent")
        button_frame.pack(fill="x", pady=20)
        
        self.cancel_button = ctk.CTkButton(
            button_frame, 
            text="Cancel", 
            command=self.on_close,
            fg_color="gray",
            hover_color="darkgray"
        )
        self.cancel_button.pack(side="right", padx=(10, 0))
        
        self.save_button = ctk.CTkButton(
            button_frame, 
            text="Save & Continue", 
            command=self.save_keys
        )
        self.save_button.pack(side="right")
        
        # Focus on the first entry
        self.nvd_entry.focus()

    def toggle_key_visibility(self):
        """Toggle visibility of API keys"""
        if self.show_keys_var.get():
            self.nvd_entry.configure(show="")
            self.gemini_entry.configure(show="")
        else:
            self.nvd_entry.configure(show="*")
            self.gemini_entry.configure(show="*")

    def save_keys(self):
        """Validate and save API keys"""
        nvd_key = self.nvd_entry.get().strip()
        gemini_key = self.gemini_entry.get().strip()
        
        # Validation
        if not nvd_key:
            self.error_label.configure(text="Error: NVD API Key is required")
            return
        
        # Basic format validation for NVD key (UUID-like format)
        if len(nvd_key) < 32:
            self.error_label.configure(text="Error: NVD API Key appears to be invalid (too short)")
            return
        
        # Clear any previous errors
        self.error_label.configure(text="")
        
        # Call the callback with the keys
        self.setup_complete = True
        if self.callback:
            self.callback(nvd_key, gemini_key)
        
        self.destroy()

    def on_close(self):
        """Handle window close event"""
        if not self.setup_complete:
            # Ask for confirmation before closing
            confirm = ctk.CTkToplevel(self)
            confirm.title("Confirm Exit")
            confirm.geometry("300x150")
            confirm.transient(self)
            confirm.grab_set()
            
            # Center the confirmation dialog
            self.update_idletasks()
            x = self.winfo_x() + (self.winfo_width() // 2) - 150
            y = self.winfo_y() + (self.winfo_height() // 2) - 75
            confirm.geometry(f"+{x}+{y}")
            
            ctk.CTkLabel(confirm, text="Exit without saving?\nThe application will close.", 
                        justify="center").pack(pady=20)
            
            button_frame = ctk.CTkFrame(confirm, fg_color="transparent")
            button_frame.pack(pady=10)
            
            def close_app():
                confirm.destroy()
                self.destroy()
                self.master.quit()
            
            def cancel_close():
                confirm.destroy()
            
            ctk.CTkButton(button_frame, text="Yes, Exit", command=close_app,
                         fg_color="darkred", hover_color="red").pack(side="left", padx=5)
            ctk.CTkButton(button_frame, text="Cancel", command=cancel_close).pack(side="left", padx=5)
        else:
            self.destroy()