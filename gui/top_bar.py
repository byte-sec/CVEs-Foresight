# gui/top_bar.py
import customtkinter as ctk

class TopBar(ctk.CTkFrame):
    def __init__(self, master, search_command, sync_command, stop_sync_command, view_options_command, toggle_filters_command):
        super().__init__(master, fg_color="transparent")
        
        self.grid_columnconfigure(0, weight=1)

        # --- Top row for controls ---
        control_frame = ctk.CTkFrame(self, fg_color="transparent")
        control_frame.grid(row=0, column=0, sticky="ew")
        
        self.search_entry = ctk.CTkEntry(control_frame, placeholder_text="Enter CVE-ID or keyword...")
        self.search_entry.pack(side=ctk.LEFT, padx=10, pady=10, fill="x", expand=True)
        
        self.search_button = ctk.CTkButton(control_frame, text="Search", command=search_command, width=100)
        self.search_button.pack(side=ctk.LEFT, padx=(0, 10), pady=10)

        self.start_sync_button = ctk.CTkButton(control_frame, text="Start Syncing", command=sync_command)
        self.start_sync_button.pack(side=ctk.RIGHT, padx=10, pady=10)

        self.stop_sync_button = ctk.CTkButton(control_frame, text="Stop Syncing", fg_color="darkred", hover_color="red", command=stop_sync_command, state="disabled")
        self.stop_sync_button.pack(side=ctk.RIGHT, padx=10, pady=10)
        
        self.toggle_filters_button = ctk.CTkButton(control_frame, text="Advanced Search", command=toggle_filters_command)
        self.toggle_filters_button.pack(side=ctk.RIGHT, padx=10, pady=10)

        view_options_button = ctk.CTkButton(control_frame, text="View Options", command=view_options_command)
        view_options_button.pack(side=ctk.RIGHT, padx=10, pady=10)

        # --- Bottom row for progress bar ---
        self.progress_bar = ctk.CTkProgressBar(self, mode='indeterminate')
        # The progress bar's visibility is managed by cve_feed_tab.py
