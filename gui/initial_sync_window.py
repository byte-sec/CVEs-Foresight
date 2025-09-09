# gui/initial_sync_window.py
import customtkinter as ctk
import threading

class InitialSyncWindow(ctk.CTkToplevel):
    def __init__(self, master, start_sync_callback, skip_callback):
        super().__init__(master)
        self.title("Initial Database Setup - CVE Dashboard")
        self.geometry("600x450")
        self.transient(master)
        self.grab_set()
        self.protocol("WM_DELETE_WINDOW", self.on_close)
        
        self.start_sync_callback = start_sync_callback
        self.skip_callback = skip_callback
        self.sync_in_progress = False
        
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
            text="Initial Database Setup", 
            font=ctk.CTkFont(size=20, weight="bold")
        )
        title_label.pack(pady=(10, 20))
        
        # Info text
        info_text = (
            "Your CVE database is currently empty. To get the most out of this application, "
            "it's recommended to perform an initial synchronization.\n\n"
            "This process will:\n"
            "• Download the latest 120 days of CVE data from the NVD\n"
            "• Populate your local database with vulnerability information\n"
            "• Enable full search and analysis capabilities\n\n"
            "The initial sync typically takes 5-15 minutes depending on your internet connection "
            "and may use approximately 50-100MB of data."
        )
        
        self.info_label = ctk.CTkLabel(
            main_frame,
            text=info_text,
            justify="left",
            wraplength=550
        )
        self.info_label.pack(pady=(0, 20))
        
        # Progress section (initially hidden)
        self.progress_frame = ctk.CTkFrame(main_frame)
        
        self.status_label = ctk.CTkLabel(
            self.progress_frame,
            text="Preparing to sync...",
            font=ctk.CTkFont(size=14)
        )
        self.status_label.pack(pady=10)
        
        self.progress_bar = ctk.CTkProgressBar(self.progress_frame, mode="indeterminate")
        self.progress_bar.pack(fill="x", padx=20, pady=10)
        
        # Sync statistics
        self.stats_frame = ctk.CTkFrame(self.progress_frame, fg_color="transparent")
        self.stats_frame.pack(fill="x", pady=10)
        
        self.cves_processed_label = ctk.CTkLabel(self.stats_frame, text="CVEs Processed: 0")
        self.cves_processed_label.pack(anchor="w", padx=20)
        
        self.estimated_time_label = ctk.CTkLabel(self.stats_frame, text="")
        self.estimated_time_label.pack(anchor="w", padx=20)
        
        # Buttons frame
        button_frame = ctk.CTkFrame(main_frame, fg_color="transparent")
        button_frame.pack(fill="x", pady=20)
        
        # Skip button
        self.skip_button = ctk.CTkButton(
            button_frame, 
            text="Skip for Now", 
            command=self.skip_sync,
            fg_color="gray",
            hover_color="darkgray"
        )
        self.skip_button.pack(side="right", padx=(10, 0))
        
        # Start sync button
        self.start_button = ctk.CTkButton(
            button_frame, 
            text="Start Initial Sync", 
            command=self.start_sync,
            fg_color="green",
            hover_color="darkgreen"
        )
        self.start_button.pack(side="right")
        
        # Warning note
        warning_frame = ctk.CTkFrame(main_frame, fg_color="#2d2d2d")
        warning_frame.pack(fill="x", pady=10)
        
        warning_text = (
            "Note: You can skip this step and start the application immediately. "
            "You can always perform a full sync later from the main interface. "
            "However, without initial data, search and analysis features will be limited."
        )
        
        ctk.CTkLabel(
            warning_frame,
            text=warning_text,
            justify="left",
            wraplength=550,
            font=ctk.CTkFont(size=12),
            text_color="gray"
        ).pack(padx=15, pady=10)
        
        # Statistics tracking
        self.cves_count = 0
        self.start_time = None

    def start_sync(self):
        """Start the initial synchronization process"""
        self.sync_in_progress = True
        
        # Show progress section
        self.progress_frame.pack(fill="x", pady=20)
        
        # Update UI
        self.start_button.configure(state="disabled")
        self.skip_button.configure(text="Cancel Sync", command=self.cancel_sync)
        self.progress_bar.start()
        
        # Update info text
        self.info_label.configure(text="Synchronization in progress... Please wait.")
        
        # Start tracking time
        import time
        self.start_time = time.time()
        
        # Start the sync callback in a separate thread
        if self.start_sync_callback:
            threading.Thread(target=self.start_sync_callback, daemon=True).start()

    def update_sync_progress(self, cves_processed, status_message=""):
        """Update the progress display"""
        self.cves_count = cves_processed
        self.cves_processed_label.configure(text=f"CVEs Processed: {cves_processed}")
        
        if status_message:
            self.status_label.configure(text=status_message)
        
        # Update estimated time if we have processed some CVEs
        if cves_processed > 0 and self.start_time:
            import time
            elapsed = time.time() - self.start_time
            rate = cves_processed / elapsed if elapsed > 0 else 0
            if rate > 0:
                # Estimate based on typical 120-day sync (approximately 8000-12000 CVEs)
                estimated_total = 10000
                remaining = max(0, estimated_total - cves_processed)
                eta_seconds = remaining / rate
                eta_minutes = int(eta_seconds // 60)
                eta_seconds = int(eta_seconds % 60)
                self.estimated_time_label.configure(
                    text=f"Estimated time remaining: {eta_minutes}m {eta_seconds}s"
                )

    def sync_completed(self, success=True):
        """Handle sync completion"""
        self.progress_bar.stop()
        
        if success:
            self.status_label.configure(text="Synchronization completed successfully!")
            self.info_label.configure(
                text=f"Initial sync complete! Processed {self.cves_count} CVEs. "
                     "Your database is now ready for full functionality."
            )
            
            # Change button to close
            self.skip_button.configure(text="Continue", command=self.destroy)
            self.start_button.configure(state="disabled")
            
            # Auto-close after 3 seconds
            self.after(3000, self.destroy)
            
        else:
            self.status_label.configure(text="Synchronization failed!")
            self.info_label.configure(
                text="The initial sync encountered an error. You can try again later "
                     "or skip for now and use the application with limited functionality."
            )
            
            # Reset buttons
            self.start_button.configure(state="normal", text="Retry Sync")
            self.skip_button.configure(text="Skip for Now", command=self.skip_sync)

    def cancel_sync(self):
        """Cancel the ongoing sync"""
        if self.sync_in_progress:
            confirm = ctk.CTkToplevel(self)
            confirm.title("Cancel Sync")
            confirm.geometry("350x150")
            confirm.transient(self)
            confirm.grab_set()
            
            # Center the confirmation dialog
            self.update_idletasks()
            x = self.winfo_x() + (self.winfo_width() // 2) - 175
            y = self.winfo_y() + (self.winfo_height() // 2) - 75
            confirm.geometry(f"+{x}+{y}")
            
            ctk.CTkLabel(confirm, text="Cancel the synchronization?\nPartial data will be kept.", 
                        justify="center").pack(pady=20)
            
            button_frame = ctk.CTkFrame(confirm, fg_color="transparent")
            button_frame.pack(pady=10)
            
            def do_cancel():
                confirm.destroy()
                self.sync_in_progress = False
                self.progress_bar.stop()
                self.status_label.configure(text="Synchronization cancelled")
                self.start_button.configure(state="normal", text="Start Initial Sync")
                self.skip_button.configure(text="Skip for Now", command=self.skip_sync)
                # You might want to signal the actual sync process to stop here
            
            def dont_cancel():
                confirm.destroy()
            
            ctk.CTkButton(button_frame, text="Yes, Cancel", command=do_cancel,
                         fg_color="darkred", hover_color="red").pack(side="left", padx=5)
            ctk.CTkButton(button_frame, text="Continue Sync", command=dont_cancel).pack(side="left", padx=5)

    def skip_sync(self):
        """Skip the initial sync and proceed to main application"""
        if self.skip_callback:
            self.skip_callback()
        self.destroy()

    def on_close(self):
        """Handle window close event"""
        if self.sync_in_progress:
            self.cancel_sync()
        else:
            self.skip_sync()