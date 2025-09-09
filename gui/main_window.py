# gui/main_window.py
import customtkinter as ctk
import threading
from backend import api_handler as backend
from .setup_window import SetupWindow
from .cve_feed_tab import CVEFeedTab
from .dashboard_tab import DashboardTab
from .initial_sync_window import InitialSyncWindow
import config_manager
import importlib
import database

class App(ctk.CTk):
    def __init__(self):
        super().__init__()
        self.title("CVE Intelligence Dashboard")
        self.geometry("1400x800")
        
        # Add this line here
        self.main_ui_created = False
        
        # Initialize threading flags
        self._setup_complete = False
        self._sync_complete = False
        self._sync_result = False

        config = config_manager.load_config()
        if not config.get("NVD_API_KEY"):
            self.show_setup_window()
        else:
            self.initialize_main_app()

    def show_setup_window(self, error_message=None):
        setup = SetupWindow(self, self.save_api_keys_and_continue)
        if error_message:
            setup.error_label.configure(text=error_message)
        self.wait_window(setup)

    def save_api_keys_and_continue(self, nvd_key, gemini_key):
        config_data = {"NVD_API_KEY": nvd_key, "GEMINI_API_KEY": gemini_key}
        config_manager.save_config(config_data)
        importlib.reload(backend)
        self.initialize_main_app()

    def initialize_main_app(self):
        database.setup_database()
        # Remove the database check - just launch the UI directly
        self.launch_main_ui()

    # def show_initial_sync_window(self):
    #     self.sync_window = InitialSyncWindow(self, 
    #                                     start_sync_callback=self.run_initial_sync_and_launch,
    #                                     skip_callback=self.launch_main_ui)
    #     self.wait_window(self.sync_window)

    # def run_initial_sync_and_launch(self):
    #     """Start initial sync in background thread"""
    #     self._sync_complete = False
    #     threading.Thread(target=self._initial_sync_worker, daemon=True).start()
    #     # Start polling for completion from main thread
    #     self.after(100, self.check_sync_completion)

    # def _initial_sync_worker(self):
    #     """Worker thread for the initial sync process."""
    #     try:
    #         success = backend.perform_initial_sync()
    #         self._sync_result = success
    #     except Exception as e:
    #         print(f"Initial sync failed: {e}")
    #         self._sync_result = False
    #     finally:
    #         self._sync_complete = True

    # def check_sync_completion(self):
    #     """Check if sync is complete (called from main thread)"""
    #     if self._sync_complete:
    #         if self._sync_result:
    #             self.launch_main_ui()
    #         else:
    #             if hasattr(self, 'sync_window'):
    #                 self.sync_window.destroy()
    #             self.show_setup_window("Initial sync failed. Please check your NVD API key.")
    #     else:
    #         # Check again in 100ms
    #         self.after(100, self.check_sync_completion)

    def launch_main_ui(self):
        """Launch the main UI directly"""
        if self.winfo_viewable() == 0:
            self.deiconify()
        
        # Show loading screen only for CWE setup
        self.setup_frame = ctk.CTkFrame(master=self)
        self.setup_frame.pack(fill="both", expand=True)
        self.setup_label = ctk.CTkLabel(master=self.setup_frame, text="Setting up application...", font=("Arial", 20))
        self.setup_label.place(relx=0.5, rely=0.5, anchor="center")
        
        self.columns = ("CVE ID", "Severity", "CVSS Score", "Vector", "CWE ID", "CWE Name", "Published")
        self.column_vars = {col: ctk.BooleanVar(value=True) for col in self.columns}
        
        # Just do CWE setup, no CVE syncing
        threading.Thread(target=self.run_cwe_build_thread, daemon=True).start()
        self.after(100, self.check_setup_completion)
    
    def run_cwe_build_thread(self):
        """Runs the backend CWE database check in background thread."""
        try:
            success = backend.build_cwe_database_if_needed(self.thread_safe_status_update)
            self._setup_result = success
        except Exception as e:
            print(f"CWE build failed: {e}")
            self._setup_result = False
        finally:
            self._setup_complete = True

    def thread_safe_status_update(self, message):
        """Thread-safe status update method"""
        # Schedule GUI update on main thread
        self.after(0, lambda: self.update_setup_status_safe(message))

    def update_setup_status_safe(self, message):
        """Safe method to update setup status from main thread"""
        if hasattr(self, 'setup_label') and self.setup_label.winfo_exists():
            self.setup_label.configure(text=message)

    def check_setup_completion(self):
        """Check if setup is complete (called from main thread)"""
        if self._setup_complete:
            success = getattr(self, '_setup_result', False)
            if success:
                self.create_main_widgets()
            else:
                self.update_setup_status_safe("Setup failed. Please restart the application.")
        else:
            # Check again in 100ms
            self.after(100, self.check_setup_completion)

    def create_main_widgets(self):
        """Creates the main application widgets after all setup is complete."""
        if self.main_ui_created: 
            return
            
        if hasattr(self, 'setup_frame'):
            self.setup_frame.destroy()
        
        self.grid_columnconfigure(0, weight=1)
        self.grid_rowconfigure(0, weight=1)

        self.tab_view = ctk.CTkTabview(self)
        self.tab_view.grid(row=0, column=0, padx=10, pady=10, sticky="nsew")

        self.tab_view.add("CVE Feed")
        self.tab_view.add("Dashboard")
        
        self.cve_feed_tab = CVEFeedTab(self.tab_view.tab("CVE Feed"), self.columns, self.column_vars)
        self.cve_feed_tab.pack(fill="both", expand=True)

        self.dashboard_tab = DashboardTab(self.tab_view.tab("Dashboard"))
        self.dashboard_tab.pack(fill="both", expand=True)

        # Load initial data for CVE feed
        self.cve_feed_tab.load_initial_data()
        self.main_ui_created = True