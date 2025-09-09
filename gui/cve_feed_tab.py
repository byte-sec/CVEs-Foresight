# gui/cve_feed_tab.py
import customtkinter as ctk
import threading
from backend import api_handler as backend
from .top_bar import TopBar
from .cve_list_view import CVEListView
from .cve_detail_view import CVEDetailView
from .advanced_search_panel import AdvancedSearchPanel
from .error_window import ErrorWindow

class CVEFeedTab(ctk.CTkFrame):
    def __init__(self, master, columns, column_vars):
        super().__init__(master, fg_color="transparent")

        self.sync_thread = None
        self.stop_event = threading.Event()
        self.columns = columns
        self.column_vars = column_vars
        self.last_keyword = ""
        self.search_panel_visible = False
        self.task_running = False

        self.create_main_widgets()

    def create_main_widgets(self):
        self.grid_columnconfigure(0, weight=1); self.grid_columnconfigure(1, weight=1)
        self.grid_rowconfigure(2, weight=1)

        self.top_bar = TopBar(self, 
                              search_command=self.search_button_clicked,
                              sync_command=self.start_sync_clicked,
                              stop_sync_command=self.stop_sync_clicked,
                              view_options_command=self.open_view_options_window,
                              toggle_filters_command=self.toggle_search_panel)
        self.top_bar.grid(row=0, column=0, columnspan=2, padx=0, pady=5, sticky="ew")
        
        self.search_panel = AdvancedSearchPanel(self, 
                                                apply_command=self.apply_advanced_search, 
                                                clear_command=self.clear_search)
        
        self.cve_list = CVEListView(self, self.column_vars, on_select_callback=self.on_cve_select)
        self.cve_list.grid(row=2, column=0, padx=0, pady=10, sticky="nsew")

        self.detail_view = CVEDetailView(self, analyze_callback=self.analyze_cve_clicked)
        self.detail_view.grid(row=2, column=1, padx=0, pady=10, sticky="nsew")

    def start_task(self):
        """Shows the progress bar and disables buttons."""
        if self.task_running: return False
        self.task_running = True
        self.top_bar.progress_bar.grid(row=1, column=0, sticky="ew", padx=10, pady=(0, 5))
        self.top_bar.progress_bar.start()
        self.top_bar.search_button.configure(state="disabled")
        self.top_bar.start_sync_button.configure(state="disabled")
        self.search_panel.apply_button.configure(state="disabled")
        return True

    def finish_task(self):
        """Hides the progress bar and re-enables buttons."""
        self.top_bar.progress_bar.stop()
        self.top_bar.progress_bar.grid_forget()
        self.top_bar.search_button.configure(state="normal")
        self.top_bar.start_sync_button.configure(state="normal")
        self.search_panel.apply_button.configure(state="normal")
        self.task_running = False

    def on_cve_select(self, cve_data):
        self.detail_view.display_details(cve_data, self.last_keyword, self.deep_search_clicked)

    def analyze_cve_clicked(self, cve_id):
        self.detail_view.display_details({"description": "Analyzing with AI... Please wait."}, self.last_keyword, self.deep_search_clicked)
        threading.Thread(target=self.run_analysis_thread, args=(cve_id,), daemon=True).start()

    def run_analysis_thread(self, cve_id):
        enriched_cve = backend.get_and_update_ai_enrichment(cve_id)
        if enriched_cve and "error" in enriched_cve:
            self.after(0, self.show_error_popup, "AI Analysis Failed", enriched_cve["error"])
            self.after(0, self.detail_view.display_details, self.cve_list.cve_data_cache.get(cve_id))
        else:
            self.cve_list.cve_data_cache[cve_id] = enriched_cve
            self.after(0, self.cve_list.update_item, enriched_cve)
            self.after(0, self.detail_view.display_details, enriched_cve, self.last_keyword, self.deep_search_clicked)

    def search_button_clicked(self):
        if not self.start_task(): return
        threading.Thread(target=self.run_search_thread, daemon=True).start()
    
    def run_search_thread(self):
        keyword = self.top_bar.search_entry.get()
        if not keyword: 
            self.after(0, self.finish_task)
            return
        self.last_keyword = keyword
        self.after(0, self.clear_and_show_loading, "Loading...")
        results = backend.fetch_and_process_cves(keyword, historical=False)
        
        if results and isinstance(results, list) and "error" in results[0]:
            self.after(0, self.show_error_popup, "Search Failed", results[0]["error"])
            self.after(0, self.cve_list.populate, [])
        else:
            self.after(0, self.cve_list.populate, results)
        self.after(0, self.finish_task)

    def load_initial_data(self):
        if not self.start_task(): return
        self.last_keyword = ""
        threading.Thread(target=self.run_initial_load_thread, daemon=True).start()

    def run_initial_load_thread(self):
        self.after(0, self.clear_and_show_loading, "Loading recent CVEs from database...")
        results = backend.get_recent_cves_from_db()
        
        if not results:
            # Show helpful message when no data exists
            empty_message = {
                "error": "No CVE data found. Click 'Start Syncing' to download vulnerability data from the NVD."
            }
            self.after(0, self.detail_view.display_details, empty_message)
            self.after(0, self.cve_list.populate, [])
        else:
            self.after(0, self.cve_list.populate, results)
        
        self.after(0, self.finish_task)
    
    def on_search_entry_change(self, event):
        if not self.top_bar.search_entry.get():
            self.load_initial_data()
            
    def deep_search_clicked(self):
        if not self.start_task(): return
        threading.Thread(target=self.run_deep_search_thread, daemon=True).start()

    def run_deep_search_thread(self):
        keyword = self.last_keyword
        if not keyword: 
            self.after(0, self.finish_task)
            return
        self.after(0, self.clear_and_show_loading, f"Performing deep search for '{keyword}'...")
        new_results = backend.fetch_and_process_cves(keyword, historical=True)
        
        if new_results and isinstance(new_results, list) and "error" in new_results[0]:
            self.after(0, self.show_error_popup, "Deep Search Failed", new_results[0]["error"])
            self.after(0, self.cve_list.populate, [])
        else:
            self.after(0, self.cve_list.populate, new_results)
        self.after(0, self.finish_task)

    def start_sync_clicked(self):
        if not self.start_task(): return
        self.sync_thread = threading.Thread(target=self.run_sync_thread, daemon=True)
        self.sync_thread.start()
        
    def run_sync_thread(self):
        # --- UPDATED: Provide a more detailed initial message ---
        self.after(0, self.update_sync_status, "Starting full database sync...")
        self.after(0, lambda: self.top_bar.stop_sync_button.configure(state="normal"))
        
        self.stop_event.clear()
        
        # Pass the new status update callback to the backend
        backend.perform_full_sync(self.stop_event,
                         lambda cve: self.after(0, self.cve_list.add_item, cve, 0))
        
        print("Sync finished or stopped. Refreshing CVE list.")
        self.after(0, self.clear_and_show_loading, "Sync complete. Displaying recent CVEs.")
        self.after(0, self.load_initial_data)
        self.after(0, lambda: self.top_bar.stop_sync_button.configure(state="disabled"))
        self.after(0, self.finish_task)
        
    def stop_sync_clicked(self):
        if self.sync_thread and self.sync_thread.is_alive():
            self.stop_event.set()
            self.clear_and_show_loading("Stop signal sent. The sync will pause and the list will refresh shortly.")
            
    def clear_and_show_loading(self, message="Loading..."):
        self.detail_view.display_details({"error": message})
        if "sync" not in message.lower():
            self.cve_list.populate([])

    # --- NEW: Function to update the detail panel with sync status ---
    def update_sync_status(self, message):
        self.detail_view.display_details({"error": message})

    def open_view_options_window(self):
        view_window = ctk.CTkToplevel(self)
        view_window.title("View Options")
        view_window.geometry("250x300")
        view_window.transient(self)

        for col in self.columns:
            cb = ctk.CTkCheckBox(view_window, text=col, variable=self.column_vars[col], command=self.apply_column_filters)
            cb.pack(anchor="w", padx=20, pady=5)
        
    def apply_column_filters(self):
        self.cve_list.populate(list(self.cve_list.cve_data_cache.values()))

    def toggle_search_panel(self):
        if self.search_panel_visible:
            self.search_panel.grid_forget()
            self.top_bar.toggle_filters_button.configure(text="Advanced Search")
        else:
            self.search_panel.grid(row=1, column=0, columnspan=2, padx=0, pady=0, sticky="ew")
            self.top_bar.toggle_filters_button.configure(text="Hide Search")
        self.search_panel_visible = not self.search_panel_visible

    def apply_advanced_search(self, search_params):
        if not self.start_task(): return
        threading.Thread(target=self.run_advanced_search_thread, args=(search_params,), daemon=True).start()

    def run_advanced_search_thread(self, search_params):
        self.after(0, self.clear_and_show_loading, "Performing advanced search...")
        results = backend.advanced_nvd_search(search_params)
        
        if results and isinstance(results, list) and "error" in results[0]:
            self.after(0, self.show_error_popup, "Advanced Search Failed", results[0]["error"])
            self.after(0, self.cve_list.populate, [])
        else:
            self.after(0, self.cve_list.populate, results)
        self.after(0, self.finish_task)

    def clear_search(self):
        self.load_initial_data()
        
    def show_error_popup(self, title, message):
        """Creates and shows a generic error window."""
        ErrorWindow(self, title=title, message=message)
