import customtkinter as ctk
from tkinter import ttk
import threading
from backend import api_handler as backend
import matplotlib.pyplot as plt
from matplotlib.backends.backend_tkagg import FigureCanvasTkAgg

class DashboardTab(ctk.CTkScrollableFrame):  # Changed from CTkFrame to CTkScrollableFrame
    def __init__(self, master, **kwargs):
        super().__init__(master, **kwargs)
        
        # Widget lifecycle tracking
        self._destroyed = False
        self._after_jobs = []

        # --- Controls Frame (Fixed at top with border) ---
        controls_frame = ctk.CTkFrame(self, border_width=2, border_color="#4a4a4a")
        controls_frame.pack(fill="x", padx=10, pady=10)

        self.update_kev_button = ctk.CTkButton(controls_frame, text="Update KEV Catalog", command=self.update_kev)
        self.update_kev_button.pack(side="left", padx=10, pady=10)

        self.refresh_button = ctk.CTkButton(controls_frame, text="Refresh Dashboard", command=self.load_dashboard_data)
        self.refresh_button.pack(side="left", padx=10, pady=10)
        
        self.status_label = ctk.CTkLabel(controls_frame, text="")
        self.status_label.pack(side="left", padx=10, pady=10)

        # --- Active Threats Section with border ---
        threats_frame = ctk.CTkFrame(self, border_width=2, border_color="#4a4a4a")
        threats_frame.pack(fill="both", expand=True, padx=10, pady=(0, 15))

        # Header with title and count
        header_frame = ctk.CTkFrame(threats_frame, fg_color="transparent")
        header_frame.pack(fill="x", padx=15, pady=(15, 10))

        ctk.CTkLabel(header_frame, text="Active Threats (CISA KEV - Known Exploited Vulnerabilities)", 
             font=ctk.CTkFont(size=16, weight="bold")).pack(side="left")

        self.threat_count_label = ctk.CTkLabel(header_frame, text="Count: 0", 
                                            font=ctk.CTkFont(size=12, weight="bold"),
                                            text_color="#4ecdc4")
        self.threat_count_label.pack(side="right")
        
        # Create treeview with proper padding
        tree_container = ctk.CTkFrame(threats_frame, fg_color="transparent")
        tree_container.pack(fill="both", expand=True, padx=15, pady=(0, 15))

        self.trending_tree = self.create_treeview(tree_container)
        self.trending_tree.pack(side="left", fill="both", expand=True)

        # Add vertical scrollbar
        v_scrollbar = ctk.CTkScrollbar(tree_container, orientation="vertical", command=self.trending_tree.yview)
        v_scrollbar.pack(side="right", fill="y")
        self.trending_tree.configure(yscrollcommand=v_scrollbar.set)

        # Add horizontal scrollbar
        h_scrollbar = ctk.CTkScrollbar(tree_container, orientation="horizontal", command=self.trending_tree.xview)
        h_scrollbar.pack(side="bottom", fill="x")
        self.trending_tree.configure(xscrollcommand=h_scrollbar.set)

        # --- Severity Stats Section with border ---
        self.severity_stats_frame = ctk.CTkFrame(self, border_width=2, border_color="#4a4a4a")
        self.severity_stats_frame.pack(fill="x", padx=10, pady=(0, 15))

        # --- CWE Chart Section with border ---
        cwe_frame = ctk.CTkFrame(self, border_width=2, border_color="#4a4a4a")
        cwe_frame.pack(fill="both", expand=True, padx=10, pady=(0, 15))

        ctk.CTkLabel(cwe_frame, text="Top 10 Weakness Types (CWE)", 
                    font=ctk.CTkFont(size=16, weight="bold")).pack(anchor="w", padx=15, pady=(15, 10))

        self.cwe_chart_frame = ctk.CTkFrame(cwe_frame, fg_color="transparent")
        self.cwe_chart_frame.pack(fill="both", expand=True, padx=15, pady=(0, 15))

        # Bind destroy event for cleanup
        self.bind("<Destroy>", self._on_destroy)
        
        # Auto-load dashboard data after initialization
        job = self.after(1000, self._safe_load_dashboard_data)
        self._after_jobs.append(job)

    def _on_destroy(self, event=None):
        """Clean up when widget is destroyed"""
        if event and event.widget == self:
            self._destroyed = True
            # Cancel all pending after() jobs
            for job in self._after_jobs:
                try:
                    self.after_cancel(job)
                except:
                    pass
            self._after_jobs.clear()

    def _safe_after(self, delay, callback, *args):
        """Safely schedule an after() callback with tracking"""
        if not self._destroyed:
            job = self.after(delay, callback, *args)
            self._after_jobs.append(job)
            return job
        return None

    def _safe_load_dashboard_data(self):
        """Safely load dashboard data with destruction check"""
        if not self._destroyed:
            self.load_dashboard_data()

    def load_dashboard_data(self):
        """Loads all data for the dashboard in a background thread."""
        if self._destroyed:
            return
            
        self.status_label.configure(text="Loading dashboard data...")
        self.refresh_button.configure(state="disabled")
        threading.Thread(target=self._load_data_worker, daemon=True).start()

    def _load_data_worker(self):
        """Worker thread for loading dashboard data"""
        if self._destroyed:
            return
            
        try:
            kev_threats = backend.get_kev_threats_direct()  # Direct KEV data
            severity_data = backend.get_severity_counts()
            cwe_data = backend.get_top_cwe_counts()
            
            if not self._destroyed:
                self._safe_after(0, self._safe_update_ui, kev_threats, severity_data, cwe_data)
                
        except Exception as e:
            if not self._destroyed:
                error_msg = f"Failed to load dashboard data: {str(e)}"
                self._safe_after(0, lambda: self.status_label.configure(text=error_msg))
                self._safe_after(0, lambda: self.refresh_button.configure(state="normal"))

    def _safe_update_ui(self, trending, severity, cwe):
        """Safely update UI with destruction check"""
        if self._destroyed:
            return
            
        self.update_ui(trending, severity, cwe)

    def update_ui(self, kev_threats, severity, cwe):
        """Update the UI with loaded data"""
        if self._destroyed:
            return
            
        try:
            self.populate_trending_tree(kev_threats)
            self.create_severity_stats(severity)  # Text stats instead of chart
            self.create_cwe_chart(cwe)
            self.status_label.configure(text="Dashboard loaded successfully")
            self.refresh_button.configure(state="normal")
        except Exception as e:
            self.status_label.configure(text=f"Error updating UI: {str(e)}")
            self.refresh_button.configure(state="normal")
    
    def update_kev(self):
        """Update KEV catalog"""
        if self._destroyed:
            return
            
        self.status_label.configure(text="Updating KEV Catalog from CISA...")
        self.update_kev_button.configure(state="disabled")
        threading.Thread(target=self._update_kev_worker, daemon=True).start()

    def _update_kev_worker(self):
        """Worker thread for KEV catalog update"""
        if self._destroyed:
            return
            
        try:
            success = backend.update_kev_catalog()
            message = "KEV Catalog updated successfully." if success else "KEV Catalog update failed."
            
            if not self._destroyed:
                # Refresh dashboard after updating KEV
                self._safe_after(0, lambda: self.status_label.configure(text=message))
                self._safe_after(0, lambda: self.update_kev_button.configure(state="normal"))
                if success:
                    self._safe_after(500, self._safe_load_dashboard_data)  # Reload data after half second
                    
        except Exception as e:
            if not self._destroyed:
                error_msg = f"KEV update failed: {str(e)}"
                self._safe_after(0, lambda: self.status_label.configure(text=error_msg))
                self._safe_after(0, lambda: self.update_kev_button.configure(state="normal"))

    def create_treeview(self, master):
        """Create and style the treeview widget with proper column widths"""
        style = ttk.Style()
        style.theme_use("default")
        style.configure("Treeview", background="#2b2b2b", foreground="white", fieldbackground="#2b2b2b", borderwidth=0, rowheight=25)
        style.map('Treeview', background=[('selected', '#1f6aa5')])
        style.configure("Treeview.Heading", background="#565b5e", foreground="white", relief="flat", font=('Arial', 10, 'bold'))
        style.map("Treeview.Heading", background=[('active', '#343638')])
        
        columns = ("CVE ID", "Product", "Vulnerability", "Date Added")
        tree = ttk.Treeview(master, columns=columns, show='headings')
        tree.heading("CVE ID", text="CVE ID")
        tree.heading("Product", text="Vendor/Product") 
        tree.heading("Vulnerability", text="Vulnerability Name")
        tree.heading("Date Added", text="Added to KEV")
        
        # Wider columns to show full text
        tree.column("CVE ID", width=140, anchor='w')
        tree.column("Product", width=250, anchor='w')
        tree.column("Vulnerability", width=400, anchor='w')  # Much wider for full names
        tree.column("Date Added", width=120, anchor='w')
        
        return tree

    def populate_trending_tree(self, kev_threats):
        """Populate with direct KEV data showing full vulnerability names"""
        if self._destroyed:
            return
            
        for item in self.trending_tree.get_children():
            self.trending_tree.delete(item)
        
        if not kev_threats:
            self.trending_tree.insert("", "end", values=("No KEV data available", "N/A", "N/A", "Update KEV Catalog"))
            # Update count
            self.threat_count_label.configure(text="Count: 0")
            return

        for i, threat in enumerate(kev_threats):
            if self._destroyed:
                break
                
            tag = 'evenrow' if i % 2 == 0 else 'oddrow'
            values = (
                threat.get('cve_id', 'N/A'), 
                threat.get('product', 'N/A'),
                threat.get('name', 'N/A'),  # Full name, no truncation
                threat.get('date_added', 'N/A')
            )
            self.trending_tree.insert("", "end", values=values, tags=(tag,))
        
        # Update count label
        self.threat_count_label.configure(text=f"Count: {len(kev_threats)}")

    def create_severity_stats(self, data):
        """Create compact text-based severity statistics"""
        if self._destroyed:
            return
            
        for widget in self.severity_stats_frame.winfo_children():
            widget.destroy()
            
        # Add section title
        ctk.CTkLabel(self.severity_stats_frame, text="CVE Severity Distribution", 
                    font=ctk.CTkFont(size=16, weight="bold")).pack(anchor="w", padx=15, pady=(15, 10))
            
        if not data:
            ctk.CTkLabel(self.severity_stats_frame, text="No severity data available").pack(padx=15, pady=15)
            return

        # Stats container with proper padding
        stats_container = ctk.CTkFrame(self.severity_stats_frame, fg_color="transparent")
        stats_container.pack(fill="x", padx=15, pady=(0, 15))

        colors = {'CRITICAL': '#e63946', 'HIGH': '#f77f00', 'MEDIUM': '#fcbf49', 'LOW': '#90e0ef'}
        
        # Stats in a horizontal row
        for item in data:
            severity = item['severity']
            count = item['count']
            
            stat_frame = ctk.CTkFrame(stats_container)
            stat_frame.pack(side="left", padx=10, pady=5)
            
            severity_label = ctk.CTkLabel(stat_frame, text=severity, 
                                        font=ctk.CTkFont(size=12, weight="bold"),
                                        text_color=colors.get(severity, 'white'))
            severity_label.pack(padx=10, pady=(8, 2))
            
            count_label = ctk.CTkLabel(stat_frame, text=str(count), 
                                    font=ctk.CTkFont(size=16, weight="bold"))
            count_label.pack(padx=10, pady=(2, 8))

    def create_cwe_chart(self, data):
        """Create CWE chart with full names and better layout"""
        if self._destroyed:
            return
            
        for widget in self.cwe_chart_frame.winfo_children():
            widget.destroy()
            
        if not data:
            ctk.CTkLabel(self.cwe_chart_frame, text="No CWE data available").pack(expand=True)
            return
        
        try:
            plt.style.use('dark_background')
            fig, ax = plt.subplots(figsize=(14, 8))  # Wider figure
            fig.patch.set_facecolor('#2b2b2b')
            ax.set_facecolor('#2b2b2b')

            # Use full CWE names, no truncation
            labels = [item['primary_cwe_name'] for item in data]
            counts = [item['count'] for item in data]

            # Create horizontal bar chart for better text display
            bars = ax.barh(range(len(labels)), counts, color=['#ff6b6b', '#4ecdc4', '#45b7d1', '#96ceb4', '#ffeaa7', '#a8e6cf', '#ff8b94', '#b4a7d6', '#d4a574', '#f4a261'])
            
            # Set labels with full names
            ax.set_yticks(range(len(labels)))
            ax.set_yticklabels(labels, fontsize=10, color='white')
            ax.set_xlabel('Count', color='white', fontsize=12)
            ax.set_title('Top 10 Weakness Types (CWE)', color='white', fontsize=14, pad=20)
            
            # Add value labels on bars
            for i, bar in enumerate(bars):
                width = bar.get_width()
                ax.text(width + 0.1, bar.get_y() + bar.get_height()/2, 
                    f'{int(width)}', ha='left', va='center', color='white', fontsize=10)
            
            ax.tick_params(axis='x', colors='white')
            ax.tick_params(axis='y', colors='white')
            plt.tight_layout()  # Automatically adjust layout to prevent text cutoff
            
            canvas = FigureCanvasTkAgg(fig, master=self.cwe_chart_frame)
            canvas.draw()
            canvas.get_tk_widget().pack(fill="both", expand=True, padx=5, pady=5)
            
        except Exception as e:
            error_label = ctk.CTkLabel(self.cwe_chart_frame, text=f"Chart error: {str(e)}")
            error_label.pack(expand=True)