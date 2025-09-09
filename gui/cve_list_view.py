# gui/cve_list_view.py
import customtkinter as ctk
from tkinter import ttk
from memory_manager import MemoryOptimizedDataFrame, track_object

class CVEListView(ctk.CTkFrame):
    def __init__(self, master, column_vars, on_select_callback):
        super().__init__(master)
        self.cve_data_cache = MemoryOptimizedDataFrame(max_size=2000)
        track_object(self)


        self.column_vars = column_vars
        self.on_select_callback = on_select_callback
        self.cve_data_cache = {}

        self.columns = list(column_vars.keys())
        self.sort_column = "Published"
        self.sort_reverse = True

        self.grid_rowconfigure(0, weight=1)
        self.grid_columnconfigure(0, weight=1)
        
        self.rebuild_treeview()

    def rebuild_treeview(self):
        """Destroys and rebuilds the treeview widget based on current column visibility."""
        for widget in self.winfo_children():
            widget.destroy()

        visible_columns = [col for col, var in self.column_vars.items() if var.get()]
        
        style = ttk.Style()
        style.theme_use("default")
        style.configure("Treeview", background="#2b2b2b", foreground="white", fieldbackground="#2b2b2b", borderwidth=0, rowheight=25)
        style.map('Treeview', background=[('selected', '#1f6aa5')])
        style.configure("Treeview.Heading", background="#565b5e", foreground="white", relief="flat", font=('Arial', 10, 'bold'))
        style.map("Treeview.Heading", background=[('active', '#343638')])

        self.tree = ttk.Treeview(self, columns=visible_columns, show='headings')

        all_column_configs = {
            "CVE ID": {"width": 140, "anchor": 'w'},
            "Severity": {"width": 70, "anchor": 'center'},
            "CVSS Score": {"width": 80, "anchor": 'center'},
            "Vector": {"width": 250, "anchor": 'w'},
            "CWE ID": {"width": 100, "anchor": 'w'},
            "CWE Name": {"width": 250, "anchor": 'w'},
            "Published": {"width": 110, "anchor": 'w'}
        }

        for col in visible_columns:
            self.tree.heading(col, text=col, command=lambda c=col: self.sort_by_column(c))
            config = all_column_configs.get(col, {})
            self.tree.column(col, width=config.get("width", 100), anchor=config.get("anchor", 'w'))
        
        self.tree.grid(row=0, column=0, sticky='nsew')
        self.tree.bind("<<TreeviewSelect>>", self.on_cve_select)

        vsb = ttk.Scrollbar(self, orient="vertical", command=self.tree.yview)
        vsb.grid(row=0, column=1, sticky='ns')
        self.tree.configure(yscrollcommand=vsb.set)
        hsb = ttk.Scrollbar(self, orient="horizontal", command=self.tree.xview)
        hsb.grid(row=1, column=0, sticky='ew')
        self.tree.configure(xscrollcommand=hsb.set)

        self.tree.tag_configure('oddrow', background='#343638')
        self.tree.tag_configure('evenrow', background='#2b2b2b')

    def sort_by_column(self, col):
        """Sorts the treeview data by the selected column and refreshes the view."""
        if self.sort_column == col:
            self.sort_reverse = not self.sort_reverse
        else:
            self.sort_column = col
            self.sort_reverse = False

        key_map = {
            "CVE ID": "cve_id", "Severity": "severity", "CVSS Score": "cvss_score",
            "Vector": "vector_string", "CWE ID": "primary_cwe_id", "CWE Name": "primary_cwe_name", 
            "Published": "published_date"
        }
        sort_key = key_map.get(col)
        if not sort_key: return

        data = list(self.cve_data_cache.values())

        if sort_key == "cvss_score":
            data.sort(key=lambda item: float(item.get(sort_key) or 0.0), reverse=self.sort_reverse)
        else:
            data.sort(key=lambda item: (item.get(sort_key) or "").lower(), reverse=self.sort_reverse)
        
        self.populate(data)

    def populate(self, cves):
        """Populates the treeview with a list of CVEs."""
        self.rebuild_treeview()
        self.cve_data_cache.clear()

        if not cves:
            return

        for i, cve in enumerate(cves):
            self.add_item(cve, i, update_cache=True)
        
        self.update_sort_indicators()

        children = self.tree.get_children()
        if children:
            self.tree.focus(children[0])
            self.tree.selection_set(children[0])

    def update_sort_indicators(self):
        """Updates the column headers with sort indicators."""
        for col in self.columns:
            indicator = ''
            if col == self.sort_column:
                indicator = ' ▼' if self.sort_reverse else ' ▲'
            if col in self.tree['columns']:
                self.tree.heading(col, text=col + indicator)

    def add_item(self, cve, index=0, update_cache=False):
        tag = 'evenrow' if len(self.tree.get_children()) % 2 == 0 else 'oddrow'
        cve_id = cve['cve_id']
        
        if update_cache:
            self.cve_data_cache[cve_id] = cve
        elif cve_id in self.cve_data_cache and index != 0: 
            return
        
        all_values = {
            "CVE ID": cve_id,
            "Severity": cve.get('severity', 'N/A'),
            "CVSS Score": cve.get('cvss_score', 'N/A'),
            "Vector": cve.get('vector_string', 'N/A'),
            "CWE ID": cve.get('primary_cwe_id', 'N/A'),
            "CWE Name": cve.get('primary_cwe_name', 'N/A'),
            "Published": cve.get('published_date', 'N/A').split('T')[0]
        }
        
        visible_columns = self.tree['columns']
        values_tuple = tuple(all_values.get(col) for col in visible_columns)
        
        self.tree.insert("", index, iid=cve_id, values=values_tuple, tags=(tag,))

    def update_item(self, cve):
        cve_id = cve['cve_id']
        if not self.tree.exists(cve_id): return
        
        all_values = {
            "CVE ID": cve_id,
            "Severity": cve.get('severity', 'N/A'),
            "CVSS Score": cve.get('cvss_score', 'N/A'),
            "Vector": cve.get('vector_string', 'N/A'),
            "CWE ID": cve.get('primary_cwe_id', 'N/A'),
            "CWE Name": cve.get('primary_cwe_name', 'N/A'),
            "Published": cve.get('published_date', 'N/A').split('T')[0]
        }
        visible_columns = self.tree['columns']
        values_tuple = tuple(all_values.get(col) for col in visible_columns)
        
        self.tree.item(cve_id, values=values_tuple)

    def on_cve_select(self, event):
        selected_item_id = self.tree.focus()
        if not selected_item_id: return
        cve_data = self.cve_data_cache.get(selected_item_id)
        if cve_data:
            self.on_select_callback(cve_data)
