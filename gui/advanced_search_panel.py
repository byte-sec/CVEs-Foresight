# gui/advanced_search_panel.py
import customtkinter as ctk

class AdvancedSearchPanel(ctk.CTkFrame):
    def __init__(self, master, apply_command, clear_command):
        super().__init__(master, fg_color="#2b2b2b")
        self.apply_command = apply_command
        self.clear_command = clear_command

        self.grid_columnconfigure(3, weight=1)

        # --- Column 1: Specific Identifiers ---
        id_frame = ctk.CTkFrame(self, fg_color="transparent")
        id_frame.grid(row=0, column=0, padx=20, pady=10, sticky="n")
        ctk.CTkLabel(id_frame, text="Search by ID", font=ctk.CTkFont(weight="bold")).pack(anchor="w", pady=(0, 5))
        
        self.cve_id_entry = ctk.CTkEntry(id_frame, placeholder_text="CVE-YYYY-NNNN...")
        self.cve_id_entry.pack(fill="x", pady=5)
        
        self.cpe_name_entry = ctk.CTkEntry(id_frame, placeholder_text="cpe:2.3:a:vendor:product...")
        self.cpe_name_entry.pack(fill="x", pady=5)

        # --- Column 2: Keywords and Attributes ---
        attr_frame = ctk.CTkFrame(self, fg_color="transparent")
        attr_frame.grid(row=0, column=1, padx=20, pady=10, sticky="n")
        ctk.CTkLabel(attr_frame, text="Keywords & Attributes", font=ctk.CTkFont(weight="bold")).pack(anchor="w", pady=(0, 5))

        self.keyword_entry = ctk.CTkEntry(attr_frame, placeholder_text="Keyword(s)...")
        self.keyword_entry.pack(fill="x", pady=5)
        
        self.exact_match_var = ctk.BooleanVar()
        self.exact_match_check = ctk.CTkCheckBox(attr_frame, text="Exact Match", variable=self.exact_match_var)
        self.exact_match_check.pack(anchor="w", pady=5)

        self.has_kev_var = ctk.BooleanVar()
        self.has_kev_check = ctk.CTkCheckBox(attr_frame, text="Has Known Exploit (KEV)", variable=self.has_kev_var)
        self.has_kev_check.pack(anchor="w", pady=5)

        # --- Column 3: Severity and Score ---
        score_frame = ctk.CTkFrame(self, fg_color="transparent")
        score_frame.grid(row=0, column=2, padx=20, pady=10, sticky="n")
        ctk.CTkLabel(score_frame, text="Severity & Score", font=ctk.CTkFont(weight="bold")).pack(anchor="w", pady=(0, 5))

        self.severity_menu = ctk.CTkOptionMenu(score_frame, values=["Any", "CRITICAL", "HIGH", "MEDIUM", "LOW"])
        self.severity_menu.pack(fill="x", pady=5)

        # --- Action Buttons ---
        button_frame = ctk.CTkFrame(self, fg_color="transparent")
        button_frame.grid(row=0, column=4, padx=20, pady=10, sticky="se")

        self.clear_button = ctk.CTkButton(button_frame, text="Clear", command=self.clear_fields, width=100)
        self.clear_button.pack(side="left", padx=10)
        
        self.apply_button = ctk.CTkButton(button_frame, text="Apply Search", command=self.apply_search, width=120)
        self.apply_button.pack(side="left")

    def get_search_params(self):
        """Returns a dictionary of the current search parameters."""
        params = {}
        if self.cve_id_entry.get(): params['cveId'] = self.cve_id_entry.get()
        if self.cpe_name_entry.get(): params['cpeName'] = self.cpe_name_entry.get()
        if self.keyword_entry.get(): params['keywordSearch'] = self.keyword_entry.get()
        if self.exact_match_var.get(): params['keywordExactMatch'] = ''
        if self.has_kev_var.get(): params['hasKev'] = '' 
        if self.severity_menu.get() != "Any": params['cvssV3Severity'] = self.severity_menu.get()
        return params

    def apply_search(self):
        self.apply_command(self.get_search_params())

    def clear_fields(self):
        self.cve_id_entry.delete(0, 'end')
        self.cpe_name_entry.delete(0, 'end')
        self.keyword_entry.delete(0, 'end')
        self.exact_match_var.set(False)
        self.has_kev_var.set(False)
        self.severity_menu.set("Any")
        self.clear_command()

    # --- NEW: Methods to control button state ---
    def disable_buttons(self):
        self.apply_button.configure(state="disabled")
        self.clear_button.configure(state="disabled")

    def enable_buttons(self):
        self.apply_button.configure(state="normal")
        self.clear_button.configure(state="normal")
