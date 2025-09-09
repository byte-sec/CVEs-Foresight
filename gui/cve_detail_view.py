# gui/cve_detail_view.py
import customtkinter as ctk
from backend import api_handler as backend

# Add this temporarily to cve_detail_view.py after the import
print("Available backend functions:", dir(backend))


class CVEDetailView(ctk.CTkScrollableFrame):
    def __init__(self, master, analyze_callback):
        super().__init__(master, label_text="Details")
        self.analyze_callback = analyze_callback

    def display_details(self, cve, last_keyword=None, deep_search_callback=None):
        """
        Displays the details for a given CVE.
        """
        for widget in self.winfo_children():
            widget.destroy()

        if not cve or "error" in cve:
            error_message = cve.get("error", "Select a CVE from the list to see details.")
            ctk.CTkLabel(self, text=error_message, wraplength=700).pack(pady=10)
            return

        ctk.CTkLabel(self, text="CVE Description", font=ctk.CTkFont(weight="bold")).pack(anchor="w", padx=5, pady=(5,0))
        ctk.CTkLabel(self, text=cve.get('description', 'N/A'), wraplength=700, justify="left").pack(anchor="w", padx=5, pady=5)
        
        # --- FIXED: Use the new separate CWE fields from the CVE data ---
        primary_cwe_id = cve.get('primary_cwe_id')
        primary_cwe_name = cve.get('primary_cwe_name')
        secondary_cwes = cve.get('secondary_cwes')

        if primary_cwe_id and primary_cwe_id != 'N/A':
            cwe_tags_frame = ctk.CTkFrame(self, fg_color="transparent")
            cwe_tags_frame.pack(fill="x", padx=5, pady=5)
            ctk.CTkLabel(cwe_tags_frame, text="Associated Weaknesses (CWE):", font=ctk.CTkFont(weight="bold")).pack(anchor="w", side="top", pady=(0, 5))
            
            tags_container = ctk.CTkFrame(cwe_tags_frame, fg_color="transparent")
            tags_container.pack(fill="x")
            
            # Combine primary and secondary CWEs for tag display
            all_cwe_lines = [f"{primary_cwe_id}: {primary_cwe_name}"]
            if secondary_cwes:
                all_cwe_lines.extend(secondary_cwes.split('\n'))

            max_cols = 4
            for i, line in enumerate(all_cwe_lines):
                row, col = divmod(i, max_cols)
                tag = ctk.CTkLabel(tags_container, text=line.strip(), fg_color="#343638", corner_radius=8)
                tag.grid(row=row, column=col, padx=2, pady=2, sticky="w")

        ai_frame = ctk.CTkFrame(self)
        ai_frame.pack(fill="x", padx=5, pady=10)
        ctk.CTkLabel(ai_frame, text="AI Analysis", font=ctk.CTkFont(weight="bold")).pack(anchor="w", padx=10, pady=(5,0))
        if cve.get('ai_summary'):
            summary_text = f"Summary: {cve.get('ai_summary')}\nCategory: {cve.get('ai_category')}\nRisk Score: {cve.get('ai_risk_score')}/10"
            ctk.CTkLabel(ai_frame, text=summary_text, wraplength=650, justify="left").pack(anchor="w", padx=10, pady=5)
            ctk.CTkLabel(ai_frame, text="Example Payload:", justify="left").pack(anchor="w", padx=10, pady=(10,0))
            payload_box = ctk.CTkTextbox(ai_frame, height=40, font=("Consolas", 14))
            payload_box.insert("1.0", cve.get('ai_exploit_payload'))
            payload_box.pack(fill="x", padx=10, pady=5)
        else:
            ctk.CTkLabel(ai_frame, text="No AI analysis available for this CVE.", wraplength=650, justify="left").pack(anchor="w", padx=10, pady=5)
            if 'cve_id' in cve:
                analyze_button = ctk.CTkButton(ai_frame, text="Analyze with AI", command=lambda c=cve['cve_id']: self.analyze_callback(c))
                analyze_button.pack(padx=10, pady=10)
        
        if primary_cwe_id and primary_cwe_id != 'N/A':
            cwe_details = backend.get_cwe_details_by_id(primary_cwe_id)
            if cwe_details:
                cwe_frame = ctk.CTkFrame(self)
                cwe_frame.pack(fill="x", padx=5, pady=10)
                title_text = f"Primary Weakness Details: {cwe_details['cwe_id']} - {cwe_details['name']}"
                ctk.CTkLabel(cwe_frame, text=title_text, font=ctk.CTkFont(weight="bold")).pack(anchor="w", padx=10, pady=(5,0))
                ctk.CTkLabel(cwe_frame, text="CWE Description:", font=ctk.CTkFont(weight="bold")).pack(anchor="w", padx=10, pady=(10,0))
                ctk.CTkLabel(cwe_frame, text=cwe_details['description'], wraplength=650, justify="left").pack(anchor="w", padx=10, pady=5)
                ctk.CTkLabel(cwe_frame, text="Common Consequences:", font=ctk.CTkFont(weight="bold")).pack(anchor="w", padx=10, pady=(10,0))
                ctk.CTkLabel(cwe_frame, text=cwe_details['common_consequences'], wraplength=650, justify="left").pack(anchor="w", padx=10, pady=5)
        
        if last_keyword and deep_search_callback:
            deep_search_button = ctk.CTkButton(self, text=f"Search Older Records for '{last_keyword}'", command=deep_search_callback)
            deep_search_button.pack(pady=20, padx=10)
