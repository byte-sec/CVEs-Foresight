# backend/api_config.py
import config_manager

# --- Centralized API Key and Header Setup ---
config = config_manager.load_config()
NVD_API_KEY = config.get("NVD_API_KEY")
GEMINI_API_KEY = config.get("GEMINI_API_KEY")

# This is the single, authoritative source for the NVD API header
nvd_headers = {'apiKey': NVD_API_KEY} if NVD_API_KEY else {}
