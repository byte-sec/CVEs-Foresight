import sys
import os

# Add the project root to the Python path to allow for absolute imports
project_root = os.path.abspath(os.path.join(os.path.dirname(__file__), '..'))
if project_root not in sys.path:
    sys.path.insert(0, project_root)

from backend import sync_manager
from backend import ai_service
from backend import nvd_searcher
from backend import data_processing
from backend import threat_intel
import database
import cwe_builder

# --- Main Application Logic Functions ---

def get_recent_cves_from_db():
    """Gets the most recent CVEs from the local database."""
    return database.query_local_cves(keyword="", limit=200)

def fetch_and_process_cves(keyword: str, historical: bool):
    """Pass-through function for simple and deep keyword searches."""
    return nvd_searcher.fetch_and_process_cves(keyword, historical)

def advanced_nvd_search(search_params):
    """Pass-through function for advanced NVD searches."""
    return nvd_searcher.advanced_nvd_search(search_params)

def filter_cve_data(cve_list, filters):
    """Pass-through function to filter a list of CVEs in memory."""
    return data_processing.filter_cve_list(cve_list, filters)

# --- AI Service Functions ---

def get_and_update_ai_enrichment(cve_id: str):
    """Pass-through function to get AI enrichment for a single CVE."""
    return ai_service.get_and_update_ai_enrichment(cve_id)

# --- CWE and Database Functions ---

def build_cwe_database_if_needed(status_callback):
    """Pass-through function to trigger the one-time CWE database build."""
    return cwe_builder.build_cwe_database_if_needed(status_callback)

def get_cwe_details_by_id(cwe_id: str):
    """Pass-through function to get CWE details from the database."""
    return database.get_cwe_details(cwe_id)

# --- Sync Manager Functions ---

def perform_full_sync(stop_event, update_callback):
    """Pass-through function for the full historical sync."""
    return sync_manager.perform_full_sync(stop_event, update_callback)

def perform_initial_sync():
    """Pass-through function for the fast, initial 120-day sync."""
    return sync_manager.perform_initial_sync()

# --- Threat Intel Functions ---

def update_kev_catalog():
    """Pass-through function to update the CISA KEV catalog."""
    return threat_intel.update_kev_catalog()

def get_trending_threats():
    """Pass-through function to get trending threats from the database."""
    return database.get_trending_threats()

def get_severity_counts():
    """Pass-through function to get severity counts for charts."""
    return database.get_severity_counts()

def get_top_cwe_counts():
    """Pass-through function to get top CWE counts for charts."""
    return database.get_top_cwe_counts(10)

def get_cwe_details_by_id(cwe_id: str):
    """Pass-through function to get CWE details from the database."""
    return database.get_cwe_details(cwe_id)
def get_kev_threats_direct():
    """Get KEV threats directly from catalog"""
    return database.get_kev_threats_direct(50)

