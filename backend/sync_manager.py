# backend/sync_manager.py
import requests
import json
import os
import time
import datetime
import threading
import database
from .data_processing import extract_cve_details
from .api_config import nvd_headers

# --- State Management Setup ---
STATE_FILE = "sync_state.json"

def save_sync_state(year, index, last_date):
    """Saves the current sync progress to a file."""
    state = {'last_year': year, 'last_index': index, 'last_date': last_date}
    with open(STATE_FILE, 'w') as f:
        json.dump(state, f)
    print(f"SYNC: State saved at Year: {year}, Date: {last_date}, Index: {index}")

def load_sync_state():
    """Loads sync progress from a file, if it exists."""
    if os.path.exists(STATE_FILE):
        with open(STATE_FILE, 'r') as f:
            try: 
                return json.load(f)
            except json.JSONDecodeError: 
                return None
    return None

def perform_full_sync(stop_event, update_callback, start_date=None, end_date=None, status_callback=None):
    """
    Handles all syncing operations. Can perform a full historical sync or a sync
    of a specific date range (e.g., for the initial setup).
    
    Args:
        stop_event: Threading event to signal when to stop
        update_callback: Function called for each CVE processed
        start_date: Optional start date for date-ranged sync
        end_date: Optional end date for date-ranged sync
        status_callback: Optional function to receive status updates
    """
    state = None
    total_processed = 0
    
    if start_date and end_date:
        if status_callback:
            status_callback(f"Starting date-ranged sync from {start_date.year} to {end_date.year}")
        print(f"--- Performing Date-Ranged Sync from {start_date.year} to {end_date.year} ---")
        start_year = start_date.year
        end_year = end_date.year
    else:
        if status_callback:
            status_callback("Starting full historical sync")
        print("--- Performing Full Historical Sync ---")
        state = load_sync_state()
        start_year = state['last_year'] if state else 2020
        end_year = datetime.datetime.now(datetime.timezone.utc).year
    
    for year in range(start_year, end_year + 1):
        if stop_event.is_set():
            save_sync_state(year, 0, datetime.datetime(year, 1, 1, tzinfo=datetime.timezone.utc).isoformat())
            if status_callback:
                status_callback("Sync stopped by user")
            print("SYNC: Stop signal received. Sync paused.")
            return False
        
        if status_callback:
            status_callback(f"Processing year {year}...")
        print(f"SYNC: Starting year {year}")
        
        period_start_date = datetime.datetime(year, 1, 1, tzinfo=datetime.timezone.utc)
        if start_date and year == start_year:
            period_start_date = start_date

        year_end_date = datetime.datetime(year, 12, 31, tzinfo=datetime.timezone.utc)
        if end_date and year == end_year:
            year_end_date = end_date
        
        if state and year == start_year and state.get('last_date'):
            period_start_date = datetime.datetime.fromisoformat(state['last_date'])

        year_processed = 0
        
        while period_start_date <= year_end_date:
            if stop_event.is_set():
                save_sync_state(year, 0, period_start_date.isoformat()) 
                if status_callback:
                    status_callback("Sync stopped by user")
                print("SYNC: Stop signal received. Sync paused.")
                return False

            period_end_date = period_start_date + datetime.timedelta(days=119)
            if period_end_date > year_end_date:
                period_end_date = year_end_date

            start_str = period_start_date.strftime('%Y-%m-%dT%H:%M:%S.000Z')
            end_str = period_end_date.strftime('%Y-%m-%dT%H:%M:%S.999Z')

            if status_callback:
                period_str = f"{period_start_date.strftime('%Y-%m-%d')} to {period_end_date.strftime('%Y-%m-%d')}"
                status_callback(f"Syncing {period_str} (Year {year})")

            start_index = 0
            if state and year == start_year and period_start_date.isoformat() == state.get('last_date'):
                start_index = state.get('last_index', 0)

            period_processed = 0
            
            while True:
                if stop_event.is_set():
                    save_sync_state(year, start_index, period_start_date.isoformat())
                    if status_callback:
                        status_callback("Sync stopped by user")
                    print("SYNC: Stop signal received. Sync paused.")
                    return False

                print(f"SYNC: Fetching from {start_str} to {end_str}, index {start_index}...")
                url = f"https://services.nvd.nist.gov/rest/json/cves/2.0?resultsPerPage=2000&pubStartDate={start_str}&pubEndDate={end_str}&startIndex={start_index}"
                
                try:
                    response = requests.get(url, headers=nvd_headers, timeout=30)
                    response.raise_for_status()
                    data = response.json()
                    vulnerabilities = data.get('vulnerabilities', [])

                    if not vulnerabilities:
                        print(f"SYNC: No more data for period {start_str} to {end_str}")
                        break 

                    batch_processed = 0
                    for item in vulnerabilities:
                        if stop_event.is_set():
                            save_sync_state(year, start_index, period_start_date.isoformat())
                            if status_callback:
                                status_callback("Sync stopped by user")
                            print("SYNC: Stop signal received. Sync paused.")
                            return False

                        cve_raw = item.get('cve', {})
                        cve_id = cve_raw.get('id', 'NA')
                        
                        if database.query_local_cves(cve_id):
                            print(f"SYNC: Skipping existing CVE: {cve_id}")
                            continue
                        
                        print(f"SYNC: Processing new CVE: {cve_id}")
                        
                        cve_to_save = extract_cve_details(cve_raw)
                        database.insert_cve(cve_to_save)
                        
                        if update_callback:
                            update_callback(cve_to_save)
                        
                        batch_processed += 1
                        period_processed += 1
                        year_processed += 1
                        total_processed += 1

                    # Update status with progress
                    if status_callback and batch_processed > 0:
                        status_callback(f"Year {year}: Processed {year_processed} CVEs (Total: {total_processed})")

                    total_results = data.get('totalResults', 0)
                    start_index += len(vulnerabilities)
                    
                    if start_index >= total_results:
                        print(f"SYNC: Completed period {start_str} to {end_str}")
                        break
                    
                    # Rate limiting
                    print("SYNC: Waiting 6 seconds for rate limiting...")
                    time.sleep(6) 

                except requests.exceptions.RequestException as e:
                    error_msg = f"Network error during sync: {e}"
                    print(f"SYNC: {error_msg}")
                    if status_callback:
                        status_callback(error_msg)
                    return False
                except Exception as e:
                    error_msg = f"Unexpected error during sync: {e}"
                    print(f"SYNC: {error_msg}")
                    if status_callback:
                        status_callback(error_msg)
                    return False
            
            # Move to next period
            period_start_date = period_end_date + datetime.timedelta(days=1)
            state = None  # Clear state after first period

        # Completed year
        if status_callback:
            status_callback(f"Completed year {year} - Processed {year_processed} CVEs")
        print(f"SYNC: Completed year {year} with {year_processed} new CVEs")

    # Cleanup state file if full sync completed
    if os.path.exists(STATE_FILE) and not (start_date and end_date):
        os.remove(STATE_FILE)
        print("SYNC: Removed state file after successful completion")
    
    final_msg = f"Sync completed successfully - Total CVEs processed: {total_processed}"
    if status_callback:
        status_callback(final_msg)
    print(f"--- {final_msg} ---")
    return True

def perform_initial_sync():
    """
    Perform an initial sync of the last 1 day of CVE data.
    This provides immediate functionality while keeping startup fast.
    """
    print("--- Starting Initial Sync (Last 24 Hours) ---")
    
    # Calculate date range for last 1 day
    end_date = datetime.datetime.now(datetime.timezone.utc)
    start_date = end_date - datetime.timedelta(days=1)
    
    # Create a stop event and status tracking
    stop_event = threading.Event()
    
    def status_update(message):
        print(f"INITIAL SYNC: {message}")
    
    success = perform_full_sync(
        stop_event=stop_event,
        update_callback=None,
        start_date=start_date,
        end_date=end_date,
        status_callback=status_update
    )
    
    if success:
        print("--- Initial Sync Completed Successfully ---")
    else:
        print("--- Initial Sync Failed ---")
    
    return success