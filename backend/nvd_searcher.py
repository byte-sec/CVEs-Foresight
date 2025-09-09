# backend/nvd_searcher.py
import requests
import time
import datetime
import database
from .data_processing import extract_cve_details
from .api_config import nvd_headers
from validation import validate_nvd_search_params, validate_search_keyword
from api_client import create_nvd_client, get_api_client
import config_manager

config = config_manager.load_config()
nvd_client = create_nvd_client(config['NVD_API_KEY'])

def fetch_and_process_cves(keyword: str, historical: bool = False):
    keyword = validate_search_keyword(keyword)
    """
    Handles the simple keyword search.
    If 'historical' is False, it only searches the last year for speed.
    """
    print(f"Performing keyword search for '{keyword}'. Historical: {historical}")
    base_url = "https://services.nvd.nist.gov/rest/json/cves/2.0"
    
    params = {'keywordSearch': keyword}
    if not historical:
        end_date = datetime.datetime.now(datetime.timezone.utc)
        start_date = end_date - datetime.timedelta(days=365)
        params['pubStartDate'] = start_date.strftime('%Y-%m-%dT%H:%M:%S.000Z')
        params['pubEndDate'] = end_date.strftime('%Y-%m-%dT%H:%M:%S.999Z')

    # This function is a simplified search and doesn't need full pagination for this use case.
    # It will get the first page of results (up to 2000).
    params['resultsPerPage'] = 2000
    params['startIndex'] = 0
    
    try:
        response = requests.get(base_url, params=params, headers=nvd_headers, timeout=30)
        response.raise_for_status()
        data = response.json()
        vulnerabilities = data.get('vulnerabilities', [])
        
        processed_cves = []
        for item in vulnerabilities:
            cve_raw = item.get('cve', {})
            cve_to_save = extract_cve_details(cve_raw)
            database.insert_cve(cve_to_save)
            processed_cves.append(cve_to_save)
        
        return processed_cves

    except requests.exceptions.RequestException as e:
        print(f"An error occurred during NVD keyword search: {e}")
        return [{"error": str(e)}]


def advanced_nvd_search(search_params):
    """
    Performs a search against the NVD API using a dictionary of specific parameters.
    Handles pagination to retrieve all results.
    """
    print(f"Performing NVD API advanced search with params: {search_params}")
    base_url = "https://services.nvd.nist.gov/rest/json/cves/2.0"
    
    search_params['resultsPerPage'] = 2000
    start_index = 0
    
    all_vulnerabilities = []
    
    while True:
        search_params['startIndex'] = start_index
        
        try:
            response = requests.get(base_url, params=search_params, headers=nvd_headers, timeout=30)
            response.raise_for_status()
            data = response.json()
            
            vulnerabilities = data.get('vulnerabilities', [])
            if not vulnerabilities:
                break

            all_vulnerabilities.extend(vulnerabilities)
            
            total_results = data.get('totalResults', 0)
            start_index += data.get('resultsPerPage', 0)

            if start_index >= total_results:
                break
            
            time.sleep(6)

        except requests.exceptions.RequestException as e:
            print(f"An error occurred during NVD advanced search: {e}")
            return [{"error": str(e)}]
    
    processed_cves = []
    for item in all_vulnerabilities:
        cve_raw = item.get('cve', {})
        cve_to_save = extract_cve_details(cve_raw)
        database.insert_cve(cve_to_save)
        processed_cves.append(cve_to_save)
        
    return processed_cves
