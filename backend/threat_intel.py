# backend/threat_intel.py
import requests
import database
import logging

# Set up logging for this module
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

CISA_KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"

def update_kev_catalog():
    """
    Downloads the CISA KEV catalog and updates the local database.
    Returns True on success, False on failure.
    """
    logger.info("Starting CISA KEV catalog update...")
    
    try:
        # Download the KEV catalog
        logger.info(f"Downloading KEV catalog from: {CISA_KEV_URL}")
        response = requests.get(CISA_KEV_URL, timeout=30)
        response.raise_for_status()
        
        # Parse the JSON response
        data = response.json()
        logger.info(f"Successfully downloaded KEV catalog. Response size: {len(response.content)} bytes")
        
        # Extract vulnerabilities
        vulnerabilities = data.get('vulnerabilities', [])
        if not vulnerabilities:
            logger.warning("No vulnerabilities found in the downloaded KEV catalog")
            return False

        # Extract CVE IDs and additional metadata
        kev_entries = []
        for vuln in vulnerabilities:
            cve_id = vuln.get('cveID')
            if cve_id:
                kev_entries.append({
                    'cve_id': cve_id,
                    'vendor_product': vuln.get('vendorProduct', 'Unknown'),
                    'vulnerability_name': vuln.get('vulnerabilityName', 'Unknown'),
                    'date_added': vuln.get('dateAdded', ''),
                    'short_description': vuln.get('shortDescription', ''),
                    'required_action': vuln.get('requiredAction', ''),
                    'due_date': vuln.get('dueDate', ''),
                    'known_ransomware': vuln.get('knownRansomwareCampaignUse', 'Unknown')
                })
        
        if not kev_entries:
            logger.warning("No valid CVE IDs found in KEV catalog")
            return False
        
        # Update the database
        logger.info(f"Updating database with {len(kev_entries)} KEV entries...")
        database.update_cisa_kev_table(kev_entries)
        
        logger.info(f"Successfully updated KEV catalog with {len(kev_entries)} entries")
        return True

    except requests.exceptions.Timeout:
        logger.error("Timeout while downloading KEV catalog")
        return False
    except requests.exceptions.ConnectionError:
        logger.error("Connection error while downloading KEV catalog")
        return False
    except requests.exceptions.HTTPError as e:
        logger.error(f"HTTP error while downloading KEV catalog: {e}")
        return False
    except requests.exceptions.RequestException as e:
        logger.error(f"Request error while downloading KEV catalog: {e}")
        return False
    except ValueError as e:
        logger.error(f"JSON parsing error in KEV catalog: {e}")
        return False
    except Exception as e:
        logger.error(f"Unexpected error while updating KEV catalog: {e}")
        return False

def get_kev_statistics():
    """
    Get statistics about the KEV catalog in the local database.
    Returns a dictionary with statistics or None on error.
    """
    try:
        # Get total count of KEV entries
        kev_count = database.get_kev_count()
        
        # Get count of KEV entries that are also in our CVE database
        matched_count = database.get_matched_kev_count()
        
        # Get recent additions (if date tracking is available)
        recent_additions = database.get_recent_kev_additions(days=30)
        
        return {
            'total_kev_entries': kev_count,
            'matched_cves': matched_count,
            'recent_additions': len(recent_additions) if recent_additions else 0,
            'match_percentage': (matched_count / kev_count * 100) if kev_count > 0 else 0
        }
    except Exception as e:
        logger.error(f"Error getting KEV statistics: {e}")
        return None

def get_high_priority_threats(limit=50):
    """
    Get high-priority threats from the KEV catalog that are also in our CVE database.
    Prioritizes by CVSS score and recency.
    Returns a list of CVE records or empty list on error.
    """
    try:
        return database.get_high_priority_kev_threats(limit)
    except Exception as e:
        logger.error(f"Error getting high-priority threats: {e}")
        return []

def is_cve_in_kev(cve_id):
    """
    Check if a specific CVE is in the CISA KEV catalog.
    Returns True if found, False otherwise.
    """
    try:
        return database.is_cve_in_kev_catalog(cve_id)
    except Exception as e:
        logger.error(f"Error checking KEV status for {cve_id}: {e}")
        return False

def get_kev_details(cve_id):
    """
    Get detailed KEV information for a specific CVE.
    Returns KEV details dictionary or None if not found.
    """
    try:
        return database.get_kev_details_for_cve(cve_id)
    except Exception as e:
        logger.error(f"Error getting KEV details for {cve_id}: {e}")
        return None

def validate_kev_catalog_freshness(max_age_days=7):
    """
    Check if the KEV catalog data is fresh enough.
    Returns True if data is fresh, False if it needs updating.
    """
    try:
        last_update = database.get_kev_last_update()
        if not last_update:
            logger.info("No KEV catalog found, update needed")
            return False
        
        from datetime import datetime, timedelta
        last_update_date = datetime.fromisoformat(last_update)
        age = datetime.now() - last_update_date
        
        is_fresh = age.days <= max_age_days
        logger.info(f"KEV catalog age: {age.days} days, fresh: {is_fresh}")
        return is_fresh
        
    except Exception as e:
        logger.error(f"Error checking KEV catalog freshness: {e}")
        return False

def auto_update_kev_if_needed():
    """
    Automatically update the KEV catalog if it's too old or missing.
    Returns True if update was performed (or wasn't needed), False on error.
    """
    try:
        if not validate_kev_catalog_freshness():
            logger.info("KEV catalog needs updating, performing automatic update...")
            return update_kev_catalog()
        else:
            logger.info("KEV catalog is fresh, no update needed")
            return True
    except Exception as e:
        logger.error(f"Error in auto-update KEV: {e}")
        return False