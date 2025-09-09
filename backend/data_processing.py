# backend/data_processing.py
import database

def extract_cve_details(cve_raw):
    """
    Helper function to pull all desired fields from the raw NVD JSON.
    Now correctly separates the primary CWE ID and Name for database storage.
    """
    metrics = cve_raw.get('metrics', {}).get('cvssMetricV31', [{}])[0].get('cvssData', {})
    
    weakness_list = cve_raw.get('weaknesses', [])
    cwe_display_list = []
    for weakness_obj in weakness_list:
        for description in weakness_obj.get('description', []):
            if description.get('lang') == 'en':
                cwe_id_raw = description.get('value')
                cwe_details = database.get_cwe_details(cwe_id_raw)
                cwe_display = f"{cwe_id_raw}: {cwe_details['name']}" if cwe_details else cwe_id_raw
                cwe_display_list.append(cwe_display)
    
    # Separate the primary CWE ID and Name for database storage
    primary_cwe_full = cwe_display_list[0] if cwe_display_list else "N/A"
    primary_cwe_id, primary_cwe_name = (primary_cwe_full.split(':', 1) + [""])[:2] if ':' in primary_cwe_full else (primary_cwe_full, "")
    
    # Join the rest of the CWEs for the secondary field
    secondary_cwes = "\n".join(cwe_display_list[1:]) if len(cwe_display_list) > 1 else None

    return {
        'cve_id': cve_raw.get('id', 'N/A'),
        'published_date': cve_raw.get('published', 'N/A'),
        'description': next((d['value'] for d in cve_raw.get('descriptions', []) if d['lang'] == 'en'), "No description."),
        'severity': metrics.get('baseSeverity', 'N/A'),
        'cvss_score': metrics.get('baseScore', 0.0),
        'vector_string': metrics.get('vectorString', 'N/A'),
        'primary_cwe_id': primary_cwe_id.strip(),
        'primary_cwe_name': primary_cwe_name.strip(),
        'secondary_cwes': secondary_cwes,
    }

def filter_cve_data(cve_list, filters):
    """
    Filters a list of CVE data in memory based on the provided filter criteria.
    """
    filtered_list = cve_list
    severity = filters.get("severity")
    if severity:
        filtered_list = [cve for cve in filtered_list if cve.get('severity') == severity]

    min_cvss = filters.get("min_cvss")
    if min_cvss:
        try:
            min_score = float(min_cvss)
            filtered_list = [cve for cve in filtered_list if (cve.get('cvss_score') or 0.0) >= min_score]
        except (ValueError, TypeError): pass

    max_cvss = filters.get("max_cvss")
    if max_cvss:
        try:
            max_score = float(max_cvss)
            filtered_list = [cve for cve in filtered_list if (cve.get('cvss_score') or 0.0) <= max_score]
        except (ValueError, TypeError): pass
            
    return filtered_list
