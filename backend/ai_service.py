# backend/ai_service.py
import google.generativeai as genai
import json
from ai_prompts import ENRICHMENT_PROMPT
import database
import config_manager

# --- API Key Setup ---
config = config_manager.load_config()
GEMINI_API_KEY = config.get("GEMINI_API_KEY")

gemini_model = None
if GEMINI_API_KEY:
    genai.configure(api_key=GEMINI_API_KEY)
    gemini_model = genai.GenerativeModel('gemini-1.5-flash-latest')
else:
    print("Warning: GEMINI_API_KEY not found. AI enrichment will be disabled.")

def get_ai_enrichment(description: str):
    """Calls the Gemini API to analyze a CVE description."""
    if not gemini_model:
        return {"summary": "AI Disabled", "category": "N/A", "risk_score": 0, "exploit_payload": "N/A"}

    prompt = ENRICHMENT_PROMPT.format(description=description)
    
    try:
        generation_config = genai.types.GenerationConfig(response_mime_type="application/json")
        response = gemini_model.generate_content(prompt, generation_config=generation_config)
        return json.loads(response.text)
    except Exception as e:
        print(f"AI enrichment failed: {e}")
        return {"summary": "AI analysis failed", "category": "Error", "risk_score": 0, "exploit_payload": "Error"}

def get_and_update_ai_enrichment(cve_id: str):
    """Gets AI enrichment for a single, existing CVE and updates the DB."""
    print(f"AI: Enriching {cve_id}...")
    cve_data_list = database.query_local_cves(cve_id)
    if not cve_data_list:
        return {"error": "CVE not found in local database."}
    
    cve_data = cve_data_list[0]

    if cve_data.get('ai_summary'):
        print(f"AI: {cve_id} is already enriched. Returning cached data.")
        return cve_data

    ai_data = get_ai_enrichment(cve_data['description'])
    
    cve_data.update({
        'ai_summary': ai_data.get('summary'),
        'ai_category': ai_data.get('category'),
        'ai_risk_score': ai_data.get('risk_score'),
        'ai_exploit_payload': ai_data.get('exploit_payload')
    })
    
    database.insert_cve(cve_data)
    print(f"AI: Successfully enriched and updated {cve_id}.")
    return cve_data

def format_ai_analysis_for_display(cve):
    """Creates a formatted string for the AI analysis pop-up window."""
    if not cve or cve.get('error'):
        return cve.get('error', 'Unknown error.')
    
    return (
        f"CVE ID: {cve['cve_id']}\n"
        f"Severity: {cve.get('severity', 'N/A')}\n"
        f"Published: {cve.get('published_date', 'N/A')}\n\n"
        f"Description:\n{cve.get('description', 'N/A')}\n\n"
        f"{'='*80}\n"
        f"AI Analysis\n"
        f"{'-'*80}\n"
        f"Summary: {cve.get('ai_summary', 'N/A')}\n"
        f"Category: {cve.get('ai_category', 'N/A')}\n"
        f"Risk Score: {cve.get('ai_risk_score', 'N/A')} / 10\n"
        f"Example Payload: {cve.get('ai_exploit_payload', 'N/A')}\n"
    )
