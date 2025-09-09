# ai_prompts.py

# This file stores the prompt for the AI enrichment function.
# Separating it makes the main backend code cleaner.

ENRICHMENT_PROMPT = """
Analyze the following CVE description and provide a structured JSON output.
The output must be only the JSON object, with no other text or markdown formatting.

CVE Description: "{description}"

Provide the following fields in a single JSON object:
1. "summary": A concise, easy-to-understand summary in 1-2 sentences.
2. "category": Classify the attack type. Choose one from: Remote Code Execution, Privilege Escalation, Cross-Site Scripting, SQL Injection, Denial of Service, Information Disclosure, Other.
3. "risk_score": An integer risk score from 1 (Low) to 10 (Critical), based on the potential impact.
4. "exploit_payload": A plausible, one-line proof-of-concept payload if applicable. If not applicable or impossible to determine, provide the string "Not applicable".
"""
