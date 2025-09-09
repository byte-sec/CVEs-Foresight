# validation.py
import re
import json
from typing import Dict, Any, List, Optional, Union
from datetime import datetime
import logging

logger = logging.getLogger(__name__)

class ValidationError(Exception):
    """Custom exception for validation errors"""
    pass

class SecurityError(Exception):
    """Custom exception for security-related validation failures"""
    pass

# Regular expressions for common patterns
CVE_ID_PATTERN = re.compile(r'^CVE-\d{4}-\d{4,}$', re.IGNORECASE)
CWE_ID_PATTERN = re.compile(r'^CWE-\d+$', re.IGNORECASE)
CPE_PATTERN = re.compile(r'^cpe:2\.[23]:[ahow]:', re.IGNORECASE)
API_KEY_PATTERN = re.compile(r'^[a-fA-F0-9]{8}-[a-fA-F0-9]{4}-[a-fA-F0-9]{4}-[a-fA-F0-9]{4}-[a-fA-F0-9]{12}$')

# Dangerous patterns to detect potential injection attacks
DANGEROUS_PATTERNS = [
    re.compile(r'<script', re.IGNORECASE),
    re.compile(r'javascript:', re.IGNORECASE),
    re.compile(r'vbscript:', re.IGNORECASE),
    re.compile(r'onload\s*=', re.IGNORECASE),
    re.compile(r'onerror\s*=', re.IGNORECASE),
    re.compile(r'<iframe', re.IGNORECASE),
    re.compile(r'<embed', re.IGNORECASE),
    re.compile(r'<object', re.IGNORECASE),
    re.compile(r'union\s+select', re.IGNORECASE),
    re.compile(r'drop\s+table', re.IGNORECASE),
    re.compile(r'delete\s+from', re.IGNORECASE),
    re.compile(r'insert\s+into', re.IGNORECASE),
]

def validate_cve_id(cve_id: str) -> str:
    """
    Validate CVE ID format.
    
    Args:
        cve_id: CVE identifier to validate
        
    Returns:
        Normalized CVE ID
        
    Raises:
        ValidationError: If CVE ID format is invalid
    """
    if not cve_id or not isinstance(cve_id, str):
        raise ValidationError("CVE ID must be a non-empty string")
    
    cve_id = cve_id.strip().upper()
    
    if not CVE_ID_PATTERN.match(cve_id):
        raise ValidationError(f"Invalid CVE ID format: {cve_id}. Expected format: CVE-YYYY-NNNN")
    
    # Additional validation: year should be reasonable
    year_match = re.search(r'CVE-(\d{4})-', cve_id)
    if year_match:
        year = int(year_match.group(1))
        current_year = datetime.now().year
        if year < 1999 or year > current_year + 1:
            raise ValidationError(f"CVE year {year} is outside valid range (1999-{current_year + 1})")
    
    return cve_id

def validate_cwe_id(cwe_id: str) -> str:
    """
    Validate CWE ID format.
    
    Args:
        cwe_id: CWE identifier to validate
        
    Returns:
        Normalized CWE ID
        
    Raises:
        ValidationError: If CWE ID format is invalid
    """
    if not cwe_id or cwe_id.upper() == 'N/A':
        return 'N/A'
    
    if not isinstance(cwe_id, str):
        raise ValidationError("CWE ID must be a string")
    
    cwe_id = cwe_id.strip().upper()
    
    if not CWE_ID_PATTERN.match(cwe_id):
        raise ValidationError(f"Invalid CWE ID format: {cwe_id}. Expected format: CWE-NNN")
    
    return cwe_id

def validate_cvss_score(score: Union[float, str, None]) -> float:
    """
    Validate CVSS score.
    
    Args:
        score: CVSS score to validate
        
    Returns:
        Validated CVSS score
        
    Raises:
        ValidationError: If CVSS score is invalid
    """
    if score is None or score == '' or score == 'N/A':
        return 0.0
    
    try:
        score = float(score)
    except (ValueError, TypeError):
        raise ValidationError(f"CVSS score must be a number, got: {type(score).__name__}")
    
    if not 0.0 <= score <= 10.0:
        raise ValidationError(f"CVSS score must be between 0.0 and 10.0, got: {score}")
    
    return round(score, 1)  # Round to 1 decimal place

def validate_severity(severity: str) -> str:
    """
    Validate severity level.
    
    Args:
        severity: Severity level to validate
        
    Returns:
        Normalized severity level
        
    Raises:
        ValidationError: If severity is invalid
    """
    if not severity:
        return 'N/A'
    
    if not isinstance(severity, str):
        raise ValidationError("Severity must be a string")
    
    severity = severity.strip().upper()
    valid_severities = {'CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'N/A'}
    
    if severity not in valid_severities:
        raise ValidationError(f"Invalid severity: {severity}. Must be one of: {', '.join(valid_severities)}")
    
    return severity

def validate_api_key(api_key: str, key_type: str) -> str:
    """
    Validate API key format and basic security.
    
    Args:
        api_key: API key to validate
        key_type: Type of API key ('NVD' or 'GEMINI')
        
    Returns:
        Validated API key
        
    Raises:
        ValidationError: If API key is invalid
        SecurityError: If API key appears to be compromised
    """
    if not api_key or not isinstance(api_key, str):
        raise ValidationError(f"{key_type} API key must be a non-empty string")
    
    api_key = api_key.strip()
    
    # Check for dangerous patterns that might indicate injection attempts
    if any(pattern.search(api_key) for pattern in DANGEROUS_PATTERNS):
        raise SecurityError(f"{key_type} API key contains potentially dangerous content")
    
    # Basic length validation
    if len(api_key) < 16:
        raise ValidationError(f"{key_type} API key appears too short (minimum 16 characters)")
    
    if len(api_key) > 200:
        raise ValidationError(f"{key_type} API key appears too long (maximum 200 characters)")
    
    # NVD-specific validation (UUID format)
    if key_type.upper() == 'NVD':
        if not API_KEY_PATTERN.match(api_key):
            logger.warning(f"NVD API key doesn't match expected UUID format")
            # Don't raise error as format might change, just log warning
    
    # Check for obviously fake/test keys
    test_patterns = ['test', 'fake', 'dummy', 'sample', 'example', '12345', 'abcdef']
    api_key_lower = api_key.lower()
    if any(pattern in api_key_lower for pattern in test_patterns):
        logger.warning(f"{key_type} API key appears to be a test/fake key")
    
    return api_key

def validate_search_keyword(keyword: str) -> str:
    """
    Validate and sanitize search keywords.
    
    Args:
        keyword: Search keyword to validate
        
    Returns:
        Sanitized search keyword
        
    Raises:
        ValidationError: If keyword is invalid
        SecurityError: If keyword contains dangerous patterns
    """
    if not keyword:
        return ""
    
    if not isinstance(keyword, str):
        raise ValidationError("Search keyword must be a string")
    
    keyword = keyword.strip()
    
    # Check length
    if len(keyword) > 500:
        raise ValidationError("Search keyword is too long (maximum 500 characters)")
    
    # Check for dangerous patterns
    if any(pattern.search(keyword) for pattern in DANGEROUS_PATTERNS):
        raise SecurityError("Search keyword contains potentially dangerous content")
    
    # Check for SQL injection patterns
    sql_injection_patterns = [
        r"'.*OR.*'.*='",
        r"'.*AND.*'.*='",
        r"'.*UNION.*SELECT",
        r"--.*",
        r"/\*.*\*/",
    ]
    
    for pattern in sql_injection_patterns:
        if re.search(pattern, keyword, re.IGNORECASE):
            raise SecurityError("Search keyword contains potential SQL injection patterns")
    
    return keyword

def validate_nvd_search_params(params: Dict[str, Any]) -> Dict[str, Any]:
    """
    Validate NVD API search parameters.
    
    Args:
        params: Dictionary of search parameters
        
    Returns:
        Validated and sanitized parameters
        
    Raises:
        ValidationError: If parameters are invalid
    """
    if not isinstance(params, dict):
        raise ValidationError("Search parameters must be a dictionary")
    
    validated_params = {}
    
    # Validate each parameter
    for key, value in params.items():
        if not isinstance(key, str):
            raise ValidationError(f"Parameter key must be string, got: {type(key).__name__}")
        
        key = key.strip()
        
        # Validate specific parameters
        if key == 'cveId':
            validated_params[key] = validate_cve_id(value)
        elif key == 'keywordSearch':
            validated_params[key] = validate_search_keyword(value)
        elif key == 'cvssV3Severity':
            validated_params[key] = validate_severity(value)
        elif key == 'cpeName':
            if not isinstance(value, str):
                raise ValidationError("CPE name must be a string")
            value = value.strip()
            if value and not CPE_PATTERN.match(value):
                raise ValidationError(f"Invalid CPE format: {value}")
            validated_params[key] = value
        elif key in ['resultsPerPage', 'startIndex']:
            if not isinstance(value, (int, str)):
                raise ValidationError(f"{key} must be a number")
            try:
                num_value = int(value)
                if num_value < 0:
                    raise ValidationError(f"{key} must be non-negative")
                if key == 'resultsPerPage' and num_value > 2000:
                    raise ValidationError("resultsPerPage cannot exceed 2000")
                validated_params[key] = num_value
            except ValueError:
                raise ValidationError(f"Invalid number format for {key}: {value}")
        else:
            # For unknown parameters, do basic sanitization
            if isinstance(value, str):
                value = value.strip()
                if any(pattern.search(value) for pattern in DANGEROUS_PATTERNS):
                    raise SecurityError(f"Parameter {key} contains dangerous content")
            validated_params[key] = value
    
    return validated_params

def validate_cve_data(cve_data: Dict[str, Any]) -> Dict[str, Any]:
    """
    Validate CVE data structure and content.
    
    Args:
        cve_data: CVE data dictionary
        
    Returns:
        Validated CVE data
        
    Raises:
        ValidationError: If CVE data is invalid
    """
    if not isinstance(cve_data, dict):
        raise ValidationError("CVE data must be a dictionary")
    
    validated_data = {}
    
    # Required fields
    if 'cve_id' not in cve_data:
        raise ValidationError("CVE data must include cve_id")
    
    validated_data['cve_id'] = validate_cve_id(cve_data['cve_id'])
    
    # Validate other fields
    if 'cvss_score' in cve_data:
        validated_data['cvss_score'] = validate_cvss_score(cve_data['cvss_score'])
    
    if 'severity' in cve_data:
        validated_data['severity'] = validate_severity(cve_data['severity'])
    
    if 'primary_cwe_id' in cve_data:
        validated_data['primary_cwe_id'] = validate_cwe_id(cve_data['primary_cwe_id'])
    
    # Validate string fields
    string_fields = ['description', 'vector_string', 'primary_cwe_name', 'secondary_cwes', 
                     'ai_summary', 'ai_category', 'ai_exploit_payload', 'published_date']
    
    for field in string_fields:
        if field in cve_data:
            value = cve_data[field]
            if value is not None:
                if not isinstance(value, str):
                    raise ValidationError(f"{field} must be a string, got: {type(value).__name__}")
                
                # Basic length validation
                max_lengths = {
                    'description': 10000,
                    'vector_string': 200,
                    'primary_cwe_name': 500,
                    'secondary_cwes': 2000,
                    'ai_summary': 2000,
                    'ai_category': 100,
                    'ai_exploit_payload': 1000,
                    'published_date': 50
                }
                
                max_length = max_lengths.get(field, 1000)
                if len(value) > max_length:
                    raise ValidationError(f"{field} exceeds maximum length of {max_length} characters")
                
                validated_data[field] = value.strip()
    
    # Validate AI risk score
    if 'ai_risk_score' in cve_data:
        risk_score = cve_data['ai_risk_score']
        if risk_score is not None:
            try:
                risk_score = int(risk_score)
                if not 1 <= risk_score <= 10:
                    raise ValidationError("AI risk score must be between 1 and 10")
                validated_data['ai_risk_score'] = risk_score
            except (ValueError, TypeError):
                raise ValidationError("AI risk score must be an integer")
    
    return validated_data

def sanitize_for_display(text: str, max_length: int = None) -> str:
    """
    Sanitize text for safe display in GUI components.
    
    Args:
        text: Text to sanitize
        max_length: Maximum length (truncate if longer)
        
    Returns:
        Sanitized text safe for display
    """
    if not text:
        return ""
    
    if not isinstance(text, str):
        text = str(text)
    
    # Remove null bytes and control characters
    text = ''.join(char for char in text if ord(char) >= 32 or char in '\n\r\t')
    
    # Truncate if needed
    if max_length and len(text) > max_length:
        text = text[:max_length - 3] + "..."
    
    return text

def validate_configuration(config: Dict[str, Any]) -> Dict[str, Any]:
    """
    Validate application configuration.
    
    Args:
        config: Configuration dictionary
        
    Returns:
        Validated configuration
        
    Raises:
        ValidationError: If configuration is invalid
    """
    if not isinstance(config, dict):
        raise ValidationError("Configuration must be a dictionary")
    
    validated_config = {}
    
    # Validate API keys
    if 'NVD_API_KEY' in config:
        validated_config['NVD_API_KEY'] = validate_api_key(config['NVD_API_KEY'], 'NVD')
    
    if 'GEMINI_API_KEY' in config:
        validated_config['GEMINI_API_KEY'] = validate_api_key(config['GEMINI_API_KEY'], 'GEMINI')
    
    return validated_config