"""Enhanced Web Application Firewall (WAF) for SQL Injection Detection

This WAF implements a multi-layered detection approach:
1. Blacklist check (known malicious payloads)
2. Regex pattern matching (signature-based)
3. ML-based detection (behavioral analysis)
4. Encoding attack detection (bypass prevention)

Detection layers are combined using ensemble voting for maximum accuracy.
"""

import os
import re
import urllib.parse
from flask import jsonify, request
from security_logger import log_attack
from typing import Dict, Optional, Tuple

# ============================================================
# CONFIGURATION
# ============================================================

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
BLACKLIST_PATH = os.path.join(BASE_DIR, "blacklist.txt")
ML_MODEL_PATH = os.path.join(BASE_DIR, "data", "random_forest_model.pkl")

# ML Detection settings
ML_ENABLED = True
ML_CONFIDENCE_THRESHOLD = 0.7  # Minimum confidence to flag as malicious

# Ensemble voting weights
WEIGHT_BLACKLIST = 1.0
WEIGHT_REGEX = 0.8
WEIGHT_ML = 0.9

# Load ML detector (lazy loading)
_ml_detector = None

def get_ml_detector():
    """Lazy load ML detector to avoid startup delay."""
    global _ml_detector
    if _ml_detector is None and ML_ENABLED:
        try:
            from ml.ml_detector import SQLiMLDetector, ML_AVAILABLE
            if ML_AVAILABLE and os.path.exists(ML_MODEL_PATH):
                _ml_detector = SQLiMLDetector()
                if _ml_detector.load(ML_MODEL_PATH):
                    print("[WAF] ML detector loaded successfully")
                else:
                    _ml_detector = None
                    print("[WAF] ML detector failed to load model")
            else:
                print(f"[WAF] ML detector not available (ML_AVAILABLE={ML_AVAILABLE}, model_exists={os.path.exists(ML_MODEL_PATH)})")
        except ImportError as e:
            print(f"[WAF] ML detector import failed: {e}")
            _ml_detector = None
    return _ml_detector


# ============================================================
# REGEX PATTERNS (Enhanced)
# ============================================================

SQLI_PATTERNS = [
    # 1) Boolean-based injections and classic tautologies
    r"(?i)\bOR\b\s+1=1",
    r"(?i)\bAND\b\s+1=1",
    r"(?i)('|%27)\s*(OR|AND)\s+[`'0-9]+\s*=\s*[`'0-9]+",
    r"(?i)'\s*OR\s*'1'='1",
    r"(?i)'\s*OR\s*'[^']*'\s*=\s*'[^']*",
    r"(?i)\bOR\b\s+'[^']*'\s*=\s*'[^']*",

    # 2) UNION-based data extraction
    r"(?i)\bUNION\s+(ALL\s+)?SELECT\b",
    r"(?i)\bSELECT\s+.*\bFROM\b",
    r"(?i)\bEXTRACTVALUE\s*\(",
    r"(?i)\bUPDATEXML\s*\(",

    # 3) DDL / DML statements and stacked queries
    r"(?i)\bINSERT\s+INTO\b",
    r"(?i)\bUPDATE\s+\w+\s+SET\b",
    r"(?i)\bDELETE\s+FROM\b",
    r"(?i)\bDROP\s+(TABLE|DATABASE|SCHEMA)\b",
    r"(?i)\bALTER\s+TABLE\b",
    r"(?i)\bCREATE\s+(TABLE|DATABASE|FUNCTION|PROCEDURE)\b",
    r"(?i);\s*(SELECT|INSERT|UPDATE|DELETE|DROP|ALTER|CREATE|EXEC(UTE)?)\b",

    # 4) Time-based / resource exhaustion
    r"(?i)\bSLEEP\s*\(",
    r"(?i)\bBENCHMARK\s*\(",
    r"(?i)\bWAITFOR\s+DELAY\b",
    r"(?i)\bPG_SLEEP\s*\(",
    r"(?i)\bDBMS_PIPE\.RECEIVE_MESSAGE\s*\(",

    # 5) System tables / metadata access
    r"(?i)information_schema",
    r"(?i)\bPG_CATALOG\b",
    r"(?i)\bSYS\.",
    r"(?i)\bMYSQL\.",
    r"(?i)sqlite_master",

    # 6) File / OS interaction
    r"(?i)(load_file|outfile|into\s+dumpfile)",
    r"(?i)\bxp_cmdshell\b",
    r"(?i)\bexec\s+master",

    # 7) Comment-based truncation
    r"(?i)(--|#|/\*)\s*[^\n]*$",
    
    # 8) Advanced patterns
    r"(?i)\bCONCAT\s*\([^)]*@@",
    r"(?i)@@version",
    r"(?i)\bGROUP_CONCAT\s*\(",
    r"(?i)\bHAVING\s+\d+\s*=\s*\d+",
    r"(?i)\bORDER\s+BY\s+\d+",
]

# Additional patterns for comment injection bypass
COMMENT_BYPASS_PATTERNS = [
    r"(?i)/\*.*\*/",  # Block comments
    r"(?i)/\*![0-9]*",  # MySQL version comments
    r"(?i)UN/\*\*/ION",  # Split keywords with comments
    r"(?i)SE/\*\*/LECT",
]

# ============================================================
# ENCODING DETECTION
# ============================================================

def decode_recursive(value: str, max_depth: int = 3) -> str:
    """Recursively decode URL-encoded strings to catch double/triple encoding."""
    if max_depth <= 0:
        return value
    
    try:
        decoded = urllib.parse.unquote(value)
        if decoded != value:
            return decode_recursive(decoded, max_depth - 1)
        return decoded
    except Exception:
        return value


def normalize_input(value: str) -> str:
    """Normalize input by applying multiple decoding and normalization techniques."""
    if not value:
        return value
    
    normalized = value
    
    # 1. URL decode (recursive for double-encoding)
    normalized = decode_recursive(normalized)
    
    # 2. Handle Unicode escapes (%uXXXX)
    try:
        normalized = re.sub(
            r'%u([0-9a-fA-F]{4})',
            lambda m: chr(int(m.group(1), 16)),
            normalized
        )
    except Exception:
        pass
    
    # 3. Remove null bytes
    normalized = normalized.replace('\x00', '')
    normalized = re.sub(r'%00', '', normalized, flags=re.IGNORECASE)
    
    # 4. Normalize whitespace (tabs, newlines, etc.)
    normalized = re.sub(r'[\t\r\n\x0b\x0c]', ' ', normalized)
    
    return normalized


def detect_encoding_attack(value: str) -> Tuple[bool, str]:
    """Detect encoding-based bypass attempts."""
    if not value:
        return False, ""
    
    # Check for double URL encoding
    if re.search(r'%25[0-9a-fA-F]{2}', value):
        return True, "double_url_encoding"
    
    # Check for Unicode encoding
    if re.search(r'%u[0-9a-fA-F]{4}', value):
        return True, "unicode_encoding"
    
    # Check for null byte injection
    if '\x00' in value or '%00' in value.lower():
        return True, "null_byte_injection"
    
    # Check for hex encoding
    if re.search(r'0x[0-9a-fA-F]{4,}', value):
        decoded_check = decode_recursive(value)
        if detect_sqli_regex(decoded_check):
            return True, "hex_encoding"
    
    # Check for CHAR() encoding
    if re.search(r'(?i)CHAR\s*\(\s*\d+\s*\)', value):
        return True, "char_encoding"
    
    # Check for comment-based keyword splitting
    if re.search(r'(?i)(UN|SE|IN|UP|DE|DR|AL|CR)[/\*]+[/\*]*(ION|LECT|SERT|DATE|LETE|OP|TER|EATE)', value):
        return True, "comment_splitting"
    
    return False, ""


# ============================================================
# SAFE PATHS
# ============================================================

SAFE_PATHS = [
    "/api/register",
    "/api/auth/me",
    "/api/products",
    "/api/health",
    "/api/test-db",
    "/api/security",
]


def is_safe_path(path: str) -> bool:
    """Check if path should skip WAF inspection."""
    for safe_path in SAFE_PATHS:
        if path.startswith(safe_path):
            return True
    return False


# ============================================================
# BLACKLIST
# ============================================================

def _load_blacklist() -> set:
    """Load blacklisted payloads from blacklist.txt."""
    if not os.path.exists(BLACKLIST_PATH):
        return set()
    try:
        with open(BLACKLIST_PATH, "r", encoding="utf-8", errors="ignore") as f:
            return {line.strip() for line in f if line.strip() and not line.startswith("#")}
    except Exception:
        return set()


def is_blacklisted(value: str) -> bool:
    """Check if value matches a blacklisted payload."""
    if not value or not isinstance(value, str):
        return False
    blacklist = _load_blacklist()
    
    # Check exact match
    if value.strip() in blacklist:
        return True
    
    # Check normalized match
    normalized = normalize_input(value)
    if normalized.strip() in blacklist:
        return True
    
    return False


# ============================================================
# DETECTION FUNCTIONS
# ============================================================

def detect_sqli_regex(value: str) -> bool:
    """Detect SQL injection using regex patterns."""
    if not value or not isinstance(value, str):
        return False

    for pattern in SQLI_PATTERNS:
        if re.search(pattern, value):
            return True
    
    # Check comment bypass patterns
    for pattern in COMMENT_BYPASS_PATTERNS:
        if re.search(pattern, value):
            return True
    
    return False


def detect_sqli_ml(value: str) -> Dict:
    """Detect SQL injection using ML model."""
    detector = get_ml_detector()
    
    if detector is None:
        return {
            "is_malicious": False,
            "confidence": 0.0,
            "model_type": "unavailable",
            "enabled": False
        }
    
    try:
        result = detector.predict(value)
        result["enabled"] = True
        return result
    except Exception as e:
        print(f"[WAF] ML prediction error: {e}")
        return {
            "is_malicious": False,
            "confidence": 0.0,
            "model_type": "error",
            "enabled": False,
            "error": str(e)
        }


def detect_sqli(value: str) -> bool:
    """Legacy function for backward compatibility. Uses regex detection only."""
    return detect_sqli_regex(value)


def detect_sqli_ensemble(value: str) -> Dict:
    """Ensemble detection combining all methods."""
    if not value or not isinstance(value, str):
        return {
            "is_malicious": False,
            "confidence": 0.0,
            "detection_methods": [],
            "details": {}
        }
    
    # Normalize input for better detection
    normalized = normalize_input(value)
    
    detection_methods = []
    details = {}
    total_score = 0.0
    max_weight = 0.0
    
    # 1. Blacklist check
    is_bl = is_blacklisted(value) or is_blacklisted(normalized)
    details["blacklist"] = {"detected": is_bl}
    if is_bl:
        detection_methods.append("blacklist")
        total_score += WEIGHT_BLACKLIST
    max_weight += WEIGHT_BLACKLIST
    
    # 2. Regex detection (on both original and normalized)
    is_regex = detect_sqli_regex(value) or detect_sqli_regex(normalized)
    details["regex"] = {"detected": is_regex}
    if is_regex:
        detection_methods.append("regex")
        total_score += WEIGHT_REGEX
    max_weight += WEIGHT_REGEX
    
    # 3. Encoding attack detection
    is_encoding, encoding_type = detect_encoding_attack(value)
    details["encoding"] = {"detected": is_encoding, "type": encoding_type}
    if is_encoding:
        detection_methods.append(f"encoding:{encoding_type}")
        total_score += 0.5
    
    # 4. ML detection
    ml_result = detect_sqli_ml(normalized)
    details["ml"] = ml_result
    if ml_result.get("enabled") and ml_result.get("is_malicious") and ml_result.get("confidence", 0) >= ML_CONFIDENCE_THRESHOLD:
        detection_methods.append("ml")
        total_score += WEIGHT_ML * ml_result.get("confidence", 0)
    if ml_result.get("enabled"):
        max_weight += WEIGHT_ML
    
    # Calculate ensemble confidence
    ensemble_confidence = total_score / max_weight if max_weight > 0 else 0.0
    
    # Decision: malicious if any method detected OR ensemble confidence > 0.5
    is_malicious = len(detection_methods) > 0 or ensemble_confidence > 0.5
    
    return {
        "is_malicious": is_malicious,
        "confidence": ensemble_confidence,
        "detection_methods": detection_methods,
        "details": details,
        "normalized_input": normalized[:100] if len(normalized) > 100 else normalized
    }


# ============================================================
# LOGGING
# ============================================================

def safe_log_attack(**kwargs):
    """Safely log attack without crashing on errors."""
    try:
        log_attack(**kwargs)
    except Exception as e:
        print("[WAF] log_attack failed:", e)


# ============================================================
# MAIN WAF INSPECTION
# ============================================================

def inspect_value(value: str, field_name: str, location: str, client_ip: str) -> Optional[Dict]:
    """Inspect a single value for SQL injection."""
    if not value or not isinstance(value, str):
        return None
    
    # Run ensemble detection
    result = detect_sqli_ensemble(value)
    
    if result["is_malicious"]:
        # Determine block type for response - prioritize by detection order
        # Priority: Blacklist > ML > Encoding > Regex
        methods = result["detection_methods"]
        
        if "blacklist" in methods:
            block_type = "Blacklist"
        elif "ml" in methods:
            block_type = "ML"
        elif any("encoding" in m for m in methods):
            block_type = "Encoding"
        elif "regex" in methods:
            block_type = "Regex"
        else:
            block_type = "WAF"
        
        # Log the attack
        safe_log_attack(
            ip=client_ip,
            payload=value,
            reason=f"SQLi detected in {location} field '{field_name}' at {request.path} | Methods: {result['detection_methods']} | Confidence: {result['confidence']:.2f}"
        )
        
        return {
            "error": "Malicious code detected",
            "blocked_by": block_type,
            "field": field_name,
            "confidence": round(result["confidence"], 2),
            "detection_methods": result["detection_methods"]
        }
    
    return None


def inspect_nested_value(value, key_path: str, location: str, client_ip: str) -> Optional[Dict]:
    """Recursively inspect nested values (arrays, dicts) for SQL injection."""
    if isinstance(value, str):
        return inspect_value(value, key_path, location, client_ip)
    elif isinstance(value, list):
        for i, item in enumerate(value):
            result = inspect_nested_value(item, f"{key_path}[{i}]", location, client_ip)
            if result:
                return result
    elif isinstance(value, dict):
        for sub_key, sub_value in value.items():
            result = inspect_nested_value(sub_value, f"{key_path}.{sub_key}", location, client_ip)
            if result:
                return result
    return None


def waf_inspect_request():
    """Main WAF inspection function - inspects ALL request methods and content types."""
    # Only skip OPTIONS (preflight)
    if request.method == "OPTIONS":
        return None

    client_ip = request.remote_addr or "unknown"

    # =========================================================
    # ALWAYS INSPECT - These checks apply to ALL requests
    # =========================================================

    # 1. Query parameters (prevents ?id=' OR '1'='1)
    for key, value in request.args.items():
        result = inspect_value(str(value), key, "query", client_ip)
        if result:
            return jsonify(result), 403
        result = inspect_value(str(key), f"query_key:{key}", "query", client_ip)
        if result:
            return jsonify(result), 403

    # 2. Cookies (attackers can inject via cookies on ANY endpoint)
    for key, value in request.cookies.items():
        if key.lower() in ('csrftoken', 'csrf_token', 'sessionid', '_ga', '_gid', '_gat', 
                           'access_token_cookie', 'refresh_token_cookie', 'csrf_access_token', 'csrf_refresh_token'):
            continue
        result = inspect_value(str(value), key, "cookie", client_ip)
        if result:
            return jsonify(result), 403

    # 3. Headers that could be attack vectors
    suspicious_headers = [
        'User-Agent', 'Referer', 'X-Forwarded-For', 'X-Real-IP',
        'X-Forwarded-Host', 'X-Original-URL', 'X-Rewrite-URL',
        'Content-Type', 'Accept', 'Origin', 'X-Custom-Header',
        'X-Api-Key', 'X-Auth-Token', 'Proxy-Authorization'
    ]
    for header in suspicious_headers:
        value = request.headers.get(header)
        if value:
            # Skip normal content types
            if header == 'Content-Type' and any(ct in value.lower() for ct in 
                ['application/json', 'text/plain', 'text/html', 'multipart/form-data', 
                 'application/x-www-form-urlencoded', 'application/xml']):
                continue
            # Skip normal Accept headers
            if header == 'Accept' and not any(x in value.lower() for x in ['select', 'union', 'drop', 'insert', 'delete']):
                continue
            result = inspect_value(str(value), header, "header", client_ip)
            if result:
                return jsonify(result), 403

    # 4. URL path segments (ALWAYS inspect - catches injections in /api/products/<payload>)
    path_parts = request.path.split('/')
    for part in path_parts:
        if part and not part.isdigit():  # Skip numeric IDs
            result = inspect_value(part, "path_segment", "url", client_ip)
            if result:
                return jsonify(result), 403

    # Skip body inspection for safe paths (query params, cookies, headers, path segments were checked above)
    if is_safe_path(request.path):
        return None

    # =========================================================
    # 1. Inspect JSON body (application/json)
    # =========================================================
    if request.is_json:
        try:
            data = request.get_json(silent=True)
            if data is None and request.content_length and request.content_length > 0:
                return jsonify({"error": "Malformed JSON"}), 400
            if data:
                if isinstance(data, dict):
                    for key, value in data.items():
                        result = inspect_nested_value(value, key, "json_body", client_ip)
                        if result:
                            return jsonify(result), 403
                elif isinstance(data, list):
                    for i, item in enumerate(data):
                        result = inspect_nested_value(item, f"[{i}]", "json_body", client_ip)
                        if result:
                            return jsonify(result), 403
        except Exception as e:
            print(f"[WAF] JSON parsing error: {e}")

    # =========================================================
    # 3. Inspect form data (application/x-www-form-urlencoded)
    # =========================================================
    for key, value in request.form.items():
        result = inspect_value(str(value), key, "form", client_ip)
        if result:
            return jsonify(result), 403
        # Check key as well
        result = inspect_value(str(key), f"form_key:{key}", "form", client_ip)
        if result:
            return jsonify(result), 403

    # =========================================================
    # 4. Inspect file uploads (multipart/form-data)
    # =========================================================
    for key, file in request.files.items():
        # Check filename for injection
        if file.filename:
            result = inspect_value(file.filename, f"file:{key}:filename", "file", client_ip)
            if result:
                return jsonify(result), 403
        # Check content-type header of uploaded file
        if file.content_type:
            result = inspect_value(file.content_type, f"file:{key}:content_type", "file", client_ip)
            if result:
                return jsonify(result), 403

    # =========================================================
    # 5. Inspect raw body (text/plain, application/xml, etc.)
    # =========================================================
    content_type = request.content_type or ''
    if not request.is_json and request.data:
        # Only inspect text-based content types
        if any(ct in content_type.lower() for ct in ['text/', 'xml', 'html', 'plain']):
            try:
                raw_data = request.data.decode('utf-8', errors='ignore')
                if raw_data:
                    result = inspect_value(raw_data[:10000], "raw_body", "body", client_ip)  # Limit to 10KB
                    if result:
                        return jsonify(result), 403
            except Exception as e:
                print(f"[WAF] Raw body inspection error: {e}")

    return None


# ============================================================
# UTILITY FUNCTIONS
# ============================================================

def get_waf_status() -> Dict:
    """Get current WAF status and configuration."""
    ml_detector = get_ml_detector()
    
    return {
        "enabled": True,
        "ml_enabled": ML_ENABLED,
        "ml_loaded": ml_detector is not None,
        "ml_model_path": ML_MODEL_PATH,
        "ml_confidence_threshold": ML_CONFIDENCE_THRESHOLD,
        "regex_patterns_count": len(SQLI_PATTERNS),
        "blacklist_count": len(_load_blacklist()),
        "weights": {
            "blacklist": WEIGHT_BLACKLIST,
            "regex": WEIGHT_REGEX,
            "ml": WEIGHT_ML
        }
    }


def test_payload(payload: str) -> Dict:
    """Test a payload against all detection methods."""
    return detect_sqli_ensemble(payload)
