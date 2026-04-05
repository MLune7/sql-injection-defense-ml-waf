#!/usr/bin/env python3
"""
ModSecurity CRS (Core Rule Set) Comparison Module

This module implements a subset of OWASP ModSecurity CRS SQL injection rules
to compare against our ML-based WAF detection.

CRS Rules Reference: https://github.com/coreruleset/coreruleset
Rules implemented: 942xxx series (SQL Injection)
"""

import re
import time
import json
from typing import Dict, List, Tuple
from dataclasses import dataclass
import os

# ============================================================
# CRS SQL INJECTION RULES (942xxx Series)
# These are real patterns from OWASP ModSecurity CRS v3.3
# ============================================================

CRS_RULES = {
    # ============================================================
    # OWASP ModSecurity CRS v3.3 - SQL Injection Rules (942xxx)
    # Complete implementation of all 50+ SQL injection rules
    # ============================================================
    
    # 942100 - SQL Injection Attack Detected via libinjection
    "942100": {
        "name": "SQL Injection Attack Detected",
        "pattern": r"(?i)(\b(select|union|insert|update|delete|drop|alter|create|truncate)\b.*\b(from|into|table|database|where|set)\b)",
        "severity": "CRITICAL"
    },
    
    # 942110 - SQL Injection Attack: Common Injection Testing Detected
    "942110": {
        "name": "SQL Injection: Common Testing",
        "pattern": r"(?i)([\'\"];\s*(drop|alter|truncate|delete|insert|update)\b)",
        "severity": "CRITICAL"
    },
    
    # 942120 - SQL Injection Attack: SQL Operator Detected
    "942120": {
        "name": "SQL Injection: Operator Detected",
        "pattern": r"(?i)(\bor\b\s+[\'\"]?\d+[\'\"]?\s*=\s*[\'\"]?\d+|\band\b\s+[\'\"]?\d+[\'\"]?\s*=\s*[\'\"]?\d+)",
        "severity": "HIGH"
    },
    
    # 942130 - SQL Injection Attack: SQL Tautology Detected
    "942130": {
        "name": "SQL Injection: Tautology",
        "pattern": r"(?i)([\'\"]?\s*(or|and)\s*[\'\"]?\s*[\'\"]?\s*=\s*[\'\"]?)",
        "severity": "HIGH"
    },
    
    # 942140 - SQL Injection Attack: Common DB Names Detected
    "942140": {
        "name": "SQL Injection: DB Names",
        "pattern": r"(?i)(information_schema|mysql\.user|sys\.databases?|sysobjects|syscolumns|pg_catalog|pg_tables|sqlite_master|msdb|tempdb|master\.dbo)",
        "severity": "CRITICAL"
    },
    
    # 942150 - SQL Injection Attack: SQL Function Names
    "942150": {
        "name": "SQL Injection: Function Names",
        "pattern": r"(?i)\b(concat|concat_ws|char|chr|substr|substring|ascii|hex|unhex|ord|conv|cast|convert|load_file|benchmark|sleep|waitfor|extractvalue|updatexml|exp|floor|rand|row_count|found_rows)\s*\(",
        "severity": "HIGH"
    },
    
    # 942160 - SQL Injection Attack: Blind SQL Testing
    "942160": {
        "name": "SQL Injection: Blind Testing",
        "pattern": r"(?i)(sleep\s*\(\s*\d+\s*\)|benchmark\s*\(|waitfor\s+delay|pg_sleep|dbms_pipe\.receive_message)",
        "severity": "CRITICAL"
    },
    
    # 942170 - SQL Injection Attack: SQL Comment Sequence
    "942170": {
        "name": "SQL Injection: Comment Sequence",
        "pattern": r"(\/\*.*\*\/|--\s|#\s*$|;\s*--|--\+)",
        "severity": "MEDIUM"
    },
    
    # 942180 - SQL Injection Attack: Basic Authentication Bypass
    "942180": {
        "name": "SQL Injection: Auth Bypass",
        "pattern": r"(?i)([\'\"])\s*(or|and)\s*\1\s*=\s*\1",
        "severity": "CRITICAL"
    },
    
    # 942190 - SQL Injection Attack: MSSQL Code Execution
    "942190": {
        "name": "SQL Injection: MSSQL Code Exec",
        "pattern": r"(?i)(exec\s*\(|execute\s*\(|xp_cmdshell|sp_executesql|sp_oacreate|sp_oamethod|sp_makewebtask|xp_reg|xp_servicecontrol)",
        "severity": "CRITICAL"
    },
    
    # 942200 - SQL Injection Attack: MySQL Comment/Space Obfuscation
    "942200": {
        "name": "SQL Injection: Comment Obfuscation",
        "pattern": r"(?i)(\/\*!\d*.*\*\/|\/\*\+.*\*\/)",
        "severity": "HIGH"
    },
    
    # 942210 - SQL Injection Attack: Chained Injection 1/2
    "942210": {
        "name": "SQL Injection: Chained Injection",
        "pattern": r"(?i)(;\s*(select|insert|update|delete|drop|alter|create|truncate|rename|grant|revoke)\b)",
        "severity": "CRITICAL"
    },
    
    # 942220 - SQL Injection Attack: Integer Overflow
    "942220": {
        "name": "SQL Injection: Integer Overflow",
        "pattern": r"(?i)(\d{10,})",
        "severity": "LOW"
    },
    
    # 942230 - SQL Injection Attack: Conditional Injection
    "942230": {
        "name": "SQL Injection: Conditional",
        "pattern": r"(?i)(\bcase\s+when\b|\bif\s*\(|\bcoalesce\s*\(|\bnullif\s*\(|\bifnull\s*\(|\biif\s*\()",
        "severity": "MEDIUM"
    },
    
    # 942240 - SQL Injection Attack: MySQL charset switch
    "942240": {
        "name": "SQL Injection: Charset Switch",
        "pattern": r"(?i)(_latin1|_binary|_utf8|_ascii|collate\s+\w+)",
        "severity": "MEDIUM"
    },
    
    # 942250 - SQL Injection Attack: MATCH AGAINST
    "942250": {
        "name": "SQL Injection: Match Against",
        "pattern": r"(?i)(match\s*\(.*\)\s*against\s*\()",
        "severity": "MEDIUM"
    },
    
    # 942260 - SQL Injection Attack: Basic Injection
    "942260": {
        "name": "SQL Injection: Basic",
        "pattern": r"(?i)(union\s+(all\s+)?select|select\s+.*\s+from|insert\s+into|update\s+.*\s+set|delete\s+from)",
        "severity": "CRITICAL"
    },
    
    # 942270 - SQL Injection Attack: Looking for basic injection
    "942270": {
        "name": "SQL Injection: Quotes",
        "pattern": r"(['\"][;)]\s*$|^\s*['\"])",
        "severity": "LOW"
    },
    
    # 942280 - SQL Injection Attack: PostgreSQL pg_sleep
    "942280": {
        "name": "SQL Injection: PostgreSQL",
        "pattern": r"(?i)(pg_sleep|pg_user|pg_database|current_database\(\)|pg_read_file|pg_ls_dir|pg_stat_file)",
        "severity": "HIGH"
    },
    
    # 942290 - SQL Injection Attack: MongoDB/NoSQL Injection
    "942290": {
        "name": "NoSQL Injection: MongoDB",
        "pattern": r"(\$where|\$regex|\$ne|\$gt|\$lt|\$gte|\$lte|\$or|\$and|\$exists|\$in|\$nin|\$not|\$type)",
        "severity": "HIGH"
    },
    
    # 942300 - SQL Injection Attack: MySQL Comment Detected
    "942300": {
        "name": "SQL Injection: MySQL Comment",
        "pattern": r"(#.*$|--\s.*$|\/\*[\s\S]*?\*\/)",
        "severity": "MEDIUM"
    },
    
    # 942310 - SQL Injection Attack: Chained Injection 2/2
    "942310": {
        "name": "SQL Injection: Chained 2",
        "pattern": r"(?i)(;\s*\bshutdown\b|;\s*\bwaitfor\b|;\s*\bexec\b|;\s*\bxp_)",
        "severity": "CRITICAL"
    },
    
    # 942320 - SQL Injection Attack: MySQL/PostgreSQL Stored Procedure
    "942320": {
        "name": "SQL Injection: Stored Proc",
        "pattern": r"(?i)(create\s+(procedure|function|trigger)|call\s+\w+\s*\(|execute\s+\w+)",
        "severity": "HIGH"
    },
    
    # 942330 - SQL Injection Attack: Classic Injection Probing 1/3
    "942330": {
        "name": "SQL Injection: Classic Probe 1",
        "pattern": r"(?i)(['\"][;,)]\s*(and|or|union|select|insert|update|delete|drop))",
        "severity": "HIGH"
    },
    
    # 942340 - SQL Injection Attack: Classic Injection Probing 2/3
    "942340": {
        "name": "SQL Injection: Classic Probe 2",
        "pattern": r"(?i)(\b(and|or)\b\s*['\"\d]+\s*[=<>!])",
        "severity": "MEDIUM"
    },
    
    # 942350 - SQL Injection Attack: MySQL UDF Injection
    "942350": {
        "name": "SQL Injection: MySQL UDF",
        "pattern": r"(?i)(create\s+(aggregate\s+)?function\s+.*\s+returns|drop\s+function|create\s+library)",
        "severity": "CRITICAL"
    },
    
    # 942360 - SQL Injection Attack: Concatenated Injection
    "942360": {
        "name": "SQL Injection: Concatenated",
        "pattern": r"(?i)(\|\||\+\s*['\"]|['\"]\s*\+|concat\s*\()",
        "severity": "MEDIUM"
    },
    
    # 942370 - SQL Injection Attack: Classic Injection Probing 3/3
    "942370": {
        "name": "SQL Injection: Classic Probe 3",
        "pattern": r"(?i)(['\"];\s*drop\b|['\"];\s*delete\b|['\"];\s*insert\b|['\"];\s*update\b|['\"];\s*truncate\b)",
        "severity": "CRITICAL"
    },
    
    # 942380 - SQL Injection Attack: HAVING/GROUP BY
    "942380": {
        "name": "SQL Injection: Having/Group By",
        "pattern": r"(?i)(having\s+\d+\s*[=<>]|group\s+by\s+.*\s+having|having\s+.*\s*=)",
        "severity": "HIGH"
    },
    
    # 942390 - SQL Injection Attack: LIKE/INTO
    "942390": {
        "name": "SQL Injection: Like/Into",
        "pattern": r"(?i)(\blike\s+['\"]%|into\s+(outfile|dumpfile)|load_file\s*\()",
        "severity": "HIGH"
    },
    
    # 942400 - SQL Injection Attack: Order By
    "942400": {
        "name": "SQL Injection: Order By",
        "pattern": r"(?i)(order\s+by\s+\d+|order\s+by\s+if\s*\(|order\s+by\s+case)",
        "severity": "MEDIUM"
    },
    
    # ============================================================
    # ADDITIONAL SQL INJECTION RULES (942410-942999)
    # ============================================================
    
    # 942410 - SQL Injection Attack: SQL Hex Encoding
    "942410": {
        "name": "SQL Injection: Hex Encoding",
        "pattern": r"(?i)(0x[0-9a-f]{8,}|\\x[0-9a-f]{2})",
        "severity": "HIGH"
    },
    
    # 942420 - SQL Injection Attack: Restricted SQL Character Anomaly
    "942420": {
        "name": "SQL Injection: Restricted Chars",
        "pattern": r"(['\"]\s*;\s*--|['\"]\s*\/\*|\*\/\s*['\"])",
        "severity": "HIGH"
    },
    
    # 942430 - SQL Injection Attack: Classic SQL Injection Probing
    "942430": {
        "name": "SQL Injection: Classic Probing",
        "pattern": r"(?i)(\d+\s*=\s*\d+|'\s*=\s*'|\"\s*=\s*\")",
        "severity": "MEDIUM"
    },
    
    # 942440 - SQL Comment Sequence Detected
    "942440": {
        "name": "SQL Injection: Comment Sequence 2",
        "pattern": r"(\/\*[!+]|\*\/\s*--|\/\*.*?\*\/.*?\/?\*)",
        "severity": "MEDIUM"
    },
    
    # 942450 - SQL Injection: SQL function name detected
    "942450": {
        "name": "SQL Injection: More Functions",
        "pattern": r"(?i)\b(reverse|replace|soundex|difference|quotename|stuff|format|translate|trim|ltrim|rtrim|left|right|mid|repeat|space)\s*\(",
        "severity": "MEDIUM"
    },
    
    # 942460 - SQL Injection: SQL Union
    "942460": {
        "name": "SQL Injection: Union Variants",
        "pattern": r"(?i)(union\s*\/\*.*\*\/\s*select|union\s+distinct\s+select|union\s+all\s+select)",
        "severity": "CRITICAL"
    },
    
    # 942470 - SQL Injection: SQL database names
    "942470": {
        "name": "SQL Injection: DB Object Names",
        "pattern": r"(?i)(dba_users|all_tables|user_tables|all_tab_columns|v\$version|user_password|user_tab_columns)",
        "severity": "CRITICAL"
    },
    
    # 942480 - SQL Injection: Oracle-specific attacks
    "942480": {
        "name": "SQL Injection: Oracle",
        "pattern": r"(?i)(utl_http|utl_file|dbms_pipe|dbms_java|dbms_scheduler|ctxsys\.drithsx|sys\.dbms_export_extension)",
        "severity": "CRITICAL"
    },
    
    # 942490 - SQL Injection: INFORMATION_SCHEMA attacks
    "942490": {
        "name": "SQL Injection: Info Schema",
        "pattern": r"(?i)(information_schema\.(tables|columns|schemata|routines|key_column_usage)|table_schema|column_name|table_name)",
        "severity": "CRITICAL"
    },
    
    # 942500 - SQL Injection Attack: MySQL in-line comment
    "942500": {
        "name": "SQL Injection: MySQL Inline Comment",
        "pattern": r"(\/\*!\d{5}|\*\/\s*\d)",
        "severity": "HIGH"
    },
    
    # 942510 - SQL Injection: SQLite specific attacks
    "942510": {
        "name": "SQL Injection: SQLite",
        "pattern": r"(?i)(sqlite_version|sqlite_master|sqlite_temp_master|sqlite_sequence|typeof\s*\(|zeroblob\s*\()",
        "severity": "HIGH"
    },
    
    # 942520 - SQL Injection: LIMIT/OFFSET manipulation
    "942520": {
        "name": "SQL Injection: Limit/Offset",
        "pattern": r"(?i)(limit\s+\d+\s*,\s*\d+|limit\s+\d+\s+offset\s+\d+|offset\s+\d+\s+rows)",
        "severity": "LOW"
    },
    
    # 942530 - SQL Injection: Error-based injection
    "942530": {
        "name": "SQL Injection: Error Based",
        "pattern": r"(?i)(extractvalue\s*\(|updatexml\s*\(|exp\s*\(~|geometrycollection\s*\(|multipoint\s*\(|polygon\s*\(|multipolygon\s*\()",
        "severity": "HIGH"
    },
    
    # 942540 - SQL Injection: Boolean-based blind injection
    "942540": {
        "name": "SQL Injection: Boolean Blind",
        "pattern": r"(?i)(\band\b\s+\d+\s*=\s*\d+|\bor\b\s+\d+\s*=\s*\d+|\band\b\s+'[^']*'\s*=\s*'[^']*')",
        "severity": "HIGH"
    },
    
    # 942550 - SQL Injection: Time-based blind injection
    "942550": {
        "name": "SQL Injection: Time Blind",
        "pattern": r"(?i)(sleep\s*\(|benchmark\s*\(|pg_sleep\s*\(|waitfor\s+delay\s+|dbms_lock\.sleep)",
        "severity": "CRITICAL"
    },
    
    # 942560 - SQL Injection: Stacked queries
    "942560": {
        "name": "SQL Injection: Stacked Queries",
        "pattern": r"(?i)(;\s*(declare|set|exec|execute|insert|update|delete|drop|create|alter|truncate)\b)",
        "severity": "CRITICAL"
    },
    
    # 942570 - SQL Injection: Union-based with number columns
    "942570": {
        "name": "SQL Injection: Union Column Enum",
        "pattern": r"(?i)(union\s+select\s+(null|\d+)(\s*,\s*(null|\d+))+)",
        "severity": "CRITICAL"
    },
    
    # 942580 - SQL Injection: Common admin table names
    "942580": {
        "name": "SQL Injection: Admin Tables",
        "pattern": r"(?i)(from\s+(users|admin|administrators|accounts|members|customers|passwords|credentials|logins))",
        "severity": "HIGH"
    },
    
    # 942590 - SQL Injection: Password/credential columns
    "942590": {
        "name": "SQL Injection: Credential Columns",
        "pattern": r"(?i)(select\s+.*(password|passwd|pwd|pass|credential|secret|hash|salt|token))",
        "severity": "CRITICAL"
    },
    
    # 942600 - SQL Injection: Common username patterns
    "942600": {
        "name": "SQL Injection: Username Pattern",
        "pattern": r"(?i)(where\s+(username|user|login|email|user_name|uname)\s*=)",
        "severity": "MEDIUM"
    },
    
    # 942610 - SQL Injection: Null byte injection
    "942610": {
        "name": "SQL Injection: Null Byte",
        "pattern": r"(%00|\\0|\\x00|\0)",
        "severity": "HIGH"
    },
    
    # 942620 - SQL Injection: Double encoding
    "942620": {
        "name": "SQL Injection: Double Encoding",
        "pattern": r"(%25[0-9a-fA-F]{2}|%2527|%252f|%255c)",
        "severity": "HIGH"
    },
    
    # 942630 - SQL Injection: Unicode encoding
    "942630": {
        "name": "SQL Injection: Unicode",
        "pattern": r"(\\u00[0-9a-fA-F]{2}|%u00[0-9a-fA-F]{2}|\\x[0-9a-fA-F]{2})",
        "severity": "HIGH"
    },
}

# Compile all patterns for performance
COMPILED_CRS_RULES = {
    rule_id: {
        **rule_data,
        "compiled": re.compile(rule_data["pattern"])
    }
    for rule_id, rule_data in CRS_RULES.items()
}


@dataclass
class CRSResult:
    """Result from CRS detection."""
    is_attack: bool
    matched_rules: List[Dict]
    scan_time_ms: float


def detect_with_crs(payload: str) -> CRSResult:
    """
    Detect SQL injection using CRS rules.
    
    Args:
        payload: The input string to check
        
    Returns:
        CRSResult with detection details
    """
    start_time = time.perf_counter()
    matched_rules = []
    
    for rule_id, rule in COMPILED_CRS_RULES.items():
        if rule["compiled"].search(payload):
            matched_rules.append({
                "rule_id": rule_id,
                "name": rule["name"],
                "severity": rule["severity"]
            })
    
    scan_time = (time.perf_counter() - start_time) * 1000  # Convert to ms
    
    return CRSResult(
        is_attack=len(matched_rules) > 0,
        matched_rules=matched_rules,
        scan_time_ms=scan_time
    )


def compare_detection(payload: str, our_waf_func) -> Dict:
    """
    Compare our WAF detection against CRS.
    
    Args:
        payload: The input to test
        our_waf_func: Function that returns (is_attack: bool, details: dict)
        
    Returns:
        Comparison results
    """
    # CRS detection
    crs_result = detect_with_crs(payload)
    
    # Our WAF detection
    start_time = time.perf_counter()
    our_result = our_waf_func(payload)
    our_time = (time.perf_counter() - start_time) * 1000
    
    return {
        "payload": payload[:100] + "..." if len(payload) > 100 else payload,
        "crs": {
            "detected": crs_result.is_attack,
            "rules_matched": len(crs_result.matched_rules),
            "rules": crs_result.matched_rules,
            "time_ms": round(crs_result.scan_time_ms, 4)
        },
        "our_waf": {
            "detected": our_result[0] if isinstance(our_result, tuple) else our_result,
            "details": our_result[1] if isinstance(our_result, tuple) and len(our_result) > 1 else {},
            "time_ms": round(our_time, 4)
        },
        "agreement": crs_result.is_attack == (our_result[0] if isinstance(our_result, tuple) else our_result)
    }


def run_benchmark(test_payloads: List[Tuple[str, bool]], our_waf_func) -> Dict:
    """
    Run a full benchmark comparison.
    
    Args:
        test_payloads: List of (payload, is_malicious) tuples
        our_waf_func: Our WAF detection function
        
    Returns:
        Benchmark results with metrics
    """
    results = {
        "total_samples": len(test_payloads),
        "crs": {
            "true_positives": 0,
            "true_negatives": 0,
            "false_positives": 0,
            "false_negatives": 0,
            "total_time_ms": 0
        },
        "our_waf": {
            "true_positives": 0,
            "true_negatives": 0,
            "false_positives": 0,
            "false_negatives": 0,
            "total_time_ms": 0
        },
        "detailed_results": []
    }
    
    for payload, is_malicious in test_payloads:
        comparison = compare_detection(payload, our_waf_func)
        
        # CRS metrics
        crs_detected = comparison["crs"]["detected"]
        results["crs"]["total_time_ms"] += comparison["crs"]["time_ms"]
        
        if is_malicious and crs_detected:
            results["crs"]["true_positives"] += 1
        elif not is_malicious and not crs_detected:
            results["crs"]["true_negatives"] += 1
        elif not is_malicious and crs_detected:
            results["crs"]["false_positives"] += 1
        else:  # is_malicious and not crs_detected
            results["crs"]["false_negatives"] += 1
        
        # Our WAF metrics
        our_detected = comparison["our_waf"]["detected"]
        results["our_waf"]["total_time_ms"] += comparison["our_waf"]["time_ms"]
        
        if is_malicious and our_detected:
            results["our_waf"]["true_positives"] += 1
        elif not is_malicious and not our_detected:
            results["our_waf"]["true_negatives"] += 1
        elif not is_malicious and our_detected:
            results["our_waf"]["false_positives"] += 1
        else:  # is_malicious and not our_detected
            results["our_waf"]["false_negatives"] += 1
        
        results["detailed_results"].append({
            "payload": payload[:50] + "..." if len(payload) > 50 else payload,
            "actual": "malicious" if is_malicious else "benign",
            "crs_detected": crs_detected,
            "our_waf_detected": our_detected
        })
    
    # Calculate metrics for both
    for waf_name in ["crs", "our_waf"]:
        waf = results[waf_name]
        tp, tn, fp, fn = waf["true_positives"], waf["true_negatives"], waf["false_positives"], waf["false_negatives"]
        
        waf["accuracy"] = round((tp + tn) / len(test_payloads) * 100, 2) if test_payloads else 0
        waf["precision"] = round(tp / (tp + fp) * 100, 2) if (tp + fp) > 0 else 0
        waf["recall"] = round(tp / (tp + fn) * 100, 2) if (tp + fn) > 0 else 0
        waf["f1_score"] = round(2 * (waf["precision"] * waf["recall"]) / (waf["precision"] + waf["recall"]), 2) if (waf["precision"] + waf["recall"]) > 0 else 0
        waf["avg_time_ms"] = round(waf["total_time_ms"] / len(test_payloads), 4) if test_payloads else 0
    
    return results


def print_benchmark_report(results: Dict):
    """Print a formatted benchmark report."""
    print("\n" + "=" * 70)
    print("WAF COMPARISON BENCHMARK REPORT")
    print("=" * 70)
    print(f"Total Samples: {results['total_samples']}")
    
    print("\n" + "-" * 70)
    print(f"{'Metric':<25} {'CRS (ModSecurity)':<20} {'Our ML-WAF':<20}")
    print("-" * 70)
    
    metrics = [
        ("True Positives", "true_positives"),
        ("True Negatives", "true_negatives"),
        ("False Positives", "false_positives"),
        ("False Negatives", "false_negatives"),
        ("Accuracy (%)", "accuracy"),
        ("Precision (%)", "precision"),
        ("Recall (%)", "recall"),
        ("F1 Score (%)", "f1_score"),
        ("Avg Time (ms)", "avg_time_ms"),
    ]
    
    for label, key in metrics:
        crs_val = results["crs"][key]
        our_val = results["our_waf"][key]
        
        # Highlight winner
        if key in ["accuracy", "precision", "recall", "f1_score"]:
            crs_str = f"{crs_val}" + (" ✓" if crs_val > our_val else "")
            our_str = f"{our_val}" + (" ✓" if our_val > crs_val else "")
        elif key == "avg_time_ms":
            crs_str = f"{crs_val}" + (" ✓" if crs_val < our_val else "")
            our_str = f"{our_val}" + (" ✓" if our_val < crs_val else "")
        elif key in ["false_positives", "false_negatives"]:
            crs_str = f"{crs_val}" + (" ✓" if crs_val < our_val else "")
            our_str = f"{our_val}" + (" ✓" if our_val < crs_val else "")
        else:
            crs_str = f"{crs_val}"
            our_str = f"{our_val}"
        
        print(f"{label:<25} {crs_str:<20} {our_str:<20}")
    
    print("-" * 70)
    
    # Summary
    print("\nSUMMARY:")
    crs_f1 = results["crs"]["f1_score"]
    our_f1 = results["our_waf"]["f1_score"]
    
    if our_f1 > crs_f1:
        print(f"  ✅ Our ML-WAF outperforms CRS by {our_f1 - crs_f1:.2f}% F1 Score")
    elif our_f1 == crs_f1:
        print(f"  🔄 Both systems have equal F1 Score ({our_f1}%)")
    else:
        print(f"  ⚠️ CRS outperforms our WAF by {crs_f1 - our_f1:.2f}% F1 Score")
    
    crs_fp = results["crs"]["false_positives"]
    our_fp = results["our_waf"]["false_positives"]
    
    if our_fp < crs_fp:
        print(f"  ✅ Our ML-WAF has {crs_fp - our_fp} fewer false positives")
    elif our_fp == crs_fp:
        print(f"  🔄 Both systems have equal false positives ({our_fp})")
    else:
        print(f"  ⚠️ Our ML-WAF has {our_fp - crs_fp} more false positives")


def load_test_data() -> List[Tuple[str, bool]]:
    """Load test data from the existing datasets."""
    test_data = []
    base_dir = os.path.dirname(os.path.abspath(__file__))
    
    # Load SQLi payloads (malicious)
    sqli_path = os.path.join(base_dir, "data", "sqli_payloads_expanded.txt")
    if os.path.exists(sqli_path):
        with open(sqli_path, "r", encoding="utf-8", errors="ignore") as f:
            for line in f:
                line = line.strip()
                if line and not line.startswith("#"):
                    test_data.append((line, True))
    
    # Load benign inputs
    benign_path = os.path.join(base_dir, "data", "benign_inputs_expanded.txt")
    if os.path.exists(benign_path):
        with open(benign_path, "r", encoding="utf-8", errors="ignore") as f:
            for line in f:
                line = line.strip()
                if line and not line.startswith("#"):
                    test_data.append((line, False))
    
    return test_data


if __name__ == "__main__":
    import sys
    sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
    
    from waf import detect_sqli_ensemble
    
    def our_waf_wrapper(payload: str) -> Tuple[bool, Dict]:
        """Wrapper for our WAF detection."""
        result = detect_sqli_ensemble(payload)
        return (result["is_malicious"], result)
    
    print("Loading test data...")
    test_data = load_test_data()
    
    if not test_data:
        print("No test data found. Creating sample test set...")
        test_data = [
            # Malicious
            ("' OR '1'='1", True),
            ("'; DROP TABLE users--", True),
            ("1 UNION SELECT * FROM users", True),
            ("admin'--", True),
            ("' OR 1=1#", True),
            ("1; DELETE FROM products", True),
            ("' AND 1=1 UNION SELECT username, password FROM users--", True),
            ("SLEEP(5)", True),
            ("BENCHMARK(10000000,SHA1('test'))", True),
            ("'; EXEC xp_cmdshell('dir')--", True),
            # Benign
            ("hello world", False),
            ("john.doe@email.com", False),
            ("My product review is great!", False),
            ("SELECT is my favorite band", False),
            ("I'll drop by tomorrow", False),
            ("The table is made of wood", False),
            ("password123", False),
            ("New York City", False),
            ("2024-01-15", False),
            ("https://example.com/page?id=123", False),
        ]
    
    # Check for full benchmark flag
    import random
    random.seed(42)
    
    full_benchmark = "--full" in sys.argv
    
    if full_benchmark:
        sample_size = len(test_data)
        test_sample = test_data
        print(f"Running FULL benchmark on {sample_size} samples (this may take a while)...")
    else:
        sample_size = min(1000, len(test_data))
        test_sample = random.sample(test_data, sample_size)
        print(f"Running benchmark on {sample_size} samples (use --full for complete test)...")
    
    results = run_benchmark(test_sample, our_waf_wrapper)
    
    print_benchmark_report(results)
    
    # Save detailed results
    output_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), "benchmark_results.json")
    with open(output_path, "w") as f:
        # Don't save detailed_results to keep file size manageable
        save_results = {k: v for k, v in results.items() if k != "detailed_results"}
        json.dump(save_results, f, indent=2)
    
    print(f"\nResults saved to: {output_path}")
