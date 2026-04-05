#!/usr/bin/env python3
"""
Test WAF for bypasses and vulnerabilities.
Run this to verify the WAF blocks all attack vectors.
"""
import requests
import json

BASE_URL = "http://localhost:5000"
SQLI_PAYLOAD = "' OR '1'='1"
SQLI_PAYLOAD_ENCODED = "%27%20OR%20%271%27%3D%271"

def test_query_param_injection():
    """Test: Query parameters are inspected"""
    print("\n[TEST] Query Parameter Injection")
    try:
        r = requests.get(f"{BASE_URL}/api/products?id={SQLI_PAYLOAD}")
        if r.status_code == 403:
            print("  ✅ BLOCKED - Query param injection detected")
            return True
        else:
            print(f"  ❌ BYPASS - Status {r.status_code}")
            return False
    except Exception as e:
        print(f"  ⚠️ ERROR: {e}")
        return None

def test_safe_path_query_injection():
    """Test: Even safe paths check query parameters"""
    print("\n[TEST] Safe Path Query Injection")
    try:
        # Static paths might be considered "safe" but query params should still be checked
        r = requests.get(f"{BASE_URL}/api/products?search={SQLI_PAYLOAD}")
        if r.status_code == 403:
            print("  ✅ BLOCKED - Safe path query param injection detected")
            return True
        else:
            print(f"  ⚠️ Status {r.status_code} - Check if this path is protected")
            return False
    except Exception as e:
        print(f"  ⚠️ ERROR: {e}")
        return None

def test_json_body_injection():
    """Test: JSON body is inspected"""
    print("\n[TEST] JSON Body Injection")
    try:
        r = requests.post(
            f"{BASE_URL}/api/search",
            json={"query": SQLI_PAYLOAD},
            headers={"Content-Type": "application/json"}
        )
        if r.status_code == 403:
            print("  ✅ BLOCKED - JSON body injection detected")
            return True
        else:
            print(f"  ❌ BYPASS - Status {r.status_code}")
            return False
    except Exception as e:
        print(f"  ⚠️ ERROR: {e}")
        return None

def test_form_data_injection():
    """Test: Form data (application/x-www-form-urlencoded) is inspected"""
    print("\n[TEST] Form Data Injection")
    try:
        r = requests.post(
            f"{BASE_URL}/api/search",
            data={"query": SQLI_PAYLOAD},
            headers={"Content-Type": "application/x-www-form-urlencoded"}
        )
        if r.status_code == 403:
            print("  ✅ BLOCKED - Form data injection detected")
            return True
        else:
            print(f"  ❌ BYPASS - Status {r.status_code}")
            return False
    except Exception as e:
        print(f"  ⚠️ ERROR: {e}")
        return None

def test_nested_json_injection():
    """Test: Nested JSON structures are inspected"""
    print("\n[TEST] Nested JSON Injection")
    try:
        r = requests.post(
            f"{BASE_URL}/api/search",
            json={
                "filters": {
                    "category": {
                        "name": SQLI_PAYLOAD
                    }
                }
            },
            headers={"Content-Type": "application/json"}
        )
        if r.status_code == 403:
            print("  ✅ BLOCKED - Nested JSON injection detected")
            return True
        else:
            print(f"  ❌ BYPASS - Status {r.status_code}")
            return False
    except Exception as e:
        print(f"  ⚠️ ERROR: {e}")
        return None

def test_array_injection():
    """Test: Array elements are inspected"""
    print("\n[TEST] Array Element Injection")
    try:
        r = requests.post(
            f"{BASE_URL}/api/search",
            json={
                "items": ["safe", "also safe", SQLI_PAYLOAD]
            },
            headers={"Content-Type": "application/json"}
        )
        if r.status_code == 403:
            print("  ✅ BLOCKED - Array injection detected")
            return True
        else:
            print(f"  ❌ BYPASS - Status {r.status_code}")
            return False
    except Exception as e:
        print(f"  ⚠️ ERROR: {e}")
        return None

def test_deeply_nested_array():
    """Test: Deeply nested arrays are inspected"""
    print("\n[TEST] Deeply Nested Array Injection")
    try:
        r = requests.post(
            f"{BASE_URL}/api/search",
            json={
                "data": {
                    "users": [
                        {"name": "john"},
                        {"name": SQLI_PAYLOAD}
                    ]
                }
            },
            headers={"Content-Type": "application/json"}
        )
        if r.status_code == 403:
            print("  ✅ BLOCKED - Deeply nested array injection detected")
            return True
        else:
            print(f"  ❌ BYPASS - Status {r.status_code}")
            return False
    except Exception as e:
        print(f"  ⚠️ ERROR: {e}")
        return None

def test_raw_text_body():
    """Test: Raw text body (text/plain) is inspected"""
    print("\n[TEST] Raw Text Body Injection")
    try:
        r = requests.post(
            f"{BASE_URL}/api/search",
            data=SQLI_PAYLOAD,
            headers={"Content-Type": "text/plain"}
        )
        if r.status_code == 403:
            print("  ✅ BLOCKED - Raw text body injection detected")
            return True
        else:
            print(f"  ❌ BYPASS - Status {r.status_code}")
            return False
    except Exception as e:
        print(f"  ⚠️ ERROR: {e}")
        return None

def test_xml_body():
    """Test: XML body (application/xml) is inspected"""
    print("\n[TEST] XML Body Injection")
    try:
        xml_payload = f"<query>{SQLI_PAYLOAD}</query>"
        r = requests.post(
            f"{BASE_URL}/api/search",
            data=xml_payload,
            headers={"Content-Type": "application/xml"}
        )
        if r.status_code == 403:
            print("  ✅ BLOCKED - XML body injection detected")
            return True
        else:
            print(f"  ❌ BYPASS - Status {r.status_code}")
            return False
    except Exception as e:
        print(f"  ⚠️ ERROR: {e}")
        return None

def test_file_upload_filename():
    """Test: File upload filenames are inspected"""
    print("\n[TEST] File Upload Filename Injection")
    try:
        files = {
            'file': (f"{SQLI_PAYLOAD}.txt", b"file content", 'text/plain')
        }
        r = requests.post(f"{BASE_URL}/api/search", files=files)
        if r.status_code == 403:
            print("  ✅ BLOCKED - File upload filename injection detected")
            return True
        else:
            print(f"  ❌ BYPASS - Status {r.status_code}")
            return False
    except Exception as e:
        print(f"  ⚠️ ERROR: {e}")
        return None

def test_header_injection():
    """Test: Headers are inspected"""
    print("\n[TEST] Header Injection")
    try:
        r = requests.get(
            f"{BASE_URL}/api/products",
            headers={"X-Custom-Header": SQLI_PAYLOAD}
        )
        if r.status_code == 403:
            print("  ✅ BLOCKED - Header injection detected")
            return True
        else:
            print(f"  ❌ BYPASS - Status {r.status_code}")
            return False
    except Exception as e:
        print(f"  ⚠️ ERROR: {e}")
        return None

def test_cookie_injection():
    """Test: Cookies are inspected"""
    print("\n[TEST] Cookie Injection")
    try:
        r = requests.get(
            f"{BASE_URL}/api/products",
            cookies={"session": SQLI_PAYLOAD}
        )
        if r.status_code == 403:
            print("  ✅ BLOCKED - Cookie injection detected")
            return True
        else:
            print(f"  ❌ BYPASS - Status {r.status_code}")
            return False
    except Exception as e:
        print(f"  ⚠️ ERROR: {e}")
        return None

def test_url_encoded_attack():
    """Test: URL-encoded attacks are detected"""
    print("\n[TEST] URL-Encoded Attack")
    try:
        r = requests.get(f"{BASE_URL}/api/products?id={SQLI_PAYLOAD_ENCODED}")
        if r.status_code == 403:
            print("  ✅ BLOCKED - URL-encoded attack detected")
            return True
        else:
            print(f"  ❌ BYPASS - Status {r.status_code}")
            return False
    except Exception as e:
        print(f"  ⚠️ ERROR: {e}")
        return None

def test_benign_request():
    """Test: Normal requests are allowed"""
    print("\n[TEST] Benign Request (Should Pass)")
    try:
        r = requests.get(f"{BASE_URL}/api/products")
        if r.status_code == 200:
            print("  ✅ ALLOWED - Benign request passed")
            return True
        else:
            print(f"  ❌ BLOCKED - Status {r.status_code}")
            return False
    except Exception as e:
        print(f"  ⚠️ ERROR: {e}")
        return None

def main():
    print("=" * 60)
    print("WAF VULNERABILITY TEST SUITE")
    print("=" * 60)
    print(f"Target: {BASE_URL}")
    print("Testing all attack vectors...")

    tests = [
        test_benign_request,
        test_query_param_injection,
        test_safe_path_query_injection,
        test_json_body_injection,
        test_form_data_injection,
        test_nested_json_injection,
        test_array_injection,
        test_deeply_nested_array,
        test_raw_text_body,
        test_xml_body,
        test_file_upload_filename,
        test_header_injection,
        test_cookie_injection,
        test_url_encoded_attack,
    ]

    results = []
    for test in tests:
        result = test()
        results.append((test.__name__, result))

    print("\n" + "=" * 60)
    print("SUMMARY")
    print("=" * 60)

    passed = sum(1 for _, r in results if r is True)
    failed = sum(1 for _, r in results if r is False)
    errors = sum(1 for _, r in results if r is None)

    for name, result in results:
        status = "✅ PASS" if result is True else ("❌ FAIL" if result is False else "⚠️ ERROR")
        print(f"  {status}: {name}")

    print(f"\nTotal: {passed} passed, {failed} failed, {errors} errors")

    if failed > 0:
        print("\n⚠️  WARNING: Some attacks may bypass the WAF!")
    else:
        print("\n✅ All vulnerability tests passed!")

if __name__ == "__main__":
    main()
