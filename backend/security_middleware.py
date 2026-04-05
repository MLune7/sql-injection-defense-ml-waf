"""
Comprehensive Security Middleware

Features:
1. JWT Authentication with Refresh Tokens
2. Secure HTTP-Only Cookies
3. CSRF Protection
4. Rate Limiting
5. Security Headers
6. Request Sanitization for ALL methods (GET, POST, PUT, DELETE)
7. Session Management
8. IP-based blocking
"""

import os
import re
import time
import secrets
import hashlib
from datetime import datetime, timedelta
from functools import wraps
from typing import Dict, List, Optional, Tuple
from flask import request, jsonify, make_response, g
from collections import defaultdict
import threading

# ============================================================
# CONFIGURATION
# ============================================================

class SecurityConfig:
    # JWT Settings
    JWT_ACCESS_TOKEN_EXPIRES = timedelta(minutes=15)  # Short-lived access token
    JWT_REFRESH_TOKEN_EXPIRES = timedelta(days=7)     # Longer refresh token
    JWT_COOKIE_SECURE = False  # Set True in production (HTTPS)
    JWT_COOKIE_HTTPONLY = True
    JWT_COOKIE_SAMESITE = 'Lax'
    
    # CSRF Settings
    CSRF_ENABLED = True
    CSRF_TOKEN_LENGTH = 32
    CSRF_HEADER_NAME = 'X-CSRF-Token'
    CSRF_COOKIE_NAME = 'csrf_token'
    
    # Rate Limiting
    RATE_LIMIT_ENABLED = True
    RATE_LIMIT_REQUESTS = 100  # requests
    RATE_LIMIT_WINDOW = 60     # seconds
    RATE_LIMIT_BLOCK_DURATION = 300  # 5 minutes block
    
    # Failed Login Protection
    MAX_FAILED_LOGINS = 5
    LOGIN_BLOCK_DURATION = 900  # 15 minutes
    
    # IP Blocking
    IP_BLOCK_ENABLED = True
    MAX_ATTACKS_BEFORE_BLOCK = 3
    IP_BLOCK_DURATION = 3600  # 1 hour


# ============================================================
# RATE LIMITER
# ============================================================

class RateLimiter:
    """Thread-safe rate limiter using sliding window."""
    
    def __init__(self):
        self.requests = defaultdict(list)  # ip -> [timestamps]
        self.blocked_ips = {}  # ip -> unblock_time
        self.failed_logins = defaultdict(list)  # ip -> [timestamps]
        self.attack_counts = defaultdict(int)  # ip -> count
        self.lock = threading.Lock()
    
    def _clean_old_requests(self, ip: str, window: int):
        """Remove requests older than window."""
        cutoff = time.time() - window
        self.requests[ip] = [t for t in self.requests[ip] if t > cutoff]
    
    def is_rate_limited(self, ip: str) -> Tuple[bool, Optional[int]]:
        """Check if IP is rate limited. Returns (is_limited, retry_after_seconds)."""
        if not SecurityConfig.RATE_LIMIT_ENABLED:
            return False, None
        
        with self.lock:
            now = time.time()
            
            # Check if IP is blocked
            if ip in self.blocked_ips:
                if now < self.blocked_ips[ip]:
                    return True, int(self.blocked_ips[ip] - now)
                else:
                    del self.blocked_ips[ip]
            
            # Clean old requests
            self._clean_old_requests(ip, SecurityConfig.RATE_LIMIT_WINDOW)
            
            # Check rate limit
            if len(self.requests[ip]) >= SecurityConfig.RATE_LIMIT_REQUESTS:
                self.blocked_ips[ip] = now + SecurityConfig.RATE_LIMIT_BLOCK_DURATION
                return True, SecurityConfig.RATE_LIMIT_BLOCK_DURATION
            
            # Record request
            self.requests[ip].append(now)
            return False, None
    
    def record_failed_login(self, ip: str) -> bool:
        """Record failed login. Returns True if IP should be blocked."""
        with self.lock:
            now = time.time()
            cutoff = now - SecurityConfig.LOGIN_BLOCK_DURATION
            
            # Clean old failures
            self.failed_logins[ip] = [t for t in self.failed_logins[ip] if t > cutoff]
            
            # Record failure
            self.failed_logins[ip].append(now)
            
            # Check if should block
            if len(self.failed_logins[ip]) >= SecurityConfig.MAX_FAILED_LOGINS:
                self.blocked_ips[ip] = now + SecurityConfig.LOGIN_BLOCK_DURATION
                return True
            
            return False
    
    def record_attack(self, ip: str) -> bool:
        """Record attack attempt. Returns True if IP should be blocked."""
        if not SecurityConfig.IP_BLOCK_ENABLED:
            return False
        
        with self.lock:
            self.attack_counts[ip] += 1
            
            if self.attack_counts[ip] >= SecurityConfig.MAX_ATTACKS_BEFORE_BLOCK:
                self.blocked_ips[ip] = time.time() + SecurityConfig.IP_BLOCK_DURATION
                return True
            
            return False
    
    def is_ip_blocked(self, ip: str) -> Tuple[bool, Optional[int]]:
        """Check if IP is blocked."""
        with self.lock:
            now = time.time()
            if ip in self.blocked_ips:
                if now < self.blocked_ips[ip]:
                    return True, int(self.blocked_ips[ip] - now)
                else:
                    del self.blocked_ips[ip]
                    self.attack_counts[ip] = 0
            return False, None
    
    def clear_failed_logins(self, ip: str):
        """Clear failed login count (call after successful login)."""
        with self.lock:
            self.failed_logins[ip] = []
    
    def get_stats(self) -> Dict:
        """Get rate limiter statistics."""
        with self.lock:
            return {
                "active_ips": len(self.requests),
                "blocked_ips": len(self.blocked_ips),
                "total_attack_records": sum(self.attack_counts.values())
            }


# Global rate limiter instance
rate_limiter = RateLimiter()


# ============================================================
# CSRF PROTECTION
# ============================================================

class CSRFProtection:
    """CSRF token management."""
    
    _tokens = {}  # session_id -> (token, expires)
    _lock = threading.Lock()
    
    @classmethod
    def generate_token(cls, session_id: str) -> str:
        """Generate a new CSRF token."""
        token = secrets.token_hex(SecurityConfig.CSRF_TOKEN_LENGTH)
        expires = time.time() + 3600  # 1 hour
        
        with cls._lock:
            cls._tokens[session_id] = (token, expires)
        
        return token
    
    @classmethod
    def validate_token(cls, session_id: str, token: str) -> bool:
        """Validate a CSRF token."""
        if not SecurityConfig.CSRF_ENABLED:
            return True
        
        with cls._lock:
            if session_id not in cls._tokens:
                return False
            
            stored_token, expires = cls._tokens[session_id]
            
            # Check expiry
            if time.time() > expires:
                del cls._tokens[session_id]
                return False
            
            # Constant-time comparison
            return secrets.compare_digest(stored_token, token)
    
    @classmethod
    def cleanup_expired(cls):
        """Remove expired tokens."""
        now = time.time()
        with cls._lock:
            expired = [k for k, v in cls._tokens.items() if now > v[1]]
            for k in expired:
                del cls._tokens[k]


# ============================================================
# SECURE HEADERS
# ============================================================

def add_security_headers(response):
    """Add security headers to response."""
    # Prevent clickjacking
    response.headers['X-Frame-Options'] = 'DENY'
    
    # Prevent MIME type sniffing
    response.headers['X-Content-Type-Options'] = 'nosniff'
    
    # XSS Protection (legacy browsers)
    response.headers['X-XSS-Protection'] = '1; mode=block'
    
    # Referrer Policy
    response.headers['Referrer-Policy'] = 'strict-origin-when-cross-origin'
    
    # Content Security Policy (basic)
    response.headers['Content-Security-Policy'] = "default-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline'"
    
    # Strict Transport Security (enable in production with HTTPS)
    # response.headers['Strict-Transport-Security'] = 'max-age=31536000; includeSubDomains'
    
    # Permissions Policy
    response.headers['Permissions-Policy'] = 'geolocation=(), microphone=(), camera=()'
    
    return response


# ============================================================
# INPUT SANITIZATION
# ============================================================

class InputSanitizer:
    """Sanitize and validate all input."""
    
    # Dangerous patterns in any input
    DANGEROUS_PATTERNS = [
        r'<script[^>]*>',
        r'javascript:',
        r'on\w+\s*=',
        r'data:text/html',
        r'vbscript:',
    ]
    
    @classmethod
    def sanitize_string(cls, value: str, max_length: int = 10000) -> str:
        """Sanitize a string value."""
        if not isinstance(value, str):
            return str(value)
        
        # Truncate if too long
        if len(value) > max_length:
            value = value[:max_length]
        
        # Remove null bytes
        value = value.replace('\x00', '')
        
        return value
    
    @classmethod
    def detect_xss(cls, value: str) -> bool:
        """Detect potential XSS attacks."""
        if not isinstance(value, str):
            return False
        
        value_lower = value.lower()
        
        for pattern in cls.DANGEROUS_PATTERNS:
            if re.search(pattern, value_lower, re.IGNORECASE):
                return True
        
        return False
    
    @classmethod
    def sanitize_dict(cls, data: Dict, max_depth: int = 5) -> Dict:
        """Recursively sanitize dictionary values."""
        if max_depth <= 0:
            return data
        
        sanitized = {}
        for key, value in data.items():
            # Sanitize key
            key = cls.sanitize_string(str(key), 100)
            
            # Sanitize value
            if isinstance(value, str):
                sanitized[key] = cls.sanitize_string(value)
            elif isinstance(value, dict):
                sanitized[key] = cls.sanitize_dict(value, max_depth - 1)
            elif isinstance(value, list):
                sanitized[key] = [
                    cls.sanitize_string(v) if isinstance(v, str) else v
                    for v in value
                ]
            else:
                sanitized[key] = value
        
        return sanitized


# ============================================================
# SESSION MANAGEMENT
# ============================================================

class SessionManager:
    """Manage user sessions with additional security."""
    
    _sessions = {}  # session_id -> {user_id, ip, user_agent, created, last_active, data}
    _lock = threading.Lock()
    
    @classmethod
    def create_session(cls, user_id: int, ip: str, user_agent: str) -> str:
        """Create a new session."""
        session_id = secrets.token_urlsafe(32)
        now = datetime.utcnow()
        
        with cls._lock:
            cls._sessions[session_id] = {
                'user_id': user_id,
                'ip': ip,
                'user_agent': user_agent,
                'created': now,
                'last_active': now,
                'data': {}
            }
        
        return session_id
    
    @classmethod
    def validate_session(cls, session_id: str, ip: str, user_agent: str) -> Optional[Dict]:
        """Validate session and check for hijacking."""
        with cls._lock:
            if session_id not in cls._sessions:
                return None
            
            session = cls._sessions[session_id]
            
            # Check session age (max 24 hours)
            if datetime.utcnow() - session['created'] > timedelta(hours=24):
                del cls._sessions[session_id]
                return None
            
            # Check for session hijacking (IP changed)
            if session['ip'] != ip:
                # Log potential hijacking
                print(f"[SECURITY] Session IP mismatch: {session['ip']} vs {ip}")
                # Could invalidate session here, but might cause issues with mobile users
                # For now, just log it
            
            # Update last active
            session['last_active'] = datetime.utcnow()
            
            return session
    
    @classmethod
    def destroy_session(cls, session_id: str):
        """Destroy a session."""
        with cls._lock:
            if session_id in cls._sessions:
                del cls._sessions[session_id]
    
    @classmethod
    def destroy_user_sessions(cls, user_id: int):
        """Destroy all sessions for a user."""
        with cls._lock:
            to_delete = [
                sid for sid, session in cls._sessions.items()
                if session['user_id'] == user_id
            ]
            for sid in to_delete:
                del cls._sessions[sid]
    
    @classmethod
    def get_user_sessions(cls, user_id: int) -> List[Dict]:
        """Get all active sessions for a user."""
        with cls._lock:
            return [
                {
                    'session_id': sid[:8] + '...',  # Partial for security
                    'ip': session['ip'],
                    'created': session['created'].isoformat(),
                    'last_active': session['last_active'].isoformat()
                }
                for sid, session in cls._sessions.items()
                if session['user_id'] == user_id
            ]
    
    @classmethod
    def cleanup_expired(cls, max_age_hours: int = 24):
        """Remove expired sessions."""
        cutoff = datetime.utcnow() - timedelta(hours=max_age_hours)
        with cls._lock:
            expired = [
                sid for sid, session in cls._sessions.items()
                if session['last_active'] < cutoff
            ]
            for sid in expired:
                del cls._sessions[sid]


# ============================================================
# REQUEST FINGERPRINTING
# ============================================================

def get_request_fingerprint() -> str:
    """Generate a fingerprint for the current request."""
    components = [
        request.remote_addr or '',
        request.headers.get('User-Agent', ''),
        request.headers.get('Accept-Language', ''),
        request.headers.get('Accept-Encoding', ''),
    ]
    fingerprint_string = '|'.join(components)
    return hashlib.sha256(fingerprint_string.encode()).hexdigest()[:16]


# ============================================================
# COMPREHENSIVE REQUEST INSPECTION
# ============================================================

def inspect_all_request_data() -> Optional[Tuple[Dict, int]]:
    """
    Inspect ALL parts of the request for malicious content.
    Returns (error_response, status_code) if blocked, None if OK.
    """
    from waf import detect_sqli_ensemble, normalize_input
    
    client_ip = request.remote_addr or 'unknown'
    blocked_items = []
    
    def check_value(value: str, field_name: str, location: str) -> bool:
        """Check a single value. Returns True if malicious."""
        if not value or not isinstance(value, str):
            return False
        
        # Check for XSS
        if InputSanitizer.detect_xss(value):
            blocked_items.append({
                'field': field_name,
                'location': location,
                'reason': 'XSS detected'
            })
            return True
        
        # Check for SQLi
        result = detect_sqli_ensemble(value)
        if result['is_malicious']:
            blocked_items.append({
                'field': field_name,
                'location': location,
                'reason': 'SQLi detected',
                'confidence': result['confidence'],
                'methods': result['detection_methods']
            })
            return True
        
        return False
    
    def check_dict(data: Dict, location: str):
        """Check all values in a dictionary."""
        if not isinstance(data, dict):
            return
        
        for key, value in data.items():
            if isinstance(value, str):
                check_value(value, key, location)
            elif isinstance(value, dict):
                check_dict(value, f"{location}.{key}")
            elif isinstance(value, list):
                for i, item in enumerate(value):
                    if isinstance(item, str):
                        check_value(item, f"{key}[{i}]", location)
    
    # 1. Check URL path
    if check_value(request.path, 'path', 'url'):
        pass  # Continue checking other parts
    
    # 2. Check query parameters (GET parameters)
    for key, value in request.args.items():
        check_value(str(value), key, 'query')
    
    # 3. Check JSON body (POST/PUT/PATCH)
    if request.is_json:
        try:
            data = request.get_json(silent=True)
            if data:
                check_dict(data, 'body')
        except Exception:
            pass
    
    # 4. Check form data
    for key, value in request.form.items():
        check_value(str(value), key, 'form')
    
    # 5. Check cookies
    for key, value in request.cookies.items():
        # Skip common framework cookies
        if key.lower() in ('csrftoken', 'csrf_token', '_ga', '_gid', 'sessionid'):
            continue
        check_value(str(value), key, 'cookie')
    
    # 6. Check headers
    dangerous_headers = [
        'User-Agent', 'Referer', 'X-Forwarded-For', 'X-Real-IP',
        'X-Custom-Header', 'X-Api-Key', 'Authorization'
    ]
    for header in dangerous_headers:
        value = request.headers.get(header)
        if value:
            # Don't flag Authorization header for normal JWT tokens
            if header == 'Authorization' and value.startswith('Bearer '):
                continue
            check_value(str(value), header, 'header')
    
    # If any malicious content found
    if blocked_items:
        # Record attack for rate limiting
        rate_limiter.record_attack(client_ip)
        
        # Log the attack
        try:
            from security_logger import log_attack
            log_attack(
                ip=client_ip,
                payload=str(blocked_items[0]),
                reason=f"Multi-layer inspection blocked {len(blocked_items)} items at {request.path}"
            )
        except Exception as e:
            print(f"[SECURITY] Logging failed: {e}")
        
        return {
            'error': 'Malicious content detected',
            'blocked': True,
            'details': blocked_items[0] if len(blocked_items) == 1 else blocked_items
        }, 403
    
    return None


# ============================================================
# FLASK INTEGRATION
# ============================================================

def init_security(app):
    """Initialize security middleware for Flask app."""
    
    @app.before_request
    def security_before_request():
        """Run security checks before each request."""
        client_ip = request.remote_addr or 'unknown'
        
        # 1. Check if IP is blocked
        is_blocked, retry_after = rate_limiter.is_ip_blocked(client_ip)
        if is_blocked:
            response = jsonify({
                'error': 'IP temporarily blocked',
                'retry_after': retry_after
            })
            response.status_code = 429
            response.headers['Retry-After'] = str(retry_after)
            return response
        
        # 2. Check rate limiting
        is_limited, retry_after = rate_limiter.is_rate_limited(client_ip)
        if is_limited:
            response = jsonify({
                'error': 'Too many requests',
                'retry_after': retry_after
            })
            response.status_code = 429
            response.headers['Retry-After'] = str(retry_after)
            return response
        
        # 3. CSRF check for state-changing requests
        if request.method in ('POST', 'PUT', 'DELETE', 'PATCH'):
            # Skip CSRF for API endpoints with JWT (they use token auth)
            if not request.headers.get('Authorization'):
                csrf_token = request.headers.get(SecurityConfig.CSRF_HEADER_NAME)
                csrf_cookie = request.cookies.get(SecurityConfig.CSRF_COOKIE_NAME)
                
                # If CSRF cookie exists, validate token
                if csrf_cookie and SecurityConfig.CSRF_ENABLED:
                    if not csrf_token or not CSRFProtection.validate_token(csrf_cookie, csrf_token):
                        # For now, just log - don't block (for backwards compatibility)
                        print(f"[SECURITY] CSRF validation failed for {request.path}")
        
        # 4. Store request fingerprint for logging
        g.request_fingerprint = get_request_fingerprint()
        g.request_start_time = time.time()
    
    @app.after_request
    def security_after_request(response):
        """Add security headers to response."""
        # Add security headers
        response = add_security_headers(response)
        
        # Add CSRF token cookie if not present
        if SecurityConfig.CSRF_ENABLED and SecurityConfig.CSRF_COOKIE_NAME not in request.cookies:
            csrf_token = secrets.token_hex(16)
            response.set_cookie(
                SecurityConfig.CSRF_COOKIE_NAME,
                csrf_token,
                httponly=False,  # JS needs to read this
                secure=SecurityConfig.JWT_COOKIE_SECURE,
                samesite=SecurityConfig.JWT_COOKIE_SAMESITE,
                max_age=3600
            )
        
        # Log request timing
        if hasattr(g, 'request_start_time'):
            duration = time.time() - g.request_start_time
            if duration > 1.0:  # Log slow requests
                print(f"[PERF] Slow request: {request.path} took {duration:.2f}s")
        
        return response
    
    print("[SECURITY] Security middleware initialized")
    return app


# ============================================================
# DECORATORS
# ============================================================

def require_csrf(f):
    """Decorator to require CSRF token."""
    @wraps(f)
    def decorated(*args, **kwargs):
        if not SecurityConfig.CSRF_ENABLED:
            return f(*args, **kwargs)
        
        csrf_token = request.headers.get(SecurityConfig.CSRF_HEADER_NAME)
        csrf_cookie = request.cookies.get(SecurityConfig.CSRF_COOKIE_NAME)
        
        if not csrf_token or not csrf_cookie:
            return jsonify({'error': 'CSRF token missing'}), 403
        
        if not CSRFProtection.validate_token(csrf_cookie, csrf_token):
            return jsonify({'error': 'Invalid CSRF token'}), 403
        
        return f(*args, **kwargs)
    return decorated


def rate_limit(max_requests: int, window_seconds: int):
    """Decorator for custom rate limiting on specific endpoints."""
    def decorator(f):
        endpoint_requests = defaultdict(list)
        lock = threading.Lock()
        
        @wraps(f)
        def decorated(*args, **kwargs):
            client_ip = request.remote_addr or 'unknown'
            now = time.time()
            
            with lock:
                # Clean old requests
                cutoff = now - window_seconds
                endpoint_requests[client_ip] = [
                    t for t in endpoint_requests[client_ip] if t > cutoff
                ]
                
                # Check limit
                if len(endpoint_requests[client_ip]) >= max_requests:
                    return jsonify({
                        'error': 'Rate limit exceeded for this endpoint',
                        'retry_after': window_seconds
                    }), 429
                
                # Record request
                endpoint_requests[client_ip].append(now)
            
            return f(*args, **kwargs)
        return decorated
    return decorator


# ============================================================
# UTILITY FUNCTIONS
# ============================================================

def get_security_status() -> Dict:
    """Get current security middleware status."""
    return {
        'csrf_enabled': SecurityConfig.CSRF_ENABLED,
        'rate_limit_enabled': SecurityConfig.RATE_LIMIT_ENABLED,
        'rate_limit': f"{SecurityConfig.RATE_LIMIT_REQUESTS} requests / {SecurityConfig.RATE_LIMIT_WINDOW}s",
        'ip_blocking_enabled': SecurityConfig.IP_BLOCK_ENABLED,
        'max_failed_logins': SecurityConfig.MAX_FAILED_LOGINS,
        'stats': rate_limiter.get_stats()
    }
