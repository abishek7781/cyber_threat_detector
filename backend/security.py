from functools import wraps
from flask import request, jsonify
import time
from datetime import datetime, timedelta
import re
import hashlib
import hmac
import os
from typing import Dict, List, Optional

class SecurityMiddleware:
    def __init__(self):
        self.rate_limits: Dict[str, List[float]] = {}
        self.max_requests = 100  # requests per window
        self.window_size = 3600  # 1 hour in seconds
        self.api_keys: Dict[str, str] = {}
        self.load_api_keys()

    def load_api_keys(self):
        """Load API keys from environment variables"""
        for key in ['GOOGLE_SAFE_BROWSING_API_KEY', 'IPQUALITYSCORE_API_KEY', 
                   'ALIENVAULT_API_KEY', 'THREATFOX_API_KEY', 'TALOS_API_KEY']:
            value = os.getenv(key)
            if value:
                self.api_keys[key] = value

    def rate_limit(self, f):
        @wraps(f)
        def decorated_function(*args, **kwargs):
            ip = request.remote_addr
            current_time = time.time()
            
            # Clean old requests
            if ip in self.rate_limits:
                self.rate_limits[ip] = [t for t in self.rate_limits[ip] 
                                      if current_time - t < self.window_size]
            else:
                self.rate_limits[ip] = []
            
            # Check rate limit
            if len(self.rate_limits[ip]) >= self.max_requests:
                return jsonify({
                    'error': 'Rate limit exceeded',
                    'retry_after': int(self.window_size - (current_time - self.rate_limits[ip][0]))
                }), 429
            
            # Add current request
            self.rate_limits[ip].append(current_time)
            return f(*args, **kwargs)
        return decorated_function

    def validate_url(self, url: str) -> bool:
        """Validate URL format and content"""
        # Basic URL format validation
        if not re.match(r'^https?://[^\s/$.?#].[^\s]*$', url):
            return False
        
        # Check for common malicious patterns
        malicious_patterns = [
            r'\.exe$',
            r'\.zip$',
            r'\.rar$',
            r'\.php$',
            r'\.asp$',
            r'\.jsp$',
            r'\.sql$',
            r'\.bak$',
            r'\.backup$',
            r'\.old$',
            r'\.tmp$',
            r'\.temp$',
            r'\.log$',
            r'\.ini$',
            r'\.config$',
            r'\.conf$',
            r'\.xml$',
            r'\.json$',
            r'\.yaml$',
            r'\.yml$',
            r'\.env$',
            r'\.git$',
            r'\.svn$',
            r'\.htaccess$',
            r'\.htpasswd$',
            r'\.DS_Store$',
            r'\.idea$',
            r'\.vscode$',
            r'\.sublime-project$',
            r'\.sublime-workspace$',
            r'\.project$',
            r'\.classpath$',
            r'\.settings$',
            r'\.factorypath$',
            r'\.springBeans$',
            r'\.tomcat$',
            r'\.mvn$',
            r'\.gradle$',
            r'\.npm$',
            r'\.yarn$',
            r'\.bower$',
            r'\.jspm$',
            r'\.webpack$',
            r'\.rollup$',
            r'\.parcel$',
            r'\.browserlist$',
            r'\.babelrc$',
            r'\.eslintrc$',
            r'\.prettierrc$',
            r'\.stylelintrc$',
            r'\.postcssrc$',
            r'\.browserslist$',
            r'\.editorconfig$',
            r'\.gitignore$',
            r'\.npmignore$',
            r'\.dockerignore$'
        ]
        
        for pattern in malicious_patterns:
            if re.search(pattern, url, re.IGNORECASE):
                return False
        
        return True

    def validate_api_key(self, f):
        @wraps(f)
        def decorated_function(*args, **kwargs):
            api_key = request.headers.get('X-API-Key')
            if not api_key or api_key not in self.api_keys.values():
                return jsonify({'error': 'Invalid API key'}), 401
            return f(*args, **kwargs)
        return decorated_function

    def add_security_headers(self, response):
        """Add security headers to response"""
        response.headers['X-Content-Type-Options'] = 'nosniff'
        response.headers['X-Frame-Options'] = 'DENY'
        response.headers['X-XSS-Protection'] = '1; mode=block'
        response.headers['Strict-Transport-Security'] = 'max-age=31536000; includeSubDomains'
        response.headers['Content-Security-Policy'] = "default-src 'self'; script-src 'self' 'unsafe-inline' 'unsafe-eval'; style-src 'self' 'unsafe-inline';"
        response.headers['Referrer-Policy'] = 'strict-origin-when-cross-origin'
        response.headers['Permissions-Policy'] = 'geolocation=(), microphone=(), camera=()'
        return response

    def sanitize_input(self, data: str) -> str:
        """Sanitize user input"""
        # Remove potentially dangerous characters
        sanitized = re.sub(r'[<>]', '', data)
        # Escape special characters
        sanitized = sanitized.replace('&', '&amp;')
        sanitized = sanitized.replace('"', '&quot;')
        sanitized = sanitized.replace("'", '&#x27;')
        return sanitized

    def generate_request_signature(self, data: str, timestamp: str) -> str:
        """Generate HMAC signature for request validation"""
        secret = os.getenv('API_SECRET_KEY', 'your-secret-key')
        message = f"{data}:{timestamp}"
        return hmac.new(
            secret.encode(),
            message.encode(),
            hashlib.sha256
        ).hexdigest()

    def validate_request_signature(self, f):
        @wraps(f)
        def decorated_function(*args, **kwargs):
            signature = request.headers.get('X-Request-Signature')
            timestamp = request.headers.get('X-Request-Timestamp')
            
            if not signature or not timestamp:
                return jsonify({'error': 'Missing signature or timestamp'}), 400
            
            # Check if timestamp is within 5 minutes
            if abs(time.time() - float(timestamp)) > 300:
                return jsonify({'error': 'Request expired'}), 400
            
            # Generate expected signature
            expected_signature = self.generate_request_signature(
                request.get_data(as_text=True),
                timestamp
            )
            
            if not hmac.compare_digest(signature, expected_signature):
                return jsonify({'error': 'Invalid signature'}), 400
            
            return f(*args, **kwargs)
        return decorated_function

# Initialize security middleware
security = SecurityMiddleware() 