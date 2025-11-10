"""
Centralized OAuth Callback Relay Service for app.enkryptai.com

This is a minimal, secure service that hosts the OAuth callback page
and relays authorization codes to individual gateway instances.

Features:
- Serves secure OAuth callback HTML page
- Rate limiting by IP address
- Security headers (CSP, HSTS, etc.)
- Request logging for security auditing
- Health check endpoint
- Minimal attack surface

Deployment:
- Can be deployed on any cloud platform (Vercel, Cloudflare Pages, AWS, etc.)
- Requires HTTPS (enforced)
- No database required (stateless)
- Horizontal scaling supported
"""

import os
import time
from collections import defaultdict
from datetime import datetime
from pathlib import Path
from typing import Dict

from flask import Flask, Response, request, send_from_directory
from flask_cors import CORS

# Configuration
RATE_LIMIT_REQUESTS = 10  # Max requests per window
RATE_LIMIT_WINDOW = 60  # Window in seconds
MAX_LOG_SIZE = 1000  # Max security log entries to keep

# Initialize Flask app
app = Flask(__name__)

# Enable CORS for all origins (callback needs to POST to any gateway)
CORS(app, resources={
    r"/*": {
        "origins": "*",
        "methods": ["GET", "POST", "OPTIONS"],
        "allow_headers": ["Content-Type", "X-OAuth-Relay", "X-Request-ID"],
    }
})

# In-memory rate limiting storage
# Key: IP address, Value: list of request timestamps
_rate_limit_store: Dict[str, list] = defaultdict(list)

# Security audit log (in-memory, limited size)
_security_log = []


def get_client_ip() -> str:
    """
    Get client IP address with support for proxies.

    Checks headers in order:
    1. X-Forwarded-For (first IP if multiple)
    2. X-Real-IP
    3. Direct connection IP

    Returns:
        Client IP address
    """
    # Check X-Forwarded-For (proxies)
    if 'X-Forwarded-For' in request.headers:
        # Get first IP if multiple (client IP)
        return request.headers['X-Forwarded-For'].split(',')[0].strip()

    # Check X-Real-IP (nginx)
    if 'X-Real-IP' in request.headers:
        return request.headers['X-Real-IP']

    # Direct connection
    return request.remote_addr or 'unknown'


def check_rate_limit(ip: str) -> tuple[bool, int]:
    """
    Check if IP address is within rate limit.

    Args:
        ip: Client IP address

    Returns:
        Tuple of (is_allowed, requests_remaining)
    """
    current_time = time.time()
    window_start = current_time - RATE_LIMIT_WINDOW

    # Clean up old requests outside window
    _rate_limit_store[ip] = [
        timestamp for timestamp in _rate_limit_store[ip]
        if timestamp > window_start
    ]

    # Check if within limit
    request_count = len(_rate_limit_store[ip])

    if request_count >= RATE_LIMIT_REQUESTS:
        return False, 0

    # Add current request
    _rate_limit_store[ip].append(current_time)

    return True, RATE_LIMIT_REQUESTS - request_count - 1


def log_security_event(event_type: str, ip: str, details: dict):
    """
    Log security event for auditing.

    Args:
        event_type: Type of event (e.g., "rate_limit", "callback", "error")
        ip: Client IP address
        details: Event details
    """
    event = {
        "timestamp": datetime.utcnow().isoformat(),
        "type": event_type,
        "ip": ip,
        "details": details
    }

    _security_log.append(event)

    # Limit log size
    if len(_security_log) > MAX_LOG_SIZE:
        _security_log.pop(0)

    # Also log to stdout for container logging
    print(f"[SECURITY] {event_type} from {ip}: {details}")


def add_security_headers(response: Response) -> Response:
    """
    Add security headers to response.

    Headers:
    - Strict-Transport-Security (HSTS)
    - Content-Security-Policy (CSP)
    - X-Content-Type-Options
    - X-Frame-Options
    - X-XSS-Protection
    - Referrer-Policy

    Args:
        response: Flask response object

    Returns:
        Response with security headers
    """
    # HSTS: Force HTTPS for 1 year
    response.headers['Strict-Transport-Security'] = 'max-age=31536000; includeSubDomains; preload'

    # CSP: Restrict resource loading
    csp_policy = (
        "default-src 'self'; "
        "script-src 'self' 'unsafe-inline'; "
        "style-src 'self' 'unsafe-inline'; "
        "connect-src *; "
        "img-src 'self' data:; "
        "frame-ancestors 'none';"
    )
    response.headers['Content-Security-Policy'] = csp_policy

    # Prevent MIME type sniffing
    response.headers['X-Content-Type-Options'] = 'nosniff'

    # Prevent clickjacking
    response.headers['X-Frame-Options'] = 'DENY'

    # Enable XSS filter
    response.headers['X-XSS-Protection'] = '1; mode=block'

    # Control referrer information
    response.headers['Referrer-Policy'] = 'strict-origin-when-cross-origin'

    # Remove server header
    response.headers['Server'] = 'OAuth-Relay'

    return response


@app.after_request
def after_request(response):
    """Add security headers to all responses."""
    return add_security_headers(response)


@app.route('/health', methods=['GET'])
def health_check():
    """
    Health check endpoint.

    Returns:
        JSON response with status
    """
    return {
        "status": "healthy",
        "service": "oauth-callback-relay",
        "version": "1.0.0",
        "timestamp": datetime.utcnow().isoformat()
    }, 200


@app.route('/oauth/callback', methods=['GET'])
def oauth_callback():
    """
    Serve OAuth callback HTML page.

    This endpoint serves the secure callback page that:
    1. Receives OAuth authorization code from IDP
    2. Relays code to user's gateway instance
    3. Displays success/error status

    Returns:
        HTML page
    """
    client_ip = get_client_ip()

    # Check rate limit
    is_allowed, remaining = check_rate_limit(client_ip)

    if not is_allowed:
        log_security_event("rate_limit", client_ip, {
            "method": "GET",
            "path": "/oauth/callback",
            "exceeded": True
        })

        return {
            "error": "rate_limit_exceeded",
            "message": f"Too many requests. Please wait {RATE_LIMIT_WINDOW} seconds and try again.",
            "retry_after": RATE_LIMIT_WINDOW
        }, 429

    # Log callback request
    log_security_event("callback_page_view", client_ip, {
        "method": "GET",
        "user_agent": request.headers.get('User-Agent', 'unknown')[:100],
        "has_code": 'code' in request.args,
        "has_state": 'state' in request.args,
        "has_error": 'error' in request.args
    })

    # Serve the HTML file
    static_dir = Path(__file__).parent / 'static'
    return send_from_directory(static_dir, 'oauth_callback.html')


@app.route('/metrics', methods=['GET'])
def metrics():
    """
    Metrics endpoint (basic statistics).

    Requires API key for access.

    Returns:
        JSON with metrics
    """
    # Simple API key auth
    api_key = request.headers.get('X-API-Key')
    expected_key = os.environ.get('RELAY_METRICS_API_KEY')

    if not expected_key or api_key != expected_key:
        return {"error": "unauthorized"}, 401

    # Calculate metrics
    current_time = time.time()
    window_start = current_time - 60  # Last 60 seconds

    active_ips = set()
    recent_requests = 0

    for ip, timestamps in _rate_limit_store.items():
        recent_timestamps = [t for t in timestamps if t > window_start]
        if recent_timestamps:
            active_ips.add(ip)
            recent_requests += len(recent_timestamps)

    return {
        "timestamp": datetime.utcnow().isoformat(),
        "active_ips_last_60s": len(active_ips),
        "requests_last_60s": recent_requests,
        "security_log_size": len(_security_log),
        "rate_limit_config": {
            "max_requests": RATE_LIMIT_REQUESTS,
            "window_seconds": RATE_LIMIT_WINDOW
        }
    }, 200


@app.route('/security-log', methods=['GET'])
def security_log():
    """
    Security audit log endpoint.

    Requires API key for access.

    Returns:
        JSON with recent security events
    """
    # Simple API key auth
    api_key = request.headers.get('X-API-Key')
    expected_key = os.environ.get('RELAY_METRICS_API_KEY')

    if not expected_key or api_key != expected_key:
        return {"error": "unauthorized"}, 401

    # Get limit from query parameter
    limit = min(int(request.args.get('limit', 100)), MAX_LOG_SIZE)

    return {
        "timestamp": datetime.utcnow().isoformat(),
        "total_events": len(_security_log),
        "events": _security_log[-limit:]
    }, 200


@app.errorhandler(404)
def not_found(error):
    """Handle 404 errors."""
    client_ip = get_client_ip()
    log_security_event("not_found", client_ip, {
        "path": request.path,
        "method": request.method
    })

    return {"error": "not_found", "message": "Endpoint not found"}, 404


@app.errorhandler(500)
def internal_error(error):
    """Handle 500 errors."""
    client_ip = get_client_ip()
    log_security_event("internal_error", client_ip, {
        "path": request.path,
        "method": request.method,
        "error": str(error)
    })

    return {"error": "internal_error", "message": "Internal server error"}, 500


# HTTPS redirect middleware (for production)
@app.before_request
def before_request():
    """Enforce HTTPS in production."""
    # Skip for health check
    if request.path == '/health':
        return

    # Skip for localhost
    if request.host.startswith('localhost') or request.host.startswith('127.0.0.1'):
        return

    # Enforce HTTPS
    if request.scheme != 'https':
        url = request.url.replace('http://', 'https://', 1)
        return Response(
            f'Please use HTTPS: {url}',
            status=301,
            headers={'Location': url}
        )


if __name__ == '__main__':
    # Development server (use Gunicorn/uWSGI for production)
    port = int(os.environ.get('PORT', 8080))

    print(f"""
╔═══════════════════════════════════════════════════════════════╗
║   OAuth Callback Relay Service                                ║
║   Version: 1.0.0                                              ║
║   Port: {port}                                                   ║
║   Environment: {'Production' if os.environ.get('ENV') == 'production' else 'Development'}                                        ║
╚═══════════════════════════════════════════════════════════════╝

[*] Starting server...
[*] Health check: http://localhost:{port}/health
[*] Callback page: http://localhost:{port}/oauth/callback

[!] SECURITY NOTES:
    - This server should ONLY be deployed with HTTPS
    - Rate limiting is enabled ({RATE_LIMIT_REQUESTS} req/{RATE_LIMIT_WINDOW}s per IP)
    - Security headers are automatically added
    - All requests are logged for auditing

[*] Ready to accept connections...
    """)

    app.run(
        host='0.0.0.0',
        port=port,
        debug=(os.environ.get('ENV') != 'production')
    )
