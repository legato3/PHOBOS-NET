"""Flask application factory for PHOBOS-NET.

This module creates and configures the Flask application instance.
"""
import time
from flask import Flask, request, g
from flask_compress import Compress

import os

def create_app():
    """Create and configure the Flask application."""
    # Base directory relative to this file
    base_dir = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
    
    app = Flask(__name__, 
                static_url_path='/static',
                static_folder=os.path.join(base_dir, 'frontend', 'src'),
                template_folder=os.path.join(base_dir, 'frontend', 'templates'))
    
    # Configure compression
    Compress(app)
    app.config['COMPRESS_MIMETYPES'] = [
        'text/html', 'text/css', 'text/javascript',
        'application/json', 'application/javascript'
    ]
    app.config['COMPRESS_LEVEL'] = 6
    app.config['COMPRESS_MIN_SIZE'] = 500
    
    # Register blueprints
    from app.api.routes import bp as routes_bp
    app.register_blueprint(routes_bp)
    
    # Register Firewall Decisions Blueprint (Read-Only Observability)
    from app.api.routes.firewall_decisions import bp as fw_decisions_bp
    app.register_blueprint(fw_decisions_bp)
    
    # Setup middleware
    @app.before_request
    def track_request_start():
        """OBSERVABILITY: Track request start time for duration measurement."""
        g.request_start_time = time.time()
    
    @app.after_request
    def track_request_performance(response):
        """OBSERVABILITY: Track request duration and flag slow requests."""
        from app.services.shared.metrics import track_performance, track_slow_request
        from app.config import OBS_ROUTE_SLOW_MS, OBS_ROUTE_SLOW_WARN_MS
        from app.services.shared.observability import _logger
        
        if hasattr(g, 'request_start_time'):
            duration = time.time() - g.request_start_time
            duration_ms = duration * 1000
            
            # Track performance metrics
            endpoint = request.endpoint or 'unknown'
            is_cached = response.status_code == 304 or 'cache' in response.headers.get('Cache-Control', '').lower()
            track_performance(endpoint, duration, cached=is_cached)
            
            # Guardrail: Track and warn on slow requests
            if duration_ms > OBS_ROUTE_SLOW_MS:
                track_slow_request()
                
                if duration_ms > OBS_ROUTE_SLOW_WARN_MS:
                    _logger.warning(
                        f"Slow request detected: {endpoint} took {duration_ms:.1f}ms "
                        f"(threshold: {OBS_ROUTE_SLOW_WARN_MS}ms) - {request.path}"
                    )
        
        return response
    
    @app.after_request
    def set_security_headers(response):
        """Add security headers and cache headers to all responses."""
        response.headers['X-Content-Type-Options'] = 'nosniff'
        response.headers['X-Frame-Options'] = 'DENY'
        response.headers['X-XSS-Protection'] = '1; mode=block'
        response.headers['Referrer-Policy'] = 'strict-origin-when-cross-origin'
        response.headers['Permissions-Policy'] = 'geolocation=(), microphone=(), camera=()'
        
        # Content Security Policy (relaxed for Alpine.js inline handlers)
        csp = (
            "default-src 'self'; "
            "script-src 'self' 'unsafe-inline' 'unsafe-eval' https://cdn.jsdelivr.net https://unpkg.com; "
            "style-src 'self' 'unsafe-inline' https://cdn.jsdelivr.net https://unpkg.com https://fonts.googleapis.com; "
            "img-src 'self' data: https:; "
            "font-src 'self' https://cdn.jsdelivr.net https://fonts.gstatic.com data:; "
            "connect-src 'self'; "
            "frame-ancestors 'none';"
        )
        response.headers['Content-Security-Policy'] = csp
        
        # Cache headers for static files
        if request.endpoint == 'static' or request.path.startswith('/static/'):
            response.headers['Cache-Control'] = 'public, max-age=31536000, immutable'
        # Cache headers for API endpoints
        elif request.path.startswith('/api/'):
            response.headers['Cache-Control'] = 'public, max-age=60'
        # No cache for HTML
        elif request.path == '/' or request.path.endswith('.html'):
            response.headers['Cache-Control'] = 'no-cache, no-store, must-revalidate'
            response.headers['Pragma'] = 'no-cache'
            response.headers['Expires'] = '0'
        
        return response
    
    return app

# Create app instance for backward compatibility
app = create_app()
