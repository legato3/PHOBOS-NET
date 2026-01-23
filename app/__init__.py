"""Flask application factory for PHOBOS-NET.

This module creates and configures the Flask application instance.
"""
import time
from flask import Flask, request, g
import os

def create_app():
    """Create and configure the Flask application."""
    # Base directory relative to this file
    base_dir = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
    
    app = Flask(__name__, 
                static_url_path='/static',
                static_folder=os.path.join(base_dir, 'frontend', 'src'),
                template_folder=os.path.join(base_dir, 'frontend', 'templates'))
    
    # Remove compression configuration for stability
    # (Previously causing ERR_CONTENT_LENGTH_MISMATCH)
    
    # Register blueprints
    from app.api.routes import bp as routes_bp
    app.register_blueprint(routes_bp)
    
    # Register Firewall Decisions Blueprint (Read-Only Observability)
    from app.api.routes.firewall_decisions import bp as fw_decisions_bp
    app.register_blueprint(fw_decisions_bp)
    
    # Setup middleware
    @app.before_request
    def track_request_start():
        """OBSERVABILITY: Track request start time and concurrent requests."""
        import uuid
        from app.core.app_state import record_http_request_start
        g.request_start_time = time.time()
        g.request_id = str(uuid.uuid4())[:8]
        record_http_request_start(g.request_id)
    
    @app.after_request
    def track_request_performance(response):
        """OBSERVABILITY: Track request duration, HTTP metrics, and flag slow requests."""
        # High-performance exit for static files (avoid overhead and header interference)
        if request.endpoint == 'static' or request.path.startswith('/static/'):
            return response

        from app.services.shared.metrics import track_performance, track_slow_request
        from app.config import OBS_ROUTE_SLOW_MS, OBS_ROUTE_SLOW_WARN_MS
        from app.services.shared.observability import _logger
        from app.core.app_state import record_http_request_end

        if hasattr(g, 'request_start_time'):
            duration = time.time() - g.request_start_time
            duration_ms = duration * 1000

            # Track performance metrics
            endpoint = request.endpoint or 'unknown'
            is_cached = response.status_code == 304 or 'cache' in response.headers.get('Cache-Control', '').lower()
            track_performance(endpoint, duration, cached=is_cached)

            # Track HTTP metrics (status codes, methods, concurrent requests)
            if hasattr(g, 'request_id'):
                record_http_request_end(g.request_id, response.status_code, request.method, endpoint)

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
        """Add basic security headers and cache headers."""
        # CRITICAL FIX: Explicitly bypass ALL static file responses.
        # Touching headers on static file responses (generators/streaming) in Flask/Gunicorn
        # frequently triggers ERR_CONTENT_LENGTH_MISMATCH or trunkated downloads.
        if request.endpoint == 'static' or request.path.startswith('/static/'):
            return response

        # Standard safety headers for API and HTML routes
        response.headers['X-Content-Type-Options'] = 'nosniff'
        response.headers['X-Frame-Options'] = 'SAMEORIGIN'
        
        # Simpler CSP to avoid blocking assets during troubleshooting
        csp = (
            "default-src 'self'; "
            "script-src 'self' 'unsafe-inline' 'unsafe-eval' https://cdn.jsdelivr.net https://unpkg.com; "
            "style-src 'self' 'unsafe-inline' https://cdn.jsdelivr.net https://unpkg.com https://fonts.googleapis.com; "
            "img-src 'self' data: https:; "
            "font-src 'self' https://cdn.jsdelivr.net https://fonts.gstatic.com data:; "
            "connect-src 'self'; "
        )
        response.headers['Content-Security-Policy'] = csp
        
        # Standard cache headers for API
        if request.path.startswith('/api/'):
            response.headers['Cache-Control'] = 'no-cache, no-store, must-revalidate'
        
        return response
    
    return app

# Create app instance for backward compatibility
app = create_app()
