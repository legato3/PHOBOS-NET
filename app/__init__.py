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
    
    # CRITICAL FIX: Disable X-Sendfile to resolve ERR_CONTENT_LENGTH_MISMATCH
    # This is common in Docker-on-Mac/Windows or proxy setups.
    app.config['USE_X_SENDFILE'] = False
    app.config['SEND_FILE_MAX_AGE_DEFAULT'] = 3600
    
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
        # Simple bypass for static files to reduce overhead
        if request.path.startswith('/static/') or request.path.endswith(('.ico', '.png', '.js', '.css')):
            return

        import uuid
        from app.core.app_state import record_http_request_start
        from datetime import datetime
        g.request_start_time = time.time()
        g.request_id = str(uuid.uuid4())[:8]
        record_http_request_start(g.request_id)
    
    @app.after_request
    def apply_server_policies(response):
        """Unified after_request handler for performance tracking and security headers."""
        try:
            # 1. CRITICAL BYPASS: Skip ALL custom logic for static files and common assets.
            # Use path-based matching FIRST for speed, then extension matching.
            if request.endpoint == 'static' or \
               request.path.startswith('/static/') or \
               request.path.startswith('/img/') or \
               request.path.startswith('/api/firewall/') or \
               request.path.startswith('/api/stats/') or \
               request.path.endswith(('.ico', '.png', '.jpg', '.jpeg', '.js', '.css', '.svg', '.woff', '.woff2')):
                return response

            # 2. Performance Tracking
            from app.services.shared.metrics import track_performance, track_slow_request
            from app.config import OBS_ROUTE_SLOW_MS, OBS_ROUTE_SLOW_WARN_MS
            from app.services.shared.observability import _logger
            from app.core.app_state import record_http_request_end

            endpoint = request.endpoint or 'unknown'
            if hasattr(g, 'request_start_time'):
                duration = time.time() - g.request_start_time
                duration_ms = duration * 1000
                
                is_cached = response.status_code == 304 or 'cache' in response.headers.get('Cache-Control', '').lower()
                track_performance(endpoint, duration, cached=is_cached)

                if hasattr(g, 'request_id'):
                    record_http_request_end(g.request_id, response.status_code, request.method, endpoint)

                if duration_ms > OBS_ROUTE_SLOW_MS:
                    track_slow_request()
                    if duration_ms > OBS_ROUTE_SLOW_WARN_MS:
                        _logger.warning(f"Slow route: {endpoint} ({duration_ms:.1f}ms) - {request.path}")

            # 3. Security Headers (only for non-static content)
            response.headers['X-Content-Type-Options'] = 'nosniff'
            response.headers['X-Frame-Options'] = 'SAMEORIGIN'
            
            # Use a slightly more relaxed CSP for CDN/Icons if needed, but keep it strict by default
            response.headers['Content-Security-Policy'] = (
                "default-src 'self'; "
                "script-src 'self' 'unsafe-inline' 'unsafe-eval' https://cdn.jsdelivr.net https://unpkg.com; "
                "style-src 'self' 'unsafe-inline' https://cdn.jsdelivr.net https://unpkg.com https://fonts.googleapis.com; "
                "img-src 'self' data: https:; "
                "font-src 'self' https://cdn.jsdelivr.net https://fonts.gstatic.com data:; "
                "connect-src 'self'; "
            )

            # 4. API Cache Control
            if request.path.startswith('/api/'):
                response.headers['Cache-Control'] = 'no-cache, no-store, must-revalidate'
            
            return response
        except Exception as e:
            # Fallback for unexpected errors in middleware to ensure response delivery
            try:
                from app.services.shared.observability import _logger
                _logger.error(f"Error in after_request: {e}")
            except:
                pass
            return response
    
    return app

# Create app instance for backward compatibility
app = create_app()
