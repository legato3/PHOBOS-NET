"""Flask application factory for PHOBOS-NET.

This module creates and configures the Flask application instance.
"""
import time
import os
import uuid
from flask import Flask, request, g, jsonify, Response, current_app

# Import observability and metrics at top level to avoid handler overhead
from app.services.shared.metrics import track_performance, track_slow_request
from app.config import OBS_ROUTE_SLOW_MS, OBS_ROUTE_SLOW_WARN_MS
from app.services.shared.observability import _logger
from app.core.app_state import record_http_request_start, record_http_request_end

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
        if request.path.startswith('/static/') or request.path.endswith(('.ico', '.png', '.js', '.css', '.svg', '.woff', '.woff2')):
            return

        g.request_start_time = time.time()
        g.request_id = str(uuid.uuid4())[:8]
        record_http_request_start(g.request_id)
    
    @app.after_request
    def apply_server_policies(response):
        """Unified after_request handler for performance tracking and security headers."""
        try:
            # 1. ROBUST CONTENT-LENGTH HANDLING (Re-applied):
            # We explicitly buffer the response to calculate the EXACT byte length.
            # This is critical for Docker environments where 'gthread' might otherwise 
            # stream data with a mismatched Content-Length header derived from file stat.
            if not response.is_streamed:
                # Force full read into memory
                response.direct_passthrough = False
                content_bytes = response.get_data()
                # Re-set data to ensure consistency
                response.set_data(content_bytes)
                # Set accurate header
                response.headers['Content-Length'] = str(len(content_bytes))

            path = request.path
            is_static = path == '/' or \
                        request.endpoint == 'static' or \
                        path.startswith(('/static/', '/img/')) or \
                        path.endswith(('.ico', '.png', '.jpg', '.jpeg', '.js', '.css', '.svg', '.woff', '.woff2', '.mmdb'))

            # 2. Performance Tracking (Dynamic Routes Only)
            if not is_static:
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
                            _logger.warning(f"Slow route: {endpoint} ({duration_ms:.1f}ms) - {path}")

            # 3. Security Headers
            response.headers['X-Content-Type-Options'] = 'nosniff'
            response.headers['X-Frame-Options'] = 'SAMEORIGIN'
            
            # 4. API Cache Control
            if path.startswith('/api/'):
                response.headers['Cache-Control'] = 'no-cache, no-store, must-revalidate'
            
            return response
        except Exception as e:
            # Basic logging of the failure
            _logger.error(f"Error in apply_server_policies: {e}")
            return response
    
    return app

# Create app instance for backward compatibility
app = create_app()
