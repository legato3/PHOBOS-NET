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
            # 1. PASSTHROUGH BYPASS: Do NOT touch responses that are already optimized.
            # This includes static files and streaming responses.
            if response.direct_passthrough or response.is_streamed:
                return response

            path = request.path
            # 2. ADDITIONAL STATIC BYPASS: Extra safety for identified common assets.
            if path == '/' or \
               request.endpoint == 'static' or \
               path.startswith(('/static/', '/img/')) or \
               path.endswith(('.ico', '.png', '.jpg', '.jpeg', '.js', '.css', '.svg', '.woff', '.woff2', '.mmdb')):
                return response

            # 3. THE NUCLEAR FIX: Recalculate Content-Length for APIs and dynamic routes.
            # Forces data read into memory to ensure the length header is 100% accurate.
            try:
                # set_data() resets the body and updates the Content-Length header.
                response.set_data(response.get_data())
            except Exception:
                pass

            # 4. Performance Tracking (Dynamic Routes Only)
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

            # 5. Security Headers
            response.headers['X-Content-Type-Options'] = 'nosniff'
            response.headers['X-Frame-Options'] = 'SAMEORIGIN'
            
            # 6. API Cache Control
            if path.startswith('/api/'):
                response.headers['Cache-Control'] = 'no-cache, no-store, must-revalidate'
            
            return response
        except Exception:
            return response
    
    return app

# Create app instance for backward compatibility
app = create_app()
