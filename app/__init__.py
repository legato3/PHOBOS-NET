"""Flask application factory for PHOBOS-NET.

This module creates and configures the Flask application instance.
"""

import time
import os
import uuid
from flask import Flask, request, g

# Import observability and metrics at top level to avoid handler overhead
from app.services.shared.metrics import track_performance, track_slow_request
from app.config import OBS_ROUTE_SLOW_MS, OBS_ROUTE_SLOW_WARN_MS
from app.services.shared.observability import _logger
from app.core.app_state import record_http_request_start, record_http_request_end


def create_app():
    """Create and configure the Flask application."""
    # Determine base directory (project root) robustly
    # This file is expected to be in [project_root]/app/__init__.py
    current_file_dir = os.path.dirname(os.path.abspath(__file__))  # .../app/app
    base_dir = os.path.dirname(current_file_dir)  # .../app (project root)

    # Define paths
    template_dir = os.path.join(base_dir, "frontend", "templates")
    static_dir = os.path.join(base_dir, "frontend", "src")

    # Validation/Fallback: Check if directories exist
    if not os.path.exists(template_dir):
        # Debugging: Print path that failed
        print(f"WARNING: Template directory not found at {template_dir}")
        # Try finding it relative to CWD if potential mismatch
        cwd = os.getcwd()
        potential_tpl = os.path.join(cwd, "frontend", "templates")
        if os.path.exists(potential_tpl):
            print(f"INFO: Found templates at {potential_tpl}, using that.")
            template_dir = potential_tpl
            static_dir = os.path.join(cwd, "frontend", "src")

    app = Flask(
        __name__,
        static_url_path="/static",
        static_folder=static_dir,
        template_folder=template_dir,
    )

    # CRITICAL FIX: Disable X-Sendfile to resolve ERR_CONTENT_LENGTH_MISMATCH
    app.config["USE_X_SENDFILE"] = False
    app.config["SEND_FILE_MAX_AGE_DEFAULT"] = 3600

    # Register blueprints
    from app.api.routes import bp as routes_bp

    app.register_blueprint(routes_bp)

    # Register Firewall Decisions Blueprint
    from app.api.routes.firewall_decisions import bp as fw_decisions_bp

    app.register_blueprint(fw_decisions_bp)

    # Register Insights Blueprint (Personality & Overlays)
    from app.api.routes.insights import bp as insights_bp

    app.register_blueprint(insights_bp)

    # Setup middleware
    @app.before_request
    def track_request_start():
        """OBSERVABILITY: Track request start time and concurrent requests."""
        if request.path.startswith("/static/") or request.path.endswith(
            (".ico", ".png", ".js", ".css", ".svg", ".woff", ".woff2")
        ):
            return

        g.request_start_time = time.time()
        g.request_id = str(uuid.uuid4())[:8]
        record_http_request_start(g.request_id)

    @app.after_request
    def apply_server_policies(response):
        """Unified after_request handler for performance tracking and security headers."""
        try:
            path = request.path
            is_static = (
                path == "/"
                or request.endpoint == "static"
                or path.startswith(("/static/", "/img/"))
                or path.endswith(
                    (
                        ".ico",
                        ".png",
                        ".jpg",
                        ".jpeg",
                        ".js",
                        ".css",
                        ".svg",
                        ".woff",
                        ".woff2",
                        ".mmdb",
                    )
                )
            )

            if not is_static:
                endpoint = request.endpoint or "unknown"
                if hasattr(g, "request_start_time"):
                    duration = time.time() - g.request_start_time
                    duration_ms = duration * 1000

                    is_cached = (
                        response.status_code == 304
                        or "cache" in response.headers.get("Cache-Control", "").lower()
                    )
                    track_performance(endpoint, duration, cached=is_cached)

                    if hasattr(g, "request_id"):
                        record_http_request_end(
                            g.request_id, response.status_code, request.method, endpoint
                        )

                    if duration_ms > OBS_ROUTE_SLOW_MS:
                        track_slow_request()
                        if duration_ms > OBS_ROUTE_SLOW_WARN_MS:
                            _logger.warning(
                                f"Slow route: {endpoint} ({duration_ms:.1f}ms) - {path}"
                            )

            response.headers["X-Content-Type-Options"] = "nosniff"
            response.headers["X-Frame-Options"] = "SAMEORIGIN"

            if path.startswith("/api/"):
                response.headers["Cache-Control"] = (
                    "no-cache, no-store, must-revalidate"
                )

            return response
        except Exception as e:
            _logger.error(f"Error in apply_server_policies: {e}")
            return response

    return app


# Create app instance for backward compatibility
app = create_app()
