"""Flask application factory for PROX_NFDUMP.

This module creates and configures the Flask application instance.
"""
from flask import Flask, request
from flask_compress import Compress

def create_app():
    """Create and configure the Flask application."""
    app = Flask(__name__, 
                static_folder='../frontend/static',
                template_folder='../frontend/templates')
    
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
    
    # Setup middleware
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
