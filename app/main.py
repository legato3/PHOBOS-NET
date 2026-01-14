"""Main entry point for PROX_NFDUMP application.

This module starts background threads and runs the Flask application.
"""
import os
import sys
import time
import atexit
import signal
import socket as socket_module

# Add parent directory to path for imports
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

# Import shutdown event from state module
from app.core.state import _shutdown_event

# Import thread functions
from app.core.threads import start_threat_thread, start_trends_thread, start_agg_thread

# Import syslog functions from app/services/syslog
try:
    from app.services.syslog import start_syslog_thread, _flush_syslog_buffer
except ImportError as e:
    print(f"Warning: Could not import syslog functions: {e}")
    start_syslog_thread = None
    _flush_syslog_buffer = None

if __name__ == "__main__":
    from app import app
    
    print("NetFlow Analytics Pro (Modernized)")
    
    # Graceful shutdown handler
    def shutdown_handler(signum=None, frame=None):
        print("\n[Shutdown] Stopping background services...")
        if _shutdown_event:
            _shutdown_event.set()
        if _flush_syslog_buffer:
            _flush_syslog_buffer()
        time.sleep(1)
        print("[Shutdown] Complete.")
    
    # Register shutdown handlers
    atexit.register(shutdown_handler)
    signal.signal(signal.SIGTERM, shutdown_handler)
    signal.signal(signal.SIGINT, shutdown_handler)
    
    # Start background services
    if start_threat_thread:
        start_threat_thread()
    if start_trends_thread:
        start_trends_thread()
    if start_agg_thread:
        start_agg_thread()
    if start_syslog_thread:
        start_syslog_thread()
    
    def _find_open_port(h, start_port, max_tries=10):
        """Find an open port starting from start_port."""
        p = start_port
        for _ in range(max_tries):
            try:
                s = socket_module.socket(socket_module.AF_INET, socket_module.SOCK_STREAM)
                s.setsockopt(socket_module.SOL_SOCKET, socket_module.SO_REUSEADDR, 1)
                s.bind((h, p))
                s.close()
                return p
            except OSError:
                p += 1
        return start_port
    
    # Run Flask app
    host = os.environ.get('FLASK_HOST', '0.0.0.0')
    requested_port = int(os.environ.get('FLASK_PORT', 8080))
    DEBUG_MODE = os.environ.get('FLASK_DEBUG', 'false').lower() == 'true'
    
    port = _find_open_port(host, requested_port)
    if port != requested_port:
        print(f"Requested port {requested_port} in use, selected {port} instead")
    print(f"Starting server on {host}:{port} (debug={DEBUG_MODE})")
    app.run(host=host, port=port, threaded=True, debug=DEBUG_MODE)
