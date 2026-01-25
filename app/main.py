"""Main entry point for PHOBOS-NET application.

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

# Import shutdown event and log buffer from state module
from app.core.app_state import _shutdown_event, add_app_log

# Import config
from app.config import DEBUG_MODE

# Import thread functions
from app.core.background import (
    start_threat_thread,
    start_trends_thread,
    start_agg_thread,
    start_db_size_sampler_thread,
    start_resource_sampler_thread,
    start_network_io_sampler_thread,
    start_dependency_health_thread,
    start_container_metrics_thread,
    start_events_thread,
    start_digest_thread,
)

# Import syslog functions from app.services.shared.syslog
try:
    from app.services.shared.syslog import start_syslog_thread, _flush_syslog_buffer
except ImportError as e:
    print(f"Warning: Could not import syslog functions: {e}")
    start_syslog_thread = None
    _flush_syslog_buffer = None

# Import firewall syslog listener (isolated, port 515)
try:
    from app.services.syslog.firewall_listener import start_firewall_syslog_thread
except ImportError as e:
    print(f"Warning: Could not import firewall syslog listener: {e}")
    start_firewall_syslog_thread = None

# Import SNMP thread
try:
    from app.services.shared.snmp import start_snmp_thread
except ImportError as e:
    print(f"Warning: Could not import SNMP thread: {e}")
    start_snmp_thread = None

if __name__ == "__main__":
    from app import app
    from app.services.timeline.emitters import emit_system_event
    from app.services.shared.telemetry import track_startup

    startup_msg = "NetFlow Analytics Pro (Modernized)"
    print(startup_msg)
    add_app_log(startup_msg, "INFO")

    # Add system startup event to timeline
    emit_system_event("system_start", "PHOBOS-NET service started", detail=startup_msg)

    # Track telemetry startup
    from app.config import APP_VERSION

    track_startup(version=APP_VERSION)

    # Graceful shutdown handler
    def shutdown_handler(signum=None, frame=None):
        from app.services.shared.telemetry import track_shutdown

        shutdown_msg = "\n[Shutdown] Stopping background services..."
        print(shutdown_msg)
        add_app_log(shutdown_msg.strip(), "INFO")

        # Track telemetry shutdown
        track_shutdown()

        # Add system shutdown event to timeline (before shutdown_event is set)
        try:
            emit_system_event(
                "system_stop",
                "PHOBOS-NET service stopping",
                detail=shutdown_msg.strip(),
            )
        except Exception:
            pass  # Don't fail shutdown if timeline event fails

        if _shutdown_event:
            _shutdown_event.set()
        if _flush_syslog_buffer:
            _flush_syslog_buffer()
        time.sleep(1)
        complete_msg = "[Shutdown] Complete."
        print(complete_msg)
        add_app_log(complete_msg, "INFO")

    # Register shutdown handlers
    atexit.register(shutdown_handler)
    signal.signal(signal.SIGTERM, shutdown_handler)
    signal.signal(signal.SIGINT, shutdown_handler)

    # Start background services
    if start_threat_thread:
        start_threat_thread()
        add_app_log("Threat intelligence thread started", "INFO")
    if start_trends_thread:
        start_trends_thread()
        add_app_log("Trends aggregation thread started", "INFO")
    if start_agg_thread:
        start_agg_thread()
        add_app_log("Data aggregation thread started", "INFO")
    if start_syslog_thread:
        start_syslog_thread()
        add_app_log("Syslog receiver thread started", "INFO")
    if start_db_size_sampler_thread:
        start_db_size_sampler_thread()
        add_app_log("Database size sampler thread started", "INFO")
    if start_resource_sampler_thread:
        start_resource_sampler_thread()
        add_app_log("Resource sampler thread started", "INFO")
    if start_network_io_sampler_thread:
        start_network_io_sampler_thread()
        add_app_log("Network I/O sampler thread started", "INFO")
    if start_dependency_health_thread:
        start_dependency_health_thread()
        add_app_log("Dependency health thread started", "INFO")
    if start_container_metrics_thread:
        start_container_metrics_thread()
        add_app_log("Container metrics thread started", "INFO")
    if start_events_thread:
        start_events_thread()
        add_app_log("Events rule engine thread started", "INFO")
    if start_digest_thread:
        start_digest_thread()
        add_app_log("Digest notification thread started", "INFO")

    # Start firewall syslog listener (isolated, port 515)
    if start_firewall_syslog_thread:
        start_firewall_syslog_thread()
        add_app_log("Firewall syslog listener thread started (port 515)", "INFO")

    # Start SNMP thread
    if start_snmp_thread:
        start_snmp_thread()
        add_app_log("SNMP polling thread started", "INFO")

    def _find_open_port(h, start_port, max_tries=10):
        """Find an open port starting from start_port."""
        p = start_port
        for _ in range(max_tries):
            try:
                s = socket_module.socket(
                    socket_module.AF_INET, socket_module.SOCK_STREAM
                )
                s.setsockopt(socket_module.SOL_SOCKET, socket_module.SO_REUSEADDR, 1)
                s.bind((h, p))
                s.close()
                return p
            except OSError:
                p += 1
        return start_port

    # Run Flask app
    host = os.environ.get("FLASK_HOST", "0.0.0.0")
    requested_port = int(os.environ.get("FLASK_PORT", 8080))

    port = _find_open_port(host, requested_port)
    if port != requested_port:
        port_msg = f"Requested port {requested_port} in use, selected {port} instead"
        print(port_msg)
        add_app_log(port_msg, "WARN")
    server_msg = f"Starting server on {host}:{port} (debug={DEBUG_MODE})"
    print(server_msg)
    add_app_log(server_msg, "INFO")
    app.run(host=host, port=port, threaded=True, debug=DEBUG_MODE)
