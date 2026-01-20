# Gunicorn configuration for netflow-dashboard
# Background threads are started in post_worker_init (once per worker)
# With 1 worker, this ensures threads start only once

import sys
import os

# Support both production (/root) and Docker (/app) paths
work_dir = os.getenv('WORKDIR', '/app')
sys.path.insert(0, work_dir)

def post_worker_init(worker):
    """Called just after a worker has initialized the application."""
    # Start background threads (happens once per worker)
    # With 1 worker, this runs once and threads are shared
    try:
        from app.core.background import (
            start_threat_thread, start_trends_thread, start_agg_thread,
            start_db_size_sampler_thread, start_resource_sampler_thread,
            start_network_io_sampler_thread, start_dependency_health_thread,
            start_container_metrics_thread
        )
        # Import syslog thread from new service module
        try:
            from app.services.shared.syslog import start_syslog_thread
        except ImportError:
            start_syslog_thread = None
        
        # Import firewall syslog listener (port 515)
        try:
            from app.services.syslog.firewall_listener import start_firewall_syslog_thread
        except ImportError:
            start_firewall_syslog_thread = None
        
        start_threat_thread()
        start_trends_thread()
        start_agg_thread()
        start_db_size_sampler_thread()  # Background database size sampling (decoupled from API)
        start_resource_sampler_thread()  # Background CPU/memory sampling for resource history
        start_network_io_sampler_thread()  # Network I/O bandwidth monitoring
        start_dependency_health_thread()  # External dependency health checks
        start_container_metrics_thread()  # Docker container metrics (if containerized)
        if start_syslog_thread:
            start_syslog_thread()
        if start_firewall_syslog_thread:
            start_firewall_syslog_thread()
            worker.log.info("Firewall syslog listener started on port 515")

        # Add system startup event to timeline
        try:
            from app.services.shared.timeline import add_timeline_event
            add_timeline_event(
                source='system',
                summary='PHOBOS-NET service started (gunicorn)',
                raw={'event': 'startup', 'worker_pid': worker.pid}
            )
        except Exception:
            pass  # Timeline event is non-critical

        # Track telemetry startup
        try:
            from app.services.shared.telemetry import track_startup
            track_startup(version="1.2.5")
        except Exception:
            pass  # Telemetry is non-critical
    except Exception as e:
        worker.log.error(f"Error starting background threads: {e}")
