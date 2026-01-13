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
        import netflow_dashboard
        netflow_dashboard.start_threat_thread()
        netflow_dashboard.start_trends_thread()
        netflow_dashboard.start_agg_thread()
        netflow_dashboard.start_syslog_thread()
    except Exception as e:
        worker.log.error(f"Error starting background threads: {e}")
