# Gunicorn configuration for netflow-dashboard
# Background threads are started in post_worker_init (once per worker)
# With 1 worker, this ensures threads start only once

import sys
import os

# Support both production (/root) and Docker (/app) paths
work_dir = os.getenv('WORKDIR', '/app')
sys.path.insert(0, work_dir)

# CRITICAL FIX: Disable sendfile to resolve ERR_CONTENT_LENGTH_MISMATCH
# This is required when running in Docker with virtualized filesystems
# to ensure consistent Content-Length calculation.
sendfile = False
# Use /dev/shm for Gunicorn temporary files
worker_tmp_dir = "/dev/shm"

# Performance & Stability Tuning
workers = 2  # Increased for better concurrent request handling
threads = 4  # Allow concurrency within each worker
timeout = 120  # Prevent SIGKILL on slow database queries or large log fetches
keepalive = 5  # Help with persistent connections from browser
preload_app = False # Ensure background threads start fresh in worker

def post_worker_init(worker):
    """Called just after a worker has initialized the application."""
    # MULTI-WORKER GUARD:
    # Use a lock file to ensure only ONE worker starts the background threads.
    # This prevents duplicate DB writes and redundant thread overhead.
    import fcntl
    import os
    
    lock_file = "/tmp/phobos_thread.lock"
    # Create the file if it doesn't exist
    if not os.path.exists(lock_file):
        try:
            with open(lock_file, "w") as f:
                f.write("lock")
        except Exception:
            pass

    try:
        # Opening 'r+' so we don't truncate or delete existing lock
        f = open(lock_file, "r")
        # Attempt to get an exclusive lock. LOCK_NB means "Non-Blocking" (fail if someone else has it)
        fcntl.flock(f, fcntl.LOCK_EX | fcntl.LOCK_NB)
        
        # WE GOT THE LOCK! This worker is the designated maintenance worker.
        worker.log.info("Worker acquired maintenance lock. Starting background threads...")
        
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

            # Import SNMP thread
            try:
                from app.services.shared.snmp import start_snmp_thread
            except ImportError:
                start_snmp_thread = None
            
            start_threat_thread()
            start_trends_thread()
            start_agg_thread()
            start_db_size_sampler_thread()
            start_resource_sampler_thread()
            start_network_io_sampler_thread()
            start_dependency_health_thread()
            start_container_metrics_thread()
            
            if start_syslog_thread:
                start_syslog_thread()
            if start_firewall_syslog_thread:
                start_firewall_syslog_thread()
                worker.log.info("Firewall syslog listener started on port 515")
            
            if start_snmp_thread:
                start_snmp_thread()
                worker.log.info("SNMP polling thread started")

            # Add system startup event to timeline
            try:
                from app.services.shared.timeline import add_timeline_event
                add_timeline_event(
                    source='system',
                    summary=f'PHOBOS-NET maintenance started (pid {os.getpid()})',
                    raw={'event': 'startup', 'worker_pid': worker.pid}
                )
            except Exception:
                pass

            # Track telemetry startup
            try:
                from app.services.shared.telemetry import track_startup
                from app.config import APP_VERSION
                track_startup(version=APP_VERSION)
            except Exception:
                pass
                
        except Exception as e:
            worker.log.error(f"Error starting background threads: {e}")
            
    except (BlockingIOError, IOError):
        # Another worker already has the lock.
        worker.log.info(f"Worker (pid {os.getpid()}) skipped background threads (already running in another worker)")
        # Keep file open for the duration of the process life? 
        # Actually, f is local to this function. 
        # If f is garbage collected, the lock might be released?
        # To be safe, we'll store f on the worker object.
        worker._maintenance_lock_file = f
