from . import bp
"""Flask routes for PROX_NFDUMP application.

This module contains all API routes extracted from netflow-dashboard.py.
Routes are organized in a single Flask Blueprint.
"""
from flask import Blueprint, render_template, jsonify, request, Response, stream_with_context, current_app
import time
import os
import json
import socket
import threading
import subprocess
import requests
from datetime import datetime, timedelta, timezone
from collections import defaultdict, deque, Counter
from concurrent.futures import ThreadPoolExecutor
import sqlite3

# Import from service modules (already extracted)
from app.services.netflow.netflow import get_common_nfdump_data, run_nfdump, parse_csv, get_traffic_direction
from app.services.security.threats import (
    fetch_threat_feed, get_threat_info, update_threat_timeline, get_threat_timeline,
    load_watchlist, add_to_watchlist, remove_from_watchlist,
    detect_anomalies, run_all_detections,
    load_threatlist, get_feed_label, send_notifications,
    lookup_threat_intelligence, detect_ip_anomalies, generate_ip_anomaly_alerts,
    add_health_alert_to_history
)
from app.services.netflow.stats import calculate_security_score
from app.services.shared.metrics import track_performance, track_error, get_performance_metrics, get_performance_lock
from app.services.shared.snmp import get_snmp_data, start_snmp_thread
from app.services.shared.cpu import calculate_cpu_percent_from_stat
from app.core.background import start_threat_thread, start_trends_thread, start_agg_thread
from app.services.shared.helpers import is_internal, get_region, fmt_bytes, get_time_range, flag_from_iso, load_list, check_disk_space, format_duration
from app.core.app_state import (
    _shutdown_event,
    _lock_summary, _lock_sources, _lock_dests, _lock_ports, _lock_protocols,
    _lock_alerts, _lock_flags, _lock_asns, _lock_durations, _lock_bandwidth,
    _lock_flows, _lock_countries, _lock_worldmap,
    _lock_proto_hierarchy, _lock_noise,
    _cache_lock, _mock_lock,
    _throttle_lock, _common_data_lock, _cpu_stat_lock,
    _stats_summary_cache, _stats_sources_cache, _stats_dests_cache,
    _stats_ports_cache, _stats_protocols_cache, _stats_alerts_cache,
    _stats_flags_cache, _stats_asns_cache, _stats_durations_cache,
    _stats_pkts_cache, _stats_countries_cache, _stats_talkers_cache,
    _stats_services_cache, _stats_hourly_cache, _stats_flow_stats_cache,
    _stats_proto_mix_cache, _stats_net_health_cache,
    _stats_proto_hierarchy_cache, _stats_noise_metrics_cache,
    _server_health_cache,
    _mock_data_cache, _bandwidth_cache, _bandwidth_history_cache,
    _flows_cache, _common_data_cache,
    _request_times,
    _metric_nfdump_calls, _metric_stats_cache_hits, _metric_bw_cache_hits,
    _metric_conv_cache_hits, _metric_flow_cache_hits, _metric_http_429,
    _cpu_stat_prev,
    _threat_thread_started, _trends_thread_started, _agg_thread_started,
    _syslog_thread_started, _snmp_thread_started,
    _syslog_stats, _syslog_stats_lock, _syslog_buffer, _syslog_buffer_lock,
    _syslog_buffer_size,
    _snmp_cache, _snmp_cache_lock, _snmp_prev_sample, _snmp_backoff,
    _has_nfdump,
    _dns_resolver_executor,
    _flow_history, _flow_history_lock, _flow_history_ttl,
    _app_log_buffer, _app_log_buffer_lock, add_app_log,
)
# Import threats module to access threat state
import app.services.security.threats as threats_module
import app.core.app_state as state
from app.services.shared.config_helpers import load_notify_cfg, save_notify_cfg, load_thresholds, save_thresholds, load_config, save_config
from app.services.shared.formatters import format_time_ago, format_uptime
from app.services.shared.geoip import lookup_geo, load_city_db
import app.services.shared.geoip as geoip_module
from app.services.shared.dns import resolve_ip
import app.services.shared.dns as dns_module
from app.services.shared.decorators import throttle
from app.db.sqlite import _get_firewall_block_stats, _firewall_db_connect, _firewall_db_init, _trends_db_init, _get_bucket_end, _ensure_rollup_for_bucket, _trends_db_lock, _firewall_db_lock, _trends_db_connect
from app.config import (
    FIREWALL_DB_PATH, TRENDS_DB_PATH, PORTS, PROTOS, SUSPICIOUS_PORTS,
    NOTIFY_CFG_PATH, THRESHOLDS_CFG_PATH, CONFIG_PATH, THREAT_WHITELIST,
    LONG_LOW_DURATION_THRESHOLD, LONG_LOW_BYTES_THRESHOLD
)

# Create Blueprint

# Routes extracted from netflow-dashboard.py
# Changed @app.route() to @bp.route()

@bp.route("/")
def index():
    start_threat_thread()
    start_trends_thread()
    start_agg_thread()
    return render_template("index.html")


@bp.route("/wallboard")
@bp.route("/noc")
def wallboard():
    """NOC/Wallboard view - read-only, large typography, optimized for distance viewing."""
    return render_template("wallboard.html")


@bp.route("/favicon.ico")
def favicon():
    """Serve favicon file."""
    from flask import send_from_directory
    return send_from_directory('../frontend/src', 'favicon.ico', mimetype='image/vnd.microsoft.icon')

@bp.route("/debug/paths")
def debug_paths():
    """Debug route to inspect Flask paths."""
    return jsonify({
        "static_folder": current_app.static_folder,
        "template_folder": current_app.template_folder,
        "root_path": current_app.root_path,
        "cwd": os.getcwd(),
        "static_folder_exists": os.path.exists(current_app.static_folder) if current_app.static_folder else False,
        "src_exists": os.path.exists("../frontend/src")
    })


@bp.route("/api/stats/summary")
@throttle(5, 10)
def api_stats_summary():
    range_key = request.args.get('range', '1h')
    now = time.time()
    win = int(now // 60)
    with _lock_summary:
        if _stats_summary_cache["data"] and _stats_summary_cache.get("key") == range_key and _stats_summary_cache.get("win") == win:
            return jsonify(_stats_summary_cache["data"])

    # Reuse common data cache instead of running separate nfdump query
    # Note: These totals are derived from top 100 sources (not complete dataset)
    # This provides a representative sample while avoiding expensive full aggregation
    sources = get_common_nfdump_data("sources", range_key)

    # Check for failure (None)
    if sources is None:
        data = {
            "totals": {
                "bytes": None,
                "flows": None,
                "packets": None,
                "bytes_fmt": "Unavailable",
                "avg_packet_size": None,
                "source": "top_100_sources"
            },
            "status": "error",
            "message": "Data unavailable",
            "notify": load_notify_cfg(),
            "threat_status": threats_module._threat_status
        }
    else:
        tot_b = sum(i["bytes"] for i in sources)
        tot_f = sum(i["flows"] for i in sources)
        tot_p = sum(i["packets"] for i in sources)
        data = {
            "totals": {
                "bytes": tot_b,
                "flows": tot_f,
                "packets": tot_p,
                "bytes_fmt": fmt_bytes(tot_b),
                "avg_packet_size": int(tot_b/tot_p) if tot_p > 0 else 0,
                "source": "top_100_sources"  # Clarify data source for transparency
            },
            "status": "ok",
            "notify": load_notify_cfg(),
            "threat_status": threats_module._threat_status
        }

    with _lock_summary:
        _stats_summary_cache["data"] = data
        _stats_summary_cache["ts"] = now
        _stats_summary_cache["key"] = range_key
        _stats_summary_cache["win"] = win
    return jsonify(data)



@bp.route("/api/notify_status")
def api_notify_status():
    return jsonify(load_notify_cfg())


@bp.route("/api/notify_toggle", methods=['POST'])
def api_notify_toggle():
    data = request.get_json(force=True, silent=True) or {}
    target = data.get('target')
    state = bool(data.get('state', True))
    cfg = load_notify_cfg()
    if target == 'email':
        cfg['email'] = state
    elif target == 'webhook':
        cfg['webhook'] = state
    save_notify_cfg(cfg)
    return jsonify(cfg)


@bp.route('/api/notify_mute', methods=['POST'])
def api_notify_mute():
    data = request.get_json(force=True, silent=True) or {}
    mute = bool(data.get('mute', True))
    cfg = load_notify_cfg()
    cfg['mute_until'] = time.time() + 3600 if mute else 0
    save_notify_cfg(cfg)
    return jsonify(cfg)


@bp.route('/api/thresholds', methods=['GET', 'POST'])
def api_thresholds():
    if request.method == 'GET':
        return jsonify(load_thresholds())
    data = request.get_json(force=True, silent=True) or {}
    saved = save_thresholds(data)
    return jsonify(saved)


# ===== FORENSICS API ENDPOINTS =====


@bp.route('/api/config', methods=['GET', 'POST'])
def api_config():
    """Get or update application configuration."""
    if request.method == 'GET':
        cfg = load_config()
        # Mask sensitive values for display
        if cfg.get('snmp_community'):
            cfg['snmp_community_masked'] = '*' * len(cfg['snmp_community'])
        return jsonify(cfg)
    data = request.get_json(force=True, silent=True) or {}
    saved = save_config(data)
    return jsonify({'status': 'ok', 'config': saved})


@bp.route('/api/app/metadata')
@throttle(10, 60)
def api_app_metadata():
    """Get application metadata (name, version)."""
    from app.config import APP_NAME, APP_VERSION, APP_VERSION_DISPLAY
    return jsonify({
        'name': APP_NAME,
        'version': APP_VERSION,
        'version_display': APP_VERSION_DISPLAY
    })



@bp.route('/metrics')
def metrics():
    """Prometheus-style metrics for basic instrumentation."""
    lines = []
    def add_metric(name, value, help_text=None, mtype='gauge'):
        if help_text:
            lines.append(f"# HELP {name} {help_text}")
        if mtype:
            lines.append(f"# TYPE {name} {mtype}")
        lines.append(f"{name} {value}")

    add_metric('netflow_nfdump_calls_total', _metric_nfdump_calls, 'Total number of nfdump calls', 'counter')
    add_metric('netflow_stats_cache_hits_total', _metric_stats_cache_hits, 'Cache hits for stats endpoints', 'counter')
    add_metric('netflow_bw_cache_hits_total', _metric_bw_cache_hits, 'Cache hits for bandwidth endpoint', 'counter')
    add_metric('netflow_flow_cache_hits_total', _metric_flow_cache_hits, 'Cache hits for flows endpoint', 'counter')
    add_metric('netflow_http_429_total', _metric_http_429, 'HTTP 429 rate-limit responses', 'counter')
    # Cache sizes
    add_metric('netflow_common_cache_size', len(_common_data_cache))
    add_metric('netflow_dns_cache_size', len(dns_module._dns_cache))
    add_metric('netflow_geo_cache_size', len(geoip_module._geo_cache))
    add_metric('netflow_bandwidth_history_size', len(_bandwidth_history_cache))
    # Threads status
    add_metric('netflow_threat_thread_started', 1 if _threat_thread_started else 0)
    add_metric('netflow_snmp_thread_started', 1 if _snmp_thread_started else 0)
    add_metric('netflow_trends_thread_started', 1 if _trends_thread_started else 0)
    add_metric('netflow_agg_thread_started', 1 if _agg_thread_started else 0)

    body = "\n".join(lines) + "\n"
    return Response(body, mimetype='text/plain; version=0.0.4')



@bp.route('/health')
def health_check():
    """Health check endpoint for monitoring."""
    # Syslog is considered active if:
    # 1. Messages have been received, OR
    # 2. The receiver thread is running (listening but no traffic yet)
    syslog_active = _syslog_stats.get('received', 0) > 0 or state._syslog_thread_started
    
    checks = {
        'database': False,
        'disk_space': check_disk_space('/var/cache/nfdump'),
        'syslog_active': syslog_active,
        'nfdump_available': state._has_nfdump,
        'memory_usage_mb': 0
    }

    # Check database connectivity
    try:
        with _firewall_db_lock:
            conn = _firewall_db_connect()
            conn.execute("SELECT 1")
            conn.close()
        checks['database'] = True
    except Exception:
        checks['database'] = False

    # Check memory usage (simple approximation)
    try:
        import resource
        mem_mb = resource.getrusage(resource.RUSAGE_SELF).ru_maxrss / 1024  # Linux returns KB
        checks['memory_usage_mb'] = round(mem_mb, 1)
    except Exception:
        pass

    # Determine overall status
    disk_status = checks['disk_space'].get('status', 'unknown')
    all_ok = checks['database'] and checks['syslog_active'] and checks['nfdump_available'] and disk_status != 'critical'

    status_code = 200 if all_ok else 503
    status_text = 'healthy' if all_ok else 'degraded'

    return jsonify({
        'status': status_text,
        'checks': checks,
        'timestamp': datetime.now().isoformat()
    }), status_code



@bp.route('/api/server/health')
@throttle(10, 5)  # Allow 10 requests per 5 seconds (2 req/sec) for 1-2 sec refresh
def api_server_health():
    """Comprehensive server health statistics for the dashboard server."""
    global _server_health_cache
    now = time.time()

    # Use cache if data is fresh (1 second TTL for near-real-time updates)
    SERVER_HEALTH_CACHE_TTL = 1.0
    with _cache_lock:
        if _server_health_cache["data"] and (now - _server_health_cache["ts"]) < SERVER_HEALTH_CACHE_TTL:
            return jsonify(_server_health_cache["data"])

    from app.config import APP_NAME, APP_VERSION
    
    data = {
        'application': {
            'name': APP_NAME,
            'version': APP_VERSION
        },
        'cpu': {},
        'memory': {},
        'disk': {},
        'syslog': {},
        'netflow': {},
        'database': {},
        'system': {},
        'timestamp': datetime.now().isoformat()
    }

    # CPU Statistics - use /proc filesystem (no psutil)
    try:
        # Get CPU percentage from /proc/stat (accurate method)
        cpu_percent, per_core, num_cores = calculate_cpu_percent_from_stat()
        if cpu_percent is not None:
            data['cpu']['percent'] = cpu_percent
        if per_core:
            data['cpu']['per_core'] = [round(p, 1) for p in per_core]
        if num_cores:
            data['cpu']['cores'] = num_cores

        # Get load averages
        try:
            loadavg = os.getloadavg() if hasattr(os, 'getloadavg') else None
            if loadavg:
                data['cpu']['load_1min'] = round(loadavg[0], 2)
                data['cpu']['load_5min'] = round(loadavg[1], 2)
                data['cpu']['load_15min'] = round(loadavg[2], 2)
            else:
                # Fallback to /proc/loadavg
                with open('/proc/loadavg', 'r') as f:
                    loads = [float(x) for x in f.read().split()[:3]]
                    data['cpu']['load_1min'] = round(loads[0], 2)
                    data['cpu']['load_5min'] = round(loads[1], 2)
                    data['cpu']['load_15min'] = round(loads[2], 2)
        except Exception:
            pass

        # Get process count
        try:
            proc_count = len([d for d in os.listdir('/proc') if d.isdigit()])
            data['cpu']['process_count'] = proc_count
        except Exception:
            pass

        # Get CPU frequency (if available)
        try:
            with open('/proc/cpuinfo', 'r') as f:
                cpuinfo = f.read()
                # Try to find frequency
                import re
                freq_match = re.search(r'cpu MHz\s*:\s*([\d.]+)', cpuinfo)
                if freq_match:
                    freq_mhz = float(freq_match.group(1))
                    data['cpu']['frequency_mhz'] = round(freq_mhz, 0)
        except Exception:
            pass

        # Count CPU cores if not already set
        if 'cores' not in data['cpu']:
            try:
                with open('/proc/cpuinfo', 'r') as cf:
                    cores = len([l for l in cf.readlines() if l.startswith('processor')])
                data['cpu']['cores'] = max(cores, 1)
            except Exception:
                data['cpu']['cores'] = 1

        # If CPU percent still not set, use load average approximation as fallback
        if 'percent' not in data['cpu'] or data['cpu']['percent'] is None:
            if 'load_1min' in data['cpu'] and 'cores' in data['cpu']:
                cores = data['cpu']['cores']
                load = data['cpu']['load_1min']
                data['cpu']['percent'] = min(round((load / cores) * 100, 1), 100.0)
    except Exception as e:
        data['cpu'] = {'percent': 0, 'error': str(e)}

    # Memory Statistics - use /proc filesystem (Linux)
    try:
        import resource
        # Get process memory
        try:
            mem_kb = resource.getrusage(resource.RUSAGE_SELF).ru_maxrss
            # Linux returns KB
            mem_mb = mem_kb / 1024
            data['memory']['process_mb'] = round(mem_mb, 1)
        except Exception:
            pass

        # Get system memory from /proc/meminfo
        try:
            meminfo = {}
            with open('/proc/meminfo', 'r') as f:
                for line in f:
                    parts = line.split(':')
                    if len(parts) == 2:
                        key = parts[0].strip()
                        val = parts[1].strip().split()[0]
                        meminfo[key] = int(val)

            if 'MemTotal' in meminfo and 'MemAvailable' in meminfo:
                total_kb = meminfo['MemTotal']
                avail_kb = meminfo['MemAvailable']
                used_kb = total_kb - avail_kb
                data['memory']['total_gb'] = round(total_kb / (1024 * 1024), 2)
                data['memory']['used_gb'] = round(used_kb / (1024 * 1024), 2)
                data['memory']['available_gb'] = round(avail_kb / (1024 * 1024), 2)
                data['memory']['percent'] = round((used_kb / total_kb) * 100, 1) if total_kb > 0 else 0

                # Memory breakdown
                if 'MemFree' in meminfo:
                    data['memory']['free_gb'] = round(meminfo['MemFree'] / (1024 * 1024), 2)
                if 'Buffers' in meminfo:
                    data['memory']['buffers_gb'] = round(meminfo['Buffers'] / (1024 * 1024), 2)
                if 'Cached' in meminfo:
                    data['memory']['cached_gb'] = round(meminfo['Cached'] / (1024 * 1024), 2)

                # Memory pressure indicator
                if data['memory']['percent'] >= 90:
                    data['memory']['pressure'] = 'high'
                elif data['memory']['percent'] >= 75:
                    data['memory']['pressure'] = 'medium'
                else:
                    data['memory']['pressure'] = 'low'

            # Swap statistics
            if 'SwapTotal' in meminfo and 'SwapFree' in meminfo:
                swap_total_kb = meminfo['SwapTotal']
                swap_free_kb = meminfo['SwapFree']
                swap_used_kb = swap_total_kb - swap_free_kb
                if swap_total_kb > 0:
                    data['memory']['swap_total_gb'] = round(swap_total_kb / (1024 * 1024), 2)
                    data['memory']['swap_used_gb'] = round(swap_used_kb / (1024 * 1024), 2)
                    data['memory']['swap_free_gb'] = round(swap_free_kb / (1024 * 1024), 2)
                    data['memory']['swap_percent'] = round((swap_used_kb / swap_total_kb) * 100, 1)
        except Exception as e:
            pass
    except Exception as e:
        data['memory'] = {'error': str(e)}

    # Disk Statistics
    try:
        # Root filesystem
        root_disk = check_disk_space('/')
        data['disk']['root'] = root_disk

        # NetFlow data directory
        nfdump_disk = check_disk_space('/var/cache/nfdump')
        data['disk']['nfdump'] = nfdump_disk

        # Count nfdump files
        try:
            nfdump_dir = '/var/cache/nfdump'
            if os.path.exists(nfdump_dir):
                files = [f for f in os.listdir(nfdump_dir) if f.startswith('nfcapd.')]
                data['disk']['nfdump_files'] = len(files)
            else:
                data['disk']['nfdump_files'] = 0
        except Exception:
            data['disk']['nfdump_files'] = 0
    except Exception:
        data['disk'] = {'error': 'Unable to read disk stats'}

    # Syslog Statistics
    try:
        with _syslog_stats_lock:
            # Syslog is active if: thread is started (receiver is running)
            # If logs have been received, also check if last log was recent (within 5 min)
            last_log_ts = _syslog_stats.get('last_log')
            if last_log_ts:
                # If we have logs, check if they're recent
                syslog_active = (time.time() - last_log_ts) < 300
            else:
                # If no logs yet, consider active if thread is running (receiver is listening)
                syslog_active = state._syslog_thread_started

            data['syslog'] = {
                'received': _syslog_stats.get('received', 0),
                'parsed': _syslog_stats.get('parsed', 0),
                'errors': _syslog_stats.get('errors', 0),
                'last_log': last_log_ts,
                'active': syslog_active
            }
    except Exception:
        data['syslog'] = {'error': 'Unable to read syslog stats'}

    # NetFlow Statistics
    try:
        nfdump_dir = '/var/cache/nfdump'
        netflow_data = {
            'available': state._has_nfdump if state._has_nfdump is not None else False,
            'directory': nfdump_dir,
            'disk_usage': data['disk'].get('nfdump', {}),
            'files_count': data['disk'].get('nfdump_files', 0)
        }

        # Try to get nfdump version
        try:
            result = subprocess.run(['nfdump', '-V'], capture_output=True, text=True, timeout=2)
            if result.returncode == 0:
                version_line = result.stdout.split('\n')[0] if result.stdout else ''
                netflow_data['version'] = version_line.strip()
        except Exception:
            pass

        data['netflow'] = netflow_data
    except Exception:
        data['netflow'] = {'error': 'Unable to read NetFlow stats'}

    # Database Statistics
    try:
        with _firewall_db_lock:
            conn = _firewall_db_connect()
            try:
                # Get row count
                cursor = conn.execute("SELECT COUNT(*) FROM fw_logs")
                log_count = cursor.fetchone()[0]

                # Get database size
                db_path = FIREWALL_DB_PATH
                db_size = 0
                if os.path.exists(db_path):
                    db_size = os.path.getsize(db_path)

                db_info = {
                    'connected': True,
                    'log_count': log_count,
                    'size_mb': round(db_size / (1024 * 1024), 2),
                    'path': db_path
                }

                # Get records from last 24h and 1h for growth rate calculation
                try:
                    now = time.time()
                    cutoff_24h = now - 86400
                    cutoff_1h = now - 3600
                    cursor_24h = conn.execute("SELECT COUNT(*) FROM fw_logs WHERE timestamp > ?", (cutoff_24h,))
                    count_24h = cursor_24h.fetchone()[0]
                    cursor_1h = conn.execute("SELECT COUNT(*) FROM fw_logs WHERE timestamp > ?", (cutoff_1h,))
                    count_1h = cursor_1h.fetchone()[0]
                    db_info['logs_24h'] = count_24h
                    db_info['logs_1h'] = count_1h
                    db_info['growth_rate_per_hour'] = count_1h
                    db_info['growth_rate_per_day'] = count_24h
                except Exception:
                    pass

                data['database'] = db_info
            finally:
                conn.close()
    except Exception as e:
        data['database'] = {'connected': False, 'error': str(e)}

    # System Information (Uptime, Process Info)
    try:
        # Get system uptime from /proc/uptime
        try:
            with open('/proc/uptime', 'r') as f:
                uptime_seconds = float(f.read().split()[0])
                days = int(uptime_seconds // 86400)
                hours = int((uptime_seconds % 86400) // 3600)
                minutes = int((uptime_seconds % 3600) // 60)
                data['system']['uptime_seconds'] = int(uptime_seconds)
                data['system']['uptime_formatted'] = f"{days}d {hours}h {minutes}m"
        except Exception:
            data['system']['uptime_formatted'] = 'N/A'

        # Get process/thread information using /proc
        try:
            import glob
            pid = os.getpid()
            # Count threads in /proc/PID/task/
            thread_count = len([d for d in glob.glob(f'/proc/{pid}/task/*') if os.path.isdir(d)])
            data['system']['process_threads'] = thread_count

            # Get process name/command
            try:
                with open(f'/proc/{pid}/comm', 'r') as f:
                    data['system']['process_name'] = f.read().strip()
            except Exception:
                data['system']['process_name'] = 'python3'
        except Exception:
            data['system']['process_threads'] = 0

        # Get boot time
        try:
            with open('/proc/uptime', 'r') as f:
                uptime_seconds = float(f.read().split()[0])
            boot_time = time.time() - uptime_seconds
            data['system']['boot_time'] = datetime.fromtimestamp(boot_time).isoformat()
            data['system']['boot_time_formatted'] = datetime.fromtimestamp(boot_time).strftime('%Y-%m-%d %H:%M:%S')
        except Exception:
            pass

        # Get kernel version
        try:
            with open('/proc/version', 'r') as f:
                version_line = f.read().strip()
                # Extract kernel version (e.g., "Linux version 5.10.0-...")
                import re
                kernel_match = re.search(r'Linux version ([^\s]+)', version_line)
                if kernel_match:
                    data['system']['kernel_version'] = kernel_match.group(1)
                data['system']['os_info'] = version_line.split('(')[0].strip()
        except Exception:
            pass

        # Get hostname
        try:
            data['system']['hostname'] = socket.gethostname()
        except Exception:
            try:
                with open('/etc/hostname', 'r') as f:
                    data['system']['hostname'] = f.read().strip()
            except Exception:
                pass
    except Exception:
        data['system'] = {'error': 'Unable to read system stats'}

    # Network Statistics (from /proc/net/dev)
    try:
        interfaces = {}
        with open('/proc/net/dev', 'r') as f:
            for line in f:
                if ':' in line:
                    parts = line.split(':')
                    iface_name = parts[0].strip()
                    stats = parts[1].split()
                    if len(stats) >= 16:
                        interfaces[iface_name] = {
                            'rx_bytes': int(stats[0]),
                            'rx_packets': int(stats[1]),
                            'tx_bytes': int(stats[8]),
                            'tx_packets': int(stats[9])
                        }
        data['network'] = {'interfaces': interfaces}
    except Exception:
        data['network'] = {'interfaces': {}}

    # Cache Statistics
    try:
        with _cache_lock:
            data['cache'] = {
                'dns_cache_size': len(dns_module._dns_cache),
                'geo_cache_size': len(geoip_module._geo_cache),
                'common_cache_size': len(_common_data_cache),
                'bandwidth_history_size': len(_bandwidth_history_cache)
            }
    except Exception:
        data['cache'] = {}

    # Process/Application Metrics
    try:
        import resource
        pid = os.getpid()

        # Get process memory
        mem_kb = resource.getrusage(resource.RUSAGE_SELF).ru_maxrss
        mem_mb = mem_kb / 1024

        process_metrics = {
            'process_memory_mb': round(mem_mb, 1),
            'threads': data.get('system', {}).get('process_threads', 0)
        }

        # Get process stats from /proc/PID/stat
        try:
            with open(f'/proc/{pid}/stat', 'r') as f:
                stat_parts = f.read().split()
                if len(stat_parts) > 13:
                    # utime + stime = total CPU time
                    utime = int(stat_parts[13])
                    stime = int(stat_parts[14])
                    process_metrics['cpu_time'] = utime + stime
        except Exception:
            pass

        data['process'] = process_metrics
    except Exception:
        data['process'] = {}

    # Cache the result
    with _cache_lock:
        _server_health_cache["data"] = data
        _server_health_cache["ts"] = now

    return jsonify(data)


@bp.route("/api/performance/metrics")
@throttle(10, 60)
def api_performance_metrics():
    """Get performance metrics including observability data."""
    from app.services.shared.observability import check_cache_miss_rate
    
    # Check cache miss rate guardrail (triggers warning if threshold exceeded)
    check_cache_miss_rate()
    
    metrics = get_performance_metrics()

    # Calculate statistics
    avg_response_time = 0.0
    if metrics['request_count'] > 0:
        avg_response_time = metrics['total_response_time'] / metrics['request_count']

    # Calculate per-endpoint statistics
    endpoint_stats = {}
    for endpoint, times in metrics['endpoint_times'].items():
        if times:
            endpoint_stats[endpoint] = {
                'count': len(times),
                'avg_ms': round(sum(times) / len(times) * 1000, 2),
                'min_ms': round(min(times) * 1000, 2),
                'max_ms': round(max(times) * 1000, 2),
                'p95_ms': round(sorted(times)[int(len(times) * 0.95)] * 1000, 2) if len(times) > 1 else round(times[0] * 1000, 2)
            }

    cache_hit_rate = 0.0
    total_cache_requests = metrics['cache_hits'] + metrics['cache_misses']
    if total_cache_requests > 0:
        cache_hit_rate = metrics['cache_hits'] / total_cache_requests * 100

    error_rate = 0.0
    if metrics['request_count'] > 0:
        error_rate = metrics['error_count'] / metrics['request_count'] * 100
    
    # OBSERVABILITY: Subprocess metrics
    subprocess_stats = {}
    if metrics.get('subprocess_calls', 0) > 0:
        avg_subprocess_time = metrics['subprocess_total_time'] / metrics['subprocess_calls']
        subprocess_times = metrics.get('subprocess_times', [])
        subprocess_stats = {
            'total_calls': metrics['subprocess_calls'],
            'success_count': metrics.get('subprocess_success', 0),
            'failure_count': metrics.get('subprocess_failures', 0),
            'timeout_count': metrics.get('subprocess_timeouts', 0),
            'avg_ms': round(avg_subprocess_time * 1000, 2),
            'max_ms': round(max(subprocess_times) * 1000, 2) if subprocess_times else 0,
            'p95_ms': round(sorted(subprocess_times)[int(len(subprocess_times) * 0.95)] * 1000, 2) if len(subprocess_times) > 1 else (round(subprocess_times[0] * 1000, 2) if subprocess_times else 0),
            'success_rate_percent': round(metrics.get('subprocess_success', 0) / metrics['subprocess_calls'] * 100, 2) if metrics.get('subprocess_calls', 0) > 0 else 0
        }
    
    # OBSERVABILITY: Service function metrics
    service_stats = {}
    for service_name, times in metrics.get('service_times', {}).items():
        if times:
            calls = metrics['service_calls'].get(service_name, 0)
            total_time = metrics['service_total_time'].get(service_name, 0.0)
            service_stats[service_name] = {
                'call_count': calls,
                'avg_ms': round((total_time / calls) * 1000, 2) if calls > 0 else 0,
                'total_time_ms': round(total_time * 1000, 2),
                'min_ms': round(min(times) * 1000, 2),
                'max_ms': round(max(times) * 1000, 2),
                'p95_ms': round(sorted(times)[int(len(times) * 0.95)] * 1000, 2) if len(times) > 1 else round(times[0] * 1000, 2)
            }

    return jsonify({
        'summary': {
            'total_requests': metrics['request_count'],
            'avg_response_time_ms': round(avg_response_time * 1000, 2),
            'error_count': metrics['error_count'],
            'error_rate_percent': round(error_rate, 2),
            'cache_hit_rate_percent': round(cache_hit_rate, 2),
            'cache_hits': metrics['cache_hits'],
            'cache_misses': metrics['cache_misses'],
            'slow_requests': metrics.get('slow_requests', 0)
        },
        'endpoints': endpoint_stats,
        'subprocess': subprocess_stats,
        'services': service_stats
    })


@bp.route('/api/server/logs')
@throttle(10, 5)
def api_server_logs():
    """Get application logs from in-memory buffer, log files, or docker logs."""
    lines = request.args.get('lines', 100, type=int)
    lines = min(max(lines, 10), 1000)  # Limit between 10 and 1000 lines
    
    # First, try to get logs from in-memory buffer
    with _app_log_buffer_lock:
        if _app_log_buffer:
            log_lines = list(_app_log_buffer)[-lines:]
            log_lines.reverse()  # Newest first
            return jsonify({
                'logs': log_lines,
                'count': len(log_lines),
                'source': 'buffer',
                'container': ''
            })
    
    # Try docker logs (may not work from inside container)
    try:
        container_name = os.environ.get('CONTAINER_NAME', 'phobos-net')
        result = subprocess.run(
            ['docker', 'logs', '--tail', str(lines), container_name],
            capture_output=True,
            text=True,
            timeout=5
        )
        
        if result.returncode == 0 and result.stdout.strip():
            log_lines = [line for line in result.stdout.strip().split('\n') if line.strip()]
            log_lines.reverse()
            return jsonify({
                'logs': log_lines,
                'count': len(log_lines),
                'container': container_name,
                'source': 'docker'
            })
    except (FileNotFoundError, subprocess.TimeoutExpired, Exception):
        pass  # Fall through to file reading
    
    # Try reading from log files
    return _get_logs_from_files(lines)


def _get_logs_from_files(lines):
    """Fallback: try to read from application log files."""
    log_files = [
        '/var/log/app.log',
        '/app/app.log',
        '/tmp/app.log',
        '/var/log/phobos-net.log',
        '/var/log/gunicorn/access.log',
        '/var/log/gunicorn/error.log'
    ]
    
    all_lines = []
    for log_file in log_files:
        try:
            if os.path.exists(log_file):
                with open(log_file, 'r', encoding='utf-8', errors='ignore') as f:
                    file_lines = f.readlines()
                    all_lines.extend([(log_file, line.strip()) for line in file_lines if line.strip()])
        except Exception:
            continue
    
    if all_lines:
        # Sort by file and take last N lines
        all_lines = all_lines[-lines:]
        log_lines = [f"[{os.path.basename(f)}] {line}" for f, line in all_lines]
        return jsonify({
            'logs': log_lines,
            'count': len(log_lines),
            'source': 'files'
        })
    
    # Check if we have any logs in buffer
    with _app_log_buffer_lock:
        if _app_log_buffer:
            log_lines = list(_app_log_buffer)[-lines:]
            log_lines.reverse()
            return jsonify({
                'logs': log_lines,
                'count': len(log_lines),
                'source': 'buffer'
            })
    
    # No logs available
    return jsonify({
        'logs': ['No logs available. Application logs will appear here as they are generated.'],
        'count': 1,
        'source': 'none',
        'message': 'No logs found. Logs will be captured as the application runs.'
    })


@bp.route('/api/server/database-stats')
@throttle(10, 5)
def api_database_stats():
    """Get read-only SQLite database statistics."""
    from app.config import TRENDS_DB_PATH, FIREWALL_DB_PATH
    from app.db.sqlite import _trends_db_connect, _firewall_db_connect, get_db_size_history
    import os
    import time as time_module
    
    def get_db_stats(db_path, db_name, connect_func):
        """Get statistics for a single database."""
        stats = {
            'name': db_name,
            'path': db_path,
            'exists': os.path.exists(db_path) if db_path else False,
            'file_size': 0,
            'wal_size': 0,
            'wal_exists': False,
            'total_records': 0,
            'sqlite_version': None,
            'journal_mode': None,
            'synchronous': None,
            'page_size': None,
            'cache_size': None,
            'foreign_keys': None,
            'last_write': None,
            'error': None
        }
        
        if not db_path or not os.path.exists(db_path):
            stats['error'] = 'Database file not found'
            return stats
        
        try:
            # File system metadata
            file_stat = os.stat(db_path)
            stats['file_size'] = file_stat.st_size
            stats['last_write'] = datetime.fromtimestamp(file_stat.st_mtime).isoformat()
            
            # Check for WAL file
            wal_path = db_path + '-wal'
            if os.path.exists(wal_path):
                stats['wal_exists'] = True
                wal_stat = os.stat(wal_path)
                stats['wal_size'] = wal_stat.st_size
            
            # PRAGMA queries (read-only)
            conn = connect_func()
            try:
                # SQLite version
                cur = conn.execute("SELECT sqlite_version()")
                stats['sqlite_version'] = cur.fetchone()[0]
                
                # Journal mode
                cur = conn.execute("PRAGMA journal_mode")
                stats['journal_mode'] = cur.fetchone()[0]
                
                # Synchronous mode
                cur = conn.execute("PRAGMA synchronous")
                sync_val = cur.fetchone()[0]
                sync_map = {0: 'OFF', 1: 'NORMAL', 2: 'FULL', 3: 'EXTRA'}
                stats['synchronous'] = sync_map.get(sync_val, str(sync_val))
                
                # Page size
                cur = conn.execute("PRAGMA page_size")
                stats['page_size'] = cur.fetchone()[0]
                
                # Cache size (in pages)
                cur = conn.execute("PRAGMA cache_size")
                stats['cache_size'] = cur.fetchone()[0]
                
                # Foreign keys
                cur = conn.execute("PRAGMA foreign_keys")
                stats['foreign_keys'] = bool(cur.fetchone()[0])
                
                # Approximate total records (sum of row counts from all tables)
                # This is a safe read-only query
                cur = conn.execute("""
                    SELECT name FROM sqlite_master 
                    WHERE type='table' AND name NOT LIKE 'sqlite_%'
                """)
                tables = [row[0] for row in cur.fetchall()]
                
                total_records = 0
                for table in tables:
                    try:
                        cur = conn.execute(f"SELECT COUNT(*) FROM {table}")
                        count = cur.fetchone()[0]
                        total_records += count
                    except:
                        pass  # Skip tables we can't read
                
                stats['total_records'] = total_records
                
                # Find oldest record timestamp across all tables
                oldest_ts = None
                for table in tables:
                    try:
                        # Try common timestamp column names
                        for ts_col in ['timestamp', 'bucket_end', 'hour_ts', 'first_seen_ts']:
                            try:
                                cur = conn.execute(f"SELECT MIN({ts_col}) FROM {table} WHERE {ts_col} IS NOT NULL")
                                row = cur.fetchone()
                                if row and row[0] is not None:
                                    ts_val = row[0]
                                    # Convert to float if it's numeric
                                    if isinstance(ts_val, (int, float)):
                                        if oldest_ts is None or ts_val < oldest_ts:
                                            oldest_ts = ts_val
                                    break
                            except:
                                continue  # Column doesn't exist in this table
                    except:
                        pass  # Skip tables we can't query
                
                # Calculate age of oldest record
                if oldest_ts is not None:
                    now = time.time()
                    age_seconds = now - oldest_ts
                    stats['oldest_record_age_seconds'] = age_seconds
                    # Format as human-readable (days, hours, minutes)
                    if age_seconds >= 86400:  # >= 1 day
                        days = int(age_seconds // 86400)
                        hours = int((age_seconds % 86400) // 3600)
                        if days >= 7:
                            stats['oldest_record_age'] = f"{days} days"
                        else:
                            stats['oldest_record_age'] = f"{days}d {hours}h"
                    elif age_seconds >= 3600:  # >= 1 hour
                        hours = int(age_seconds // 3600)
                        minutes = int((age_seconds % 3600) // 60)
                        stats['oldest_record_age'] = f"{hours}h {minutes}m"
                    else:
                        minutes = int(age_seconds // 60)
                        stats['oldest_record_age'] = f"{minutes}m"
                else:
                    stats['oldest_record_age'] = None
                
            finally:
                conn.close()
            
            # Get historical file size samples for sparkline (read-only, no writes)
            # Sampling is handled by background thread, not during API requests
            history = get_db_size_history(db_path, limit=100)
            stats['size_history'] = [h['file_size'] for h in history]
            
            # Calculate write-pressure hint (qualitative: normal / elevated)
            # Compare recent growth rate vs historical baseline
            write_pressure = 'normal'
            if len(history) >= 10:  # Need enough history for baseline
                # Recent activity: last 5 samples
                recent_samples = history[-5:] if len(history) >= 5 else history
                recent_growth = 0
                if len(recent_samples) > 1:
                    recent_growth = (recent_samples[-1]['file_size'] - recent_samples[0]['file_size']) / max(len(recent_samples) - 1, 1)
                
                # Historical baseline: all samples except recent
                baseline_samples = history[:-5] if len(history) >= 5 else []
                baseline_growth = 0
                if len(baseline_samples) > 1:
                    baseline_growth = (baseline_samples[-1]['file_size'] - baseline_samples[0]['file_size']) / max(len(baseline_samples) - 1, 1)
                
                # Only flag as elevated if sustained deviation (recent > 2x baseline and baseline > 0)
                if baseline_growth > 0 and recent_growth > (baseline_growth * 2):
                    write_pressure = 'elevated'
                # Also flag if baseline was stable (near zero) but recent shows significant growth
                elif baseline_growth <= 0 and recent_growth > (stats['file_size'] * 0.01):  # >1% of current size
                    write_pressure = 'elevated'
            
            stats['write_pressure'] = write_pressure
                
        except Exception as e:
            stats['error'] = str(e)
        
        return stats
    
    # Get stats for both databases
    trends_stats = get_db_stats(TRENDS_DB_PATH, 'Trends', _trends_db_connect)
    firewall_stats = get_db_stats(FIREWALL_DB_PATH, 'Firewall', _firewall_db_connect)
    
    return jsonify({
        'databases': [trends_stats, firewall_stats],
        'timestamp': datetime.now().isoformat()
    })


# ============================================
# TOOLS API ENDPOINTS
# ============================================
from app.services.shared.tools import dns_lookup, port_check, ping_host, check_reputation, whois_lookup

@bp.route('/api/tools/dns')
def api_tools_dns():
    """DNS lookup tool."""
    query = request.args.get('query', '')
    record_type = request.args.get('type', 'A')
    result = dns_lookup(query, record_type)
    return jsonify(result)

@bp.route('/api/tools/port-check')
def api_tools_port_check():
    """Port check tool."""
    host = request.args.get('host', '')
    ports = request.args.get('ports', '')
    result = port_check(host, ports)
    return jsonify(result)

@bp.route('/api/tools/ping')
def api_tools_ping():
    """Ping/traceroute tool."""
    host = request.args.get('host', '')
    mode = request.args.get('mode', 'ping')
    result = ping_host(host, mode)
    return jsonify(result)

@bp.route('/api/tools/reputation')
def api_tools_reputation():
    """IP reputation check tool."""
    ip = request.args.get('ip', '')
    # Get threat feeds from app state if available
    threat_feeds = getattr(current_app, 'threat_feeds', None) or threats_module.load_threatlist()
    result = check_reputation(ip, threat_feeds)
    return jsonify(result)

@bp.route('/api/tools/whois')
def api_tools_whois():
    """Whois/ASN lookup tool."""
    query = request.args.get('query', '')
    result = whois_lookup(query)
    return jsonify(result)


@bp.route('/api/tools/shell', methods=['POST'])
def api_tools_shell():
    """Execute shell command on the server.
    
    Security: Commands are executed with timeout and output limits.
    This is intended for network diagnostics only.
    """
    data = request.get_json(force=True, silent=True) or {}
    command = data.get('command', '').strip()
    
    if not command:
        return jsonify({'error': 'No command provided', 'output': ''}), 400
    
    # Security: Limit command length
    if len(command) > 500:
        return jsonify({'error': 'Command too long (max 500 chars)', 'output': ''}), 400
    
    # Security: Block dangerous commands
    blocked_patterns = [
        'rm -rf', 'rm -r /', 'mkfs', 'dd if=', ':(){', 'chmod 777', 
        'wget', 'curl -o', '> /dev/', 'shutdown', 'reboot', 'halt',
        'passwd', 'useradd', 'userdel', 'visudo', 'sudo su', 
        '> /etc/', '>> /etc/', 'mv /etc/', 'rm /etc/'
    ]
    command_lower = command.lower()
    for pattern in blocked_patterns:
        if pattern in command_lower:
            return jsonify({'error': f'Blocked: dangerous command pattern detected', 'output': ''}), 403
    
    try:
        # Prepare environment with expanded PATH
        env = os.environ.copy()
        env['PATH'] = '/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin:' + env.get('PATH', '')
        
        # Execute with timeout and capture output
        # Use executable='/bin/bash' if available to ensure standard shell behavior
        shell_exec = '/bin/bash' if os.path.exists('/bin/bash') else '/bin/sh'
        
        result = subprocess.run(
            command,
            shell=True,
            executable=shell_exec,
            capture_output=True,
            text=True,
            timeout=30,  # 30 second timeout
            cwd='/tmp',  # Safe working directory
            env=env      # Expanded PATH
        )
        
        output = result.stdout
        if result.stderr:
            output += '\n' + result.stderr if output else result.stderr
        
        # Limit output size
        if len(output) > 50000:
            output = output[:50000] + '\n\n... (output truncated at 50KB)'
        
        return jsonify({
            'output': output or '(no output)',
            'exit_code': result.returncode,
            'error': None
        })
        
    except subprocess.TimeoutExpired:
        return jsonify({
            'output': '',
            'exit_code': -1,
            'error': 'Command timed out after 30 seconds'
        })
    except Exception as e:
        return jsonify({
            'output': '',
            'exit_code': -1,
            'error': str(e)
        })
