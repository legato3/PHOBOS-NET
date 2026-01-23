"""Thread management functions for PHOBOS-NET application.

This module contains functions to start background threads that perform
periodic tasks like fetching threat feeds, aggregating data, and managing trends.
"""
import threading
import time
from datetime import datetime, timedelta
from concurrent.futures import ThreadPoolExecutor

# Import state module to modify thread flags
import app.core.app_state as state
from app.core.app_state import (
    _shutdown_event,
    _common_data_lock,
    _common_data_cache,
    add_app_log,
    update_thread_health,
    update_dependency_health,
)

# Import config
from app.config import CACHE_TTL_THREAT, CACHE_TTL_SHORT

# Import service functions
from app.services.security.threats import fetch_threat_feed
from app.services.netflow.netflow import parse_csv, run_nfdump
from app.services.shared.helpers import get_time_range
from app.db.sqlite import _trends_db_init, _get_bucket_end, _ensure_rollup_for_bucket, update_db_size_history
from app.config import TRENDS_DB_PATH, FIREWALL_DB_PATH


def start_threat_thread():
    """Start the threat feed update thread."""
    if state._threat_thread_started:
        return
    state._threat_thread_started = True
    def loop():
        while not _shutdown_event.is_set():
            start_time = time.time()
            try:
                fetch_threat_feed()
                exec_time_ms = (time.time() - start_time) * 1000
                update_thread_health('ThreatFeedThread', success=True, execution_time_ms=exec_time_ms)
            except Exception as e:
                exec_time_ms = (time.time() - start_time) * 1000
                update_thread_health('ThreatFeedThread', success=False, execution_time_ms=exec_time_ms, error_msg=str(e))
            # Use wait instead of sleep for faster shutdown
            _shutdown_event.wait(timeout=CACHE_TTL_THREAT)
    t = threading.Thread(target=loop, daemon=True, name='ThreatFeedThread')
    t.start()


def start_trends_thread():
    """Start the trends aggregation thread."""
    if state._trends_thread_started:
        return
    state._trends_thread_started = True
    _trends_db_init()

    def loop():
        while not _shutdown_event.is_set():
            start_time = time.time()
            try:
                # Work on the last completed bucket (avoid partial current)
                now_dt = datetime.now()
                current_end = _get_bucket_end(now_dt)
                last_completed_end = current_end - timedelta(minutes=5)
                _ensure_rollup_for_bucket(last_completed_end)
                exec_time_ms = (time.time() - start_time) * 1000
                update_thread_health('TrendsThread', success=True, execution_time_ms=exec_time_ms)
            except Exception as e:
                exec_time_ms = (time.time() - start_time) * 1000
                update_thread_health('TrendsThread', success=False, execution_time_ms=exec_time_ms, error_msg=str(e))
            _shutdown_event.wait(timeout=CACHE_TTL_SHORT)

    t = threading.Thread(target=loop, daemon=True, name='TrendsThread')
    t.start()


def start_agg_thread():
    """Background aggregator to precompute common nfdump data for 1h range every 60s."""
    if state._agg_thread_started:
        return
    state._agg_thread_started = True

    def loop():
        while not _shutdown_event.is_set():
            start_time = time.time()
            try:
                range_key = '1h'
                tf = get_time_range(range_key)
                now_ts = time.time()
                win = int(now_ts // 60)

                # Parallelize nfdump calls to speed up aggregation
                def fetch_sources():
                    data = parse_csv(run_nfdump(["-s","srcip/bytes/flows/packets","-n","100"], tf), expected_key='sa')
                    data.sort(key=lambda x: x.get("bytes", 0), reverse=True)
                    return data

                def fetch_ports():
                    data = parse_csv(run_nfdump(["-s","dstport/bytes/flows","-n","100"], tf), expected_key='dp')
                    data.sort(key=lambda x: x.get("bytes", 0), reverse=True)
                    return data

                def fetch_dests():
                    data = parse_csv(run_nfdump(["-s","dstip/bytes/flows/packets","-n","100"], tf), expected_key='da')
                    data.sort(key=lambda x: x.get("bytes", 0), reverse=True)
                    return data

                def fetch_protos():
                    return parse_csv(run_nfdump(["-s","proto/bytes/flows/packets","-n","20"], tf), expected_key='proto')

                with ThreadPoolExecutor(max_workers=4) as executor:
                    f_sources = executor.submit(fetch_sources)
                    f_ports = executor.submit(fetch_ports)
                    f_dests = executor.submit(fetch_dests)
                    f_protos = executor.submit(fetch_protos)

                    sources = f_sources.result()
                    ports = f_ports.result()
                    dests = f_dests.result()
                    protos = f_protos.result()

                with _common_data_lock:
                    _common_data_cache[f"sources:{range_key}:{win}"] = {"data": sources, "ts": now_ts, "win": win}
                    _common_data_cache[f"ports:{range_key}:{win}"] = {"data": ports, "ts": now_ts, "win": win}
                    _common_data_cache[f"dests:{range_key}:{win}"] = {"data": dests, "ts": now_ts, "win": win}
                    _common_data_cache[f"protos:{range_key}:{win}"] = {"data": protos, "ts": now_ts, "win": win}
                exec_time_ms = (time.time() - start_time) * 1000
                update_thread_health('AggregationThread', success=True, execution_time_ms=exec_time_ms)
            except Exception as e:
                exec_time_ms = (time.time() - start_time) * 1000
                update_thread_health('AggregationThread', success=False, execution_time_ms=exec_time_ms, error_msg=str(e))
                add_app_log(f"Agg thread error: {e}", 'ERROR')

            # Align next run to the minute boundary to prevent drift
            now = time.time()
            next_minute = (int(now) // 60 + 1) * 60
            sleep_time = max(1, next_minute - now)
            _shutdown_event.wait(timeout=sleep_time)

    t = threading.Thread(target=loop, daemon=True, name='AggregationThread')
    t.start()


def start_db_size_sampler_thread():
    """Start the database file size sampling thread.

    Samples database file sizes at fixed intervals (60s) and stores them
    in a bounded buffer. This runs independently of API requests to avoid
    write operations during GET handlers.
    """
    if state._db_size_sampler_thread_started:
        return
    state._db_size_sampler_thread_started = True

    def loop():
        while not _shutdown_event.is_set():
            start_time = time.time()
            try:
                import os

                # Sample Trends database
                if TRENDS_DB_PATH and os.path.exists(TRENDS_DB_PATH):
                    try:
                        file_size = os.stat(TRENDS_DB_PATH).st_size
                        update_db_size_history('Trends', TRENDS_DB_PATH, file_size)
                    except Exception:
                        pass  # Silently skip if sampling fails

                # Sample Firewall database
                if FIREWALL_DB_PATH and os.path.exists(FIREWALL_DB_PATH):
                    try:
                        file_size = os.stat(FIREWALL_DB_PATH).st_size
                        update_db_size_history('Firewall', FIREWALL_DB_PATH, file_size)
                    except Exception:
                        pass  # Silently skip if sampling fails

                exec_time_ms = (time.time() - start_time) * 1000
                update_thread_health('DbSizeSamplerThread', success=True, execution_time_ms=exec_time_ms)
            except Exception as e:
                exec_time_ms = (time.time() - start_time) * 1000
                update_thread_health('DbSizeSamplerThread', success=False, execution_time_ms=exec_time_ms, error_msg=str(e))

            # Fixed 60-second interval
            _shutdown_event.wait(timeout=60)

    t = threading.Thread(target=loop, daemon=True, name='DbSizeSamplerThread')
    t.start()


def start_resource_sampler_thread():
    """Start the resource sampling thread for CPU/Memory history.

    Samples CPU and memory usage at fixed intervals (60s) and stores them
    in a bounded deque for historical charting on the Server page.
    """
    if state._resource_sampler_thread_started:
        return
    state._resource_sampler_thread_started = True

    def loop():
        while not _shutdown_event.is_set():
            start_time = time.time()
            try:
                sample = {
                    'ts': time.time(),
                    'cpu_percent': None,
                    'mem_percent': None,
                    'load_1min': None
                }

                # Get CPU percent from /proc/stat
                try:
                    from app.services.shared.cpu import calculate_cpu_percent_from_stat
                    cpu_percent, _, _ = calculate_cpu_percent_from_stat()
                    if cpu_percent is not None:
                        sample['cpu_percent'] = round(cpu_percent, 1)
                except Exception:
                    pass

                # Get memory percent from /proc/meminfo
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
                        sample['mem_percent'] = round((used_kb / total_kb) * 100, 1) if total_kb > 0 else 0
                except Exception:
                    pass

                # Get load average
                try:
                    import os
                    loadavg = os.getloadavg() if hasattr(os, 'getloadavg') else None
                    if loadavg:
                        sample['load_1min'] = round(loadavg[0], 2)
                except Exception:
                    pass

                # Store sample
                with state._resource_history_lock:
                    state._resource_history.append(sample)

                exec_time_ms = (time.time() - start_time) * 1000
                update_thread_health('ResourceSamplerThread', success=True, execution_time_ms=exec_time_ms)
            except Exception as e:
                exec_time_ms = (time.time() - start_time) * 1000
                update_thread_health('ResourceSamplerThread', success=False, execution_time_ms=exec_time_ms, error_msg=str(e))

            # Fixed 60-second interval
            _shutdown_event.wait(timeout=60)

    t = threading.Thread(target=loop, daemon=True, name='ResourceSamplerThread')
    t.start()


def start_network_io_sampler_thread():
    """Start the network I/O sampling thread.

    Samples network interface statistics at fixed intervals (5s) and calculates
    bandwidth rates (bytes/sec, packets/sec) for monitoring.
    """
    if state._network_io_sampler_started:
        return
    state._network_io_sampler_started = True

    def parse_proc_net_dev():
        """Parse /proc/net/dev for interface statistics."""
        interfaces = {}
        try:
            with open('/proc/net/dev', 'r') as f:
                lines = f.readlines()[2:]  # Skip header lines
                for line in lines:
                    parts = line.split(':')
                    if len(parts) == 2:
                        iface = parts[0].strip()
                        values = parts[1].split()
                        if len(values) >= 16:
                            interfaces[iface] = {
                                'rx_bytes': int(values[0]),
                                'rx_packets': int(values[1]),
                                'rx_errors': int(values[2]),
                                'rx_dropped': int(values[3]),
                                'tx_bytes': int(values[8]),
                                'tx_packets': int(values[9]),
                                'tx_errors': int(values[10]),
                                'tx_dropped': int(values[11]),
                            }
        except Exception:
            pass
        return interfaces

    def loop():
        while not _shutdown_event.is_set():
            try:
                now = time.time()
                interfaces = parse_proc_net_dev()

                with state._network_io_lock:
                    prev_ts = state._network_io_metrics['timestamp']
                    prev_ifaces = state._network_io_metrics['interfaces']

                    # Calculate rates if we have previous data
                    if prev_ts > 0 and prev_ifaces:
                        interval = now - prev_ts
                        if interval > 0:
                            rates = {}
                            for iface, data in interfaces.items():
                                if iface in prev_ifaces:
                                    prev = prev_ifaces[iface]
                                    rates[iface] = {
                                        'rx_bytes_sec': round((data['rx_bytes'] - prev['rx_bytes']) / interval, 1),
                                        'tx_bytes_sec': round((data['tx_bytes'] - prev['tx_bytes']) / interval, 1),
                                        'rx_packets_sec': round((data['rx_packets'] - prev['rx_packets']) / interval, 1),
                                        'tx_packets_sec': round((data['tx_packets'] - prev['tx_packets']) / interval, 1),
                                        'rx_errors': data['rx_errors'],
                                        'tx_errors': data['tx_errors'],
                                        'rx_dropped': data['rx_dropped'],
                                        'tx_dropped': data['tx_dropped'],
                                    }
                            state._network_io_metrics['rates'] = rates

                    # Store current sample
                    state._network_io_metrics['prev_timestamp'] = prev_ts
                    state._network_io_metrics['prev_interfaces'] = prev_ifaces
                    state._network_io_metrics['timestamp'] = now
                    state._network_io_metrics['interfaces'] = interfaces

            except Exception:
                pass

            # 5-second interval for responsive bandwidth monitoring
            _shutdown_event.wait(timeout=5)

    t = threading.Thread(target=loop, daemon=True, name='NetworkIOSamplerThread')
    t.start()


def start_dependency_health_thread():
    """Start the dependency health check thread.

    Periodically checks health of external services using application-level
    indicators (file activity, stats) rather than /proc which doesn't work
    well in containers.
    """
    import os
    import glob
    from app.config import NFCAPD_DIR as NETFLOW_DIR

    def check_nfcapd():
        """Check if nfcapd is collecting data by checking file freshness."""
        result = {
            'running': False,
            'latest_file_age_sec': None,
            'files_count': 0,
            'last_check': time.time()
        }

        try:
            # 1. Binary Check (is nfdump installed/runnable?)
            # This is set in run_nfdump -> state._has_nfdump
            is_installed = getattr(state, '_has_nfdump', False)

            # 2. Data Freshness Check (are files being rotated?)
            if NETFLOW_DIR and os.path.exists(NETFLOW_DIR):
                files = glob.glob(os.path.join(NETFLOW_DIR, 'nfcapd.*'))
                result['files_count'] = len(files)
                if files:
                    latest_file = max(files, key=os.path.getmtime)
                    mtime = os.path.getmtime(latest_file)
                    age = time.time() - mtime
                    result['latest_file_age_sec'] = round(age, 1)
                    
                    # CONSIDERED RUNNING IF:
                    # - nfdump binary works (is_installed)
                    # - AND recent file activity (< 10 mins)
                    #   (nfcapd rotates every 5 mins usually, allow buffer)
                    result['running'] = is_installed and (age < 600)
                else:
                    # No files yet, but if binary exists we assume it's starting up
                    result['running'] = is_installed
            else:
                result['running'] = False
        except Exception:
            pass

        return result

    def check_syslog_health():
        """Check syslog listener health using strict application thread flags."""
        results = {
            'syslog_514': {'listening': False, 'received': 0},
            'syslog_515': {'listening': False, 'received': 0}
        }

        # Check port 514 (Standard Syslog)
        try:
            # Rely on thread flag AND recent activity
            status_514 = getattr(state, '_syslog_thread_started', False)
            
            with state._syslog_stats_lock:
                rec_514 = state._syslog_stats.get('received', 0)
                last_log = state._syslog_stats.get('last_log')
            
            # If we have recent logs (< 5 mins), we are definitely active
            has_recent = last_log and (time.time() - last_log < 300)
            
            results['syslog_514']['listening'] = status_514 or has_recent
            results['syslog_514']['received'] = rec_514
            results['syslog_514']['last_packet_time'] = last_log
        except Exception as e:
            add_app_log(f"Syslog 514 check error: {e}", 'DEBUG')

        # Check port 515 (Firewall Syslog)
        try:
            import app.services.syslog.firewall_listener as fw_listener
            status_515 = getattr(fw_listener, '_firewall_syslog_thread_started', False)
            
            try:
                from app.services.syslog.syslog_store import syslog_store
                stats = syslog_store.get_stats()
                rec_515 = stats.get('total_received', 0)
                last_log_515 = stats.get('last_log_ts')
            except:
                rec_515 = 0
                last_log_515 = None

            has_recent_515 = last_log_515 and (time.time() - last_log_515 < 300)

            results['syslog_515']['listening'] = status_515 or has_recent_515
            results['syslog_515']['received'] = rec_515
            results['syslog_515']['last_packet_time'] = last_log_515
        except Exception as e:
            add_app_log(f"Syslog 515 check error: {e}", 'DEBUG')

        return results

    def loop():
        # Wait for startup
        _shutdown_event.wait(timeout=10)

        while not _shutdown_event.is_set():
            try:
                # Check nfcapd via file freshness and binary status
                nfcapd_health = check_nfcapd()
                update_dependency_health('nfcapd', **nfcapd_health)

                # Check syslog listeners via thread flags
                syslog_health = check_syslog_health()
                update_dependency_health('syslog_514', **syslog_health['syslog_514'])
                update_dependency_health('syslog_515', **syslog_health['syslog_515'])

            except Exception as e:
                add_app_log(f"Dependency health check error: {e}", 'ERROR')

            # Check every 15 seconds
            _shutdown_event.wait(timeout=15)

    t = threading.Thread(target=loop, daemon=True, name='DependencyHealthThread')
    t.start()


def start_container_metrics_thread():
    """Start the container metrics sampling thread.

    Collects Docker container-specific metrics from cgroup filesystem.
    Works with both cgroup v1 and v2. Also collects extended container info.
    """
    import os
    import subprocess
    import json

    def is_containerized():
        """Detect if running inside a container using multiple indicators."""
        # Check for Docker/.dockerenv file (most reliable for Docker)
        if os.path.exists('/.dockerenv'):
            return True

        # Check for container runtime files
        if os.path.exists('/run/.containerenv'):  # Podman
            return True

        # Check cgroup for docker/lxc/k8s (cgroup v1 format)
        try:
            with open('/proc/1/cgroup', 'r') as f:
                content = f.read().lower()
                if 'docker' in content or 'lxc' in content or 'kubepods' in content or 'containerd' in content:
                    return True
        except Exception:
            pass

        # Check /proc/1/cpuset for container ID (works in both cgroup v1 and v2)
        try:
            with open('/proc/1/cpuset', 'r') as f:
                content = f.read().strip()
                # In Docker, this shows /docker/<container-id> or just /<container-id>
                if content != '/' and len(content) > 1:
                    return True
        except Exception:
            pass

        # Check /proc/1/mountinfo for overlay filesystems (Docker uses overlayfs)
        try:
            with open('/proc/1/mountinfo', 'r') as f:
                content = f.read().lower()
                if 'overlay' in content or '/docker/' in content or 'containerd' in content:
                    return True
        except Exception:
            pass

        # Check if /proc/1/sched contains something other than init
        try:
            with open('/proc/1/sched', 'r') as f:
                first_line = f.readline()
                # In containers, PID 1 is usually not 'init' or 'systemd'
                if not any(x in first_line.lower() for x in ['init', 'systemd']):
                    return True
        except Exception:
            pass

        # Check for cgroup v2 with memory limits (containerized environments typically have limits)
        try:
            mem_max_path = '/sys/fs/cgroup/memory.max'
            if os.path.exists(mem_max_path):
                with open(mem_max_path, 'r') as f:
                    val = f.read().strip()
                    # If there's a numeric limit (not 'max'), we're likely in a container
                    if val != 'max':
                        return True
        except Exception:
            pass

        # Check cgroup v1 memory limit
        try:
            mem_limit_path = '/sys/fs/cgroup/memory/memory.limit_in_bytes'
            if os.path.exists(mem_limit_path):
                with open(mem_limit_path, 'r') as f:
                    limit = int(f.read().strip())
                    # If limit is less than 100GB, likely containerized
                    if limit < 100 * 1024 * 1024 * 1024:
                        return True
        except Exception:
            pass

        return False

    def get_container_id():
        """Get the container ID from cgroup or hostname."""
        container_id = None
        
        # Try from /proc/self/cgroup
        try:
            with open('/proc/self/cgroup', 'r') as f:
                for line in f:
                    # Format: hierarchy-ID:controller-list:cgroup-path
                    # Docker containers have paths like /docker/<container-id>
                    parts = line.strip().split(':')
                    if len(parts) >= 3:
                        cgroup_path = parts[2]
                        if '/docker/' in cgroup_path:
                            container_id = cgroup_path.split('/docker/')[-1].split('/')[0]
                            if len(container_id) >= 12:
                                break
                        elif '/containerd/' in cgroup_path:
                            container_id = cgroup_path.split('/')[-1]
                            if len(container_id) >= 12:
                                break
        except Exception:
            pass
        
        # Fallback to hostname (Docker sets hostname to container ID by default)
        if not container_id:
            try:
                import socket
                hostname = socket.gethostname()
                # Container IDs are 64 chars, but hostname is typically 12 chars
                if len(hostname) == 12 and all(c in '0123456789abcdef' for c in hostname):
                    container_id = hostname
            except Exception:
                pass
        
        return container_id

    def get_docker_container_info(container_id):
        """Get extended container info from Docker socket if available."""
        info = {}
        if not container_id:
            return info
        
        # Try using docker CLI (faster and works without socket mounting)
        try:
            result = subprocess.run(
                ['docker', 'inspect', container_id[:12], '--format', 
                 '{{json .}}'],
                capture_output=True, text=True, timeout=2
            )
            if result.returncode == 0:
                data = json.loads(result.stdout)
                
                # Container lifecycle
                if 'Created' in data:
                    info['container_created'] = data['Created']
                if 'State' in data:
                    state_data = data['State']
                    if 'StartedAt' in state_data:
                        info['container_started'] = state_data['StartedAt']
                    if 'Health' in state_data:
                        health = state_data['Health']
                        info['health_status'] = health.get('Status')
                        info['health_failing_streak'] = health.get('FailingStreak', 0)
                
                # Image info
                if 'Config' in data and 'Image' in data['Config']:
                    image = data['Config']['Image']
                    if ':' in image:
                        parts = image.rsplit(':', 1)
                        info['image_name'] = parts[0]
                        info['image_tag'] = parts[1]
                    else:
                        info['image_name'] = image
                        info['image_tag'] = 'latest'
                
                # Restart count
                if 'RestartCount' in data:
                    info['restart_count'] = data['RestartCount']
                
        except (FileNotFoundError, subprocess.TimeoutExpired, json.JSONDecodeError, Exception):
            pass
        
        return info

    def read_cgroup_v2():
        """Read metrics from cgroup v2 (unified hierarchy)."""
        metrics = {}
        try:
            # Memory current usage
            mem_current = '/sys/fs/cgroup/memory.current'
            mem_max = '/sys/fs/cgroup/memory.max'
            if os.path.exists(mem_current):
                with open(mem_current, 'r') as f:
                    metrics['memory_usage_bytes'] = int(f.read().strip())
            if os.path.exists(mem_max):
                with open(mem_max, 'r') as f:
                    val = f.read().strip()
                    if val != 'max':
                        metrics['memory_limit_bytes'] = int(val)

            # Memory breakdown (cache, RSS) from memory.stat
            mem_stat = '/sys/fs/cgroup/memory.stat'
            if os.path.exists(mem_stat):
                with open(mem_stat, 'r') as f:
                    for line in f:
                        parts = line.strip().split()
                        if len(parts) == 2:
                            if parts[0] == 'file':  # File cache
                                metrics['memory_cache_bytes'] = int(parts[1])
                            elif parts[0] == 'anon':  # RSS (anonymous memory)
                                metrics['memory_rss_bytes'] = int(parts[1])

            # CPU stats
            cpu_stat = '/sys/fs/cgroup/cpu.stat'
            if os.path.exists(cpu_stat):
                with open(cpu_stat, 'r') as f:
                    for line in f:
                        parts = line.strip().split()
                        if len(parts) == 2:
                            if parts[0] == 'usage_usec':
                                metrics['cpu_usage_ns'] = int(parts[1]) * 1000
                            elif parts[0] == 'nr_throttled':
                                metrics['cpu_throttled_periods'] = int(parts[1])
                            elif parts[0] == 'throttled_usec':
                                metrics['cpu_throttled_time_ns'] = int(parts[1]) * 1000

            # PIDs
            pids_current = '/sys/fs/cgroup/pids.current'
            pids_max = '/sys/fs/cgroup/pids.max'
            if os.path.exists(pids_current):
                with open(pids_current, 'r') as f:
                    metrics['pids_current'] = int(f.read().strip())
            if os.path.exists(pids_max):
                with open(pids_max, 'r') as f:
                    val = f.read().strip()
                    if val != 'max':
                        metrics['pids_limit'] = int(val)

            # Block I/O from io.stat
            io_stat = '/sys/fs/cgroup/io.stat'
            if os.path.exists(io_stat):
                with open(io_stat, 'r') as f:
                    total_rbytes = 0
                    total_wbytes = 0
                    total_rios = 0
                    total_wios = 0
                    for line in f:
                        parts = line.strip().split()
                        for part in parts:
                            if part.startswith('rbytes='):
                                total_rbytes += int(part.split('=')[1])
                            elif part.startswith('wbytes='):
                                total_wbytes += int(part.split('=')[1])
                            elif part.startswith('rios='):
                                total_rios += int(part.split('=')[1])
                            elif part.startswith('wios='):
                                total_wios += int(part.split('=')[1])
                    metrics['blkio_read_bytes'] = total_rbytes
                    metrics['blkio_write_bytes'] = total_wbytes
                    metrics['blkio_read_ops'] = total_rios
                    metrics['blkio_write_ops'] = total_wios

        except Exception:
            pass
        return metrics

    def read_cgroup_v1():
        """Read metrics from cgroup v1."""
        metrics = {}
        try:
            # Memory usage
            mem_usage = '/sys/fs/cgroup/memory/memory.usage_in_bytes'
            if os.path.exists(mem_usage):
                with open(mem_usage, 'r') as f:
                    metrics['memory_usage_bytes'] = int(f.read().strip())

            # Memory limit
            mem_limit = '/sys/fs/cgroup/memory/memory.limit_in_bytes'
            if os.path.exists(mem_limit):
                with open(mem_limit, 'r') as f:
                    val = int(f.read().strip())
                    # Check for "unlimited" (usually a very large number)
                    if val < 9223372036854771712:
                        metrics['memory_limit_bytes'] = val

            # Memory stats (cache, RSS)
            mem_stat = '/sys/fs/cgroup/memory/memory.stat'
            if os.path.exists(mem_stat):
                with open(mem_stat, 'r') as f:
                    for line in f:
                        parts = line.strip().split()
                        if len(parts) == 2:
                            if parts[0] == 'cache':
                                metrics['memory_cache_bytes'] = int(parts[1])
                            elif parts[0] == 'rss':
                                metrics['memory_rss_bytes'] = int(parts[1])

            # OOM kill count
            mem_failcnt = '/sys/fs/cgroup/memory/memory.failcnt'
            if os.path.exists(mem_failcnt):
                with open(mem_failcnt, 'r') as f:
                    metrics['oom_kill_count'] = int(f.read().strip())

            # CPU throttling
            cpu_stat = '/sys/fs/cgroup/cpu/cpu.stat'
            if os.path.exists(cpu_stat):
                with open(cpu_stat, 'r') as f:
                    for line in f:
                        parts = line.strip().split()
                        if len(parts) == 2:
                            if parts[0] == 'nr_throttled':
                                metrics['cpu_throttled_periods'] = int(parts[1])
                            elif parts[0] == 'throttled_time':
                                metrics['cpu_throttled_time_ns'] = int(parts[1])

            # CPU usage
            cpu_usage = '/sys/fs/cgroup/cpuacct/cpuacct.usage'
            if os.path.exists(cpu_usage):
                with open(cpu_usage, 'r') as f:
                    metrics['cpu_usage_ns'] = int(f.read().strip())

            # PIDs
            pids_current = '/sys/fs/cgroup/pids/pids.current'
            pids_max = '/sys/fs/cgroup/pids/pids.max'
            if os.path.exists(pids_current):
                with open(pids_current, 'r') as f:
                    metrics['pids_current'] = int(f.read().strip())
            if os.path.exists(pids_max):
                with open(pids_max, 'r') as f:
                    val = f.read().strip()
                    if val != 'max':
                        metrics['pids_limit'] = int(val)

            # Block I/O
            blkio_read = '/sys/fs/cgroup/blkio/blkio.throttle.io_service_bytes'
            if os.path.exists(blkio_read):
                with open(blkio_read, 'r') as f:
                    total_read = 0
                    total_write = 0
                    for line in f:
                        parts = line.strip().split()
                        if len(parts) >= 3:
                            if parts[1] == 'Read':
                                total_read += int(parts[2])
                            elif parts[1] == 'Write':
                                total_write += int(parts[2])
                    metrics['blkio_read_bytes'] = total_read
                    metrics['blkio_write_bytes'] = total_write

        except Exception:
            pass
        return metrics

    def get_process_metrics():
        """Get process-level metrics (file descriptors, etc.)."""
        metrics = {}
        try:
            pid = os.getpid()
            
            # File descriptor count
            fd_path = f'/proc/{pid}/fd'
            if os.path.exists(fd_path):
                metrics['fd_current'] = len(os.listdir(fd_path))
            
            # File descriptor limit
            limits_path = f'/proc/{pid}/limits'
            if os.path.exists(limits_path):
                with open(limits_path, 'r') as f:
                    for line in f:
                        if 'Max open files' in line:
                            parts = line.split()
                            # Format: Max open files            1024                 1048576              files
                            for i, part in enumerate(parts):
                                if part.isdigit():
                                    metrics['fd_limit'] = int(parts[i + 1])  # Hard limit
                                    break
        except Exception:
            pass
        return metrics

    def format_uptime(seconds):
        """Format uptime in a human-readable way."""
        if seconds is None:
            return None
        days = int(seconds // 86400)
        hours = int((seconds % 86400) // 3600)
        minutes = int((seconds % 3600) // 60)
        if days > 0:
            return f"{days}d {hours}h {minutes}m"
        elif hours > 0:
            return f"{hours}h {minutes}m"
        else:
            return f"{minutes}m"

    def loop():
        # Initial containerization check
        containerized = is_containerized()
        container_id = get_container_id() if containerized else None

        with state._container_metrics_lock:
            state._container_metrics['is_containerized'] = containerized
            if container_id:
                state._container_metrics['container_id'] = container_id
                state._container_metrics['container_id_short'] = container_id[:12] if len(container_id) >= 12 else container_id

        if not containerized:
            # Not in a container, no need to keep running
            return

        # Get initial Docker container info (less frequently)
        docker_info_ts = 0
        docker_info_interval = 60  # Refresh every 60 seconds

        while not _shutdown_event.is_set():
            try:
                now = time.time()
                
                # Try cgroup v2 first, fall back to v1
                metrics = read_cgroup_v2()
                if not metrics:
                    metrics = read_cgroup_v1()

                # Calculate memory percentage
                if metrics.get('memory_usage_bytes') and metrics.get('memory_limit_bytes'):
                    metrics['memory_usage_percent'] = round(
                        metrics['memory_usage_bytes'] / metrics['memory_limit_bytes'] * 100, 1
                    )

                # Add process-level metrics
                proc_metrics = get_process_metrics()
                metrics.update(proc_metrics)

                # Refresh Docker info periodically
                if now - docker_info_ts > docker_info_interval:
                    docker_info = get_docker_container_info(container_id)
                    if docker_info:
                        metrics.update(docker_info)
                        
                        # Calculate container uptime from started time
                        if 'container_started' in docker_info:
                            try:
                                started_str = docker_info['container_started']
                                # Parse ISO format: 2024-01-20T10:30:00.123456789Z
                                if '.' in started_str:
                                    started_str = started_str.split('.')[0] + 'Z'
                                from datetime import datetime
                                started_dt = datetime.strptime(started_str.replace('Z', '+0000'), '%Y-%m-%dT%H:%M:%S%z')
                                uptime_secs = (datetime.now(started_dt.tzinfo) - started_dt).total_seconds()
                                metrics['container_uptime_seconds'] = int(uptime_secs)
                                metrics['container_uptime_formatted'] = format_uptime(uptime_secs)
                            except Exception:
                                pass
                    
                    docker_info_ts = now

                # Fallback for uptime if docker inspect didn't work
                if not metrics.get('container_uptime_formatted'):
                    try:
                        with open('/proc/uptime', 'r') as f:
                            uptime_secs = float(f.read().split()[0])
                            metrics['container_uptime_seconds'] = int(uptime_secs)
                            metrics['container_uptime_formatted'] = format_uptime(uptime_secs)
                    except Exception:
                        pass

                metrics['last_update'] = now
                metrics['is_containerized'] = True
                metrics['container_id'] = container_id
                metrics['container_id_short'] = container_id[:12] if container_id and len(container_id) >= 12 else container_id

                with state._container_metrics_lock:
                    state._container_metrics.update(metrics)

            except Exception:
                pass

            # Sample every 10 seconds
            _shutdown_event.wait(timeout=10)

    t = threading.Thread(target=loop, daemon=True, name='ContainerMetricsThread')
    t.start()
