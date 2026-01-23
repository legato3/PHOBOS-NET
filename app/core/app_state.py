"""Centralized state management for PHOBOS-NET application.

This module consolidates all global state variables, locks, and caches
that were previously scattered across phobos_dashboard.py.

Note: Some state remains in specialized modules:
- Performance metrics → app.services.shared.metrics.py
- Threat state → app.services.security.threats.py
- DNS cache → app.services.shared/dns.py
- Geo cache → app.services.shared/geoip.py
- Database locks → app/db/sqlite.py
"""
import threading
import time
from collections import defaultdict, deque
from concurrent.futures import ThreadPoolExecutor

# ==================== Threading Primitives ====================
# Graceful shutdown event
_shutdown_event = threading.Event()

# ==================== Endpoint Locks ====================
# Granular locks per endpoint to reduce contention
_lock_summary = threading.Lock()
_lock_sources = threading.Lock()
_lock_dests = threading.Lock()
_lock_ports = threading.Lock()
_lock_protocols = threading.Lock()
_lock_alerts = threading.Lock()
_lock_flags = threading.Lock()
_lock_asns = threading.Lock()
_lock_durations = threading.Lock()
_lock_bandwidth = threading.Lock()
_lock_flows = threading.Lock()
_lock_countries = threading.Lock()
_lock_worldmap = threading.Lock()
_lock_proto_hierarchy = threading.Lock()
_lock_noise = threading.Lock()
_lock_service_cache = threading.Lock() # Lock for service name cache
_cache_lock = threading.Lock()  # Generic small cache lock (e.g., packet sizes)
_mock_lock = threading.Lock()  # Lock for mock data cache
_throttle_lock = threading.Lock()  # Lock for rate limiting
_common_data_lock = threading.Lock()  # Lock for common data cache
_cpu_stat_lock = threading.Lock()  # Lock for CPU stat caching

# ==================== Stats Caches ====================
# Caches for API endpoints (60-second TTL, aligned to windows)
_stats_summary_cache = {"data": None, "ts": 0, "key": None}
_stats_sources_cache = {"data": None, "ts": 0, "key": None}
_stats_dests_cache = {"data": None, "ts": 0, "key": None}
_stats_ports_cache = {"data": None, "ts": 0, "key": None}
_stats_protocols_cache = {"data": None, "ts": 0, "key": None}
_stats_alerts_cache = {"data": None, "ts": 0, "key": None}
_stats_flags_cache = {"data": None, "ts": 0, "key": None}
_stats_asns_cache = {"data": None, "ts": 0, "key": None}
_stats_durations_cache = {"data": None, "ts": 0, "key": None}
_stats_pkts_cache = {"data": None, "ts": 0, "key": None}
_stats_countries_cache = {"data": None, "ts": 0, "key": None}
_stats_talkers_cache = {"data": None, "ts": 0, "key": None}
_stats_services_cache = {"data": None, "ts": 0, "key": None}
_stats_hourly_cache = {"data": None, "ts": 0, "key": None}
_stats_flow_stats_cache = {"data": None, "ts": 0, "key": None}
_stats_proto_mix_cache = {"data": None, "ts": 0, "key": None}
_stats_net_health_cache = {"data": None, "ts": 0, "key": None}
_stats_proto_hierarchy_cache = {"data": None, "ts": 0, "key": None}
_stats_noise_metrics_cache = {"data": None, "ts": 0, "key": None}
_server_health_cache = {"data": None, "ts": 0}

# ==================== Data Caches ====================
_mock_data_cache = {"mtime": 0, "rows": [], "output_cache": {}}
_bandwidth_cache = {"data": None, "ts": 0}
_bandwidth_history_cache = {}
_flows_cache = {"data": None, "ts": 0}
_common_data_cache = {}
_service_cache = {}

# ==================== Phase 3: Flow History (in-memory rolling) ====================
# Rolling history: 30-60 minutes, aggregated by src/dst/port
_flow_history = {}  # Key: (src, dst, port) -> list of {ts, bytes, packets, duration}
_flow_history_lock = threading.Lock()
_flow_history_ttl = 3600  # 60 minutes default

# ==================== Baseline Tracking (automatic, environment-specific) ====================
# Rolling window baselines for key metrics (mean and deviation)
# Used internally for health classification and severity tuning
_baselines = {
    'active_flows': deque(maxlen=100),  # Rolling window of values
    'external_connections': deque(maxlen=100),
    'firewall_blocks_rate': deque(maxlen=100),  # Blocks per hour
    'anomalies_rate': deque(maxlen=100),  # Anomalies per hour
    'wan_utilization': deque(maxlen=100),  # Interface utilization baselines
    'lan_utilization': deque(maxlen=100),
    'cpu_load': deque(maxlen=100),  # CPU deviation baseline
    'mem_usage': deque(maxlen=100),  # Memory deviation baseline
}
_baselines_lock = threading.Lock()
_baselines_last_update = {
    'active_flows': 0,
    'external_connections': 0,
    'firewall_blocks_rate': 0,
    'anomalies_rate': 0,
    'wan_utilization': 0,
    'lan_utilization': 0,
}

# ==================== Rate Limiting ====================
_request_times = defaultdict(list)

# ==================== Metrics Counters ====================
_metric_nfdump_calls = 0
_metric_stats_cache_hits = 0
_metric_bw_cache_hits = 0
_metric_conv_cache_hits = 0
_metric_flow_cache_hits = 0
_metric_http_429 = 0

# ==================== CPU Stat Caching ====================
_cpu_stat_prev = {'times': {}, 'ts': 0}

# ==================== Thread Management ====================
_threat_thread_started = False
_trends_thread_started = False
_agg_thread_started = False
_syslog_thread_started = False
_snmp_thread_started = False
_db_size_sampler_thread_started = False
_resource_sampler_thread_started = False

# ==================== Resource History ====================
# Rolling history: 60 samples (1 per minute = 1 hour of history)
_resource_history = deque(maxlen=60)
_resource_history_lock = threading.Lock()

# ==================== Syslog State ====================
_syslog_stats = {"received": 0, "parsed": 0, "errors": 0, "last_log": None}
_syslog_stats_lock = threading.Lock()
_syslog_buffer = []
_syslog_buffer_lock = threading.Lock()
_syslog_buffer_size = 100
# Alert history for Syslog triggers (new)
_alert_history = deque(maxlen=1000)
_alert_history_lock = threading.Lock()

# ==================== SNMP State ====================
_snmp_cache = {"data": None, "ts": 0}
_snmp_cache_lock = threading.Lock()
_snmp_prev_sample = {"ts": 0}  # Initialize with only timestamp; counter values will be None until first poll
_snmp_prev_sample_lock = threading.Lock()
_snmp_backoff = {
    "failures": 0,
    "max_failures": 5,
    "base_delay": 2,  # seconds
    "max_delay": 60,  # max backoff delay
    "last_failure": 0
}

# ==================== Application State ====================
_has_nfdump = None  # Cache nfdump availability

# ==================== Application Log Buffer ====================
# In-memory buffer to capture recent application logs (print statements, errors)
_app_log_buffer = deque(maxlen=500)  # Keep last 500 log lines
_app_log_buffer_lock = threading.Lock()

def add_app_log(message, level='INFO'):
    """Add a log message to the in-memory buffer."""
    from datetime import datetime
    timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
    log_entry = f"[{timestamp}] [{level}] {message}"
    with _app_log_buffer_lock:
        _app_log_buffer.append(log_entry)

# ==================== Thread Pool Executor ====================
_dns_resolver_executor = ThreadPoolExecutor(max_workers=5)
_rollup_executor = ThreadPoolExecutor(max_workers=8)

# ==================== Background Thread Health ====================
# Track health of each background thread for monitoring
_thread_health = {
    'ThreatFeedThread': {
        'last_success': None,
        'last_error': None,
        'last_error_msg': None,
        'error_count': 0,
        'execution_count': 0,
        'execution_times_ms': deque(maxlen=20),
        'expected_interval_sec': 900,  # 15 minutes
        'status': 'unknown'
    },
    'TrendsThread': {
        'last_success': None,
        'last_error': None,
        'last_error_msg': None,
        'error_count': 0,
        'execution_count': 0,
        'execution_times_ms': deque(maxlen=20),
        'expected_interval_sec': 30,
        'status': 'unknown'
    },
    'AggregationThread': {
        'last_success': None,
        'last_error': None,
        'last_error_msg': None,
        'error_count': 0,
        'execution_count': 0,
        'execution_times_ms': deque(maxlen=20),
        'expected_interval_sec': 60,
        'status': 'unknown'
    },
    'SNMPThread': {
        'last_success': None,
        'last_error': None,
        'last_error_msg': None,
        'error_count': 0,
        'execution_count': 0,
        'execution_times_ms': deque(maxlen=20),
        'expected_interval_sec': 2,
        'status': 'unknown'
    },
    'SyslogThread': {
        'last_success': None,
        'last_error': None,
        'last_error_msg': None,
        'error_count': 0,
        'execution_count': 0,
        'execution_times_ms': deque(maxlen=20),
        'expected_interval_sec': 0,  # Event-driven
        'status': 'unknown'
    },
    'FirewallSyslogThread': {
        'last_success': None,
        'last_error': None,
        'last_error_msg': None,
        'error_count': 0,
        'execution_count': 0,
        'execution_times_ms': deque(maxlen=20),
        'expected_interval_sec': 0,  # Event-driven
        'status': 'unknown'
    },
    'ResourceSamplerThread': {
        'last_success': None,
        'last_error': None,
        'last_error_msg': None,
        'error_count': 0,
        'execution_count': 0,
        'execution_times_ms': deque(maxlen=20),
        'expected_interval_sec': 60,
        'status': 'unknown'
    },
    'DbSizeSamplerThread': {
        'last_success': None,
        'last_error': None,
        'last_error_msg': None,
        'error_count': 0,
        'execution_count': 0,
        'execution_times_ms': deque(maxlen=20),
        'expected_interval_sec': 60,
        'status': 'unknown'
    },
}
_thread_health_lock = threading.Lock()

def update_thread_health(thread_name, success=True, execution_time_ms=None, error_msg=None):
    """Update thread health metrics after execution."""
    import time
    with _thread_health_lock:
        if thread_name not in _thread_health:
            return
        th = _thread_health[thread_name]
        now = time.time()
        th['execution_count'] += 1
        if execution_time_ms is not None:
            th['execution_times_ms'].append(execution_time_ms)
        if success:
            th['last_success'] = now
            th['status'] = 'healthy'
        else:
            th['last_error'] = now
            th['last_error_msg'] = error_msg
            th['error_count'] += 1
            th['status'] = 'errored'

def get_thread_health_status():
    """Get health status for all threads."""
    import time
    now = time.time()
    result = {}
    with _thread_health_lock:
        for name, th in _thread_health.items():
            status = th['status']
            # Check if thread is lagging (hasn't run in 3x expected interval)
            if th['last_success'] and th['expected_interval_sec'] > 0:
                age = now - th['last_success']
                if age > th['expected_interval_sec'] * 3:
                    status = 'lagging'
            # Calculate avg execution time
            exec_times = list(th['execution_times_ms'])
            avg_exec_ms = round(sum(exec_times) / len(exec_times), 1) if exec_times else None
            result[name] = {
                'status': status,
                'last_success': th['last_success'],
                'last_success_age_sec': round(now - th['last_success'], 1) if th['last_success'] else None,
                'last_error': th['last_error'],
                'last_error_msg': th['last_error_msg'],
                'error_count': th['error_count'],
                'execution_count': th['execution_count'],
                'avg_execution_ms': avg_exec_ms,
                'expected_interval_sec': th['expected_interval_sec']
            }
    return result

# ==================== Network I/O Metrics ====================
# Track network interface bandwidth rates
_network_io_metrics = {
    'timestamp': 0,
    'prev_timestamp': 0,
    'interfaces': {},  # interface_name -> {rx_bytes, tx_bytes, rx_packets, tx_packets, ...}
    'prev_interfaces': {},  # Previous sample for rate calculation
    'rates': {}  # Calculated rates: interface_name -> {rx_bytes_sec, tx_bytes_sec, ...}
}
_network_io_lock = threading.Lock()
_network_io_sampler_started = False

# ==================== Service Dependency Health ====================
# Track health of external services
_dependency_health = {
    'nfcapd': {
        'running': None,
        'pid': None,
        'port_listening': None,
        'latest_file_age_sec': None,
        'files_count': None,
        'last_check': None
    },
    'dns': {
        'available': None,
        'last_query_time': None,
        'success_count': 0,
        'error_count': 0,
        'response_times_ms': deque(maxlen=20),
        'last_error': None
    },
    'snmp': {
        'reachable': None,
        'last_poll_time': None,
        'success_count': 0,
        'error_count': 0,
        'response_times_ms': deque(maxlen=20),
        'backoff_multiplier': 1.0
    },
    'threat_feeds': {
        'last_fetch': None,
        'fetch_success_count': 0,
        'fetch_error_count': 0,
        'records_count': 0,
        'feeds_status': {}  # feed_name -> {ok, last_update, entries}
    },
    'syslog_514': {
        'listening': None,
        'last_packet_time': None,
        'buffer_size': 0,
        'buffer_max': 100
    },
    'syslog_515': {
        'listening': None,
        'last_packet_time': None,
        'buffer_size': 0,
        'buffer_max': 5000
    }
}
_dependency_health_lock = threading.Lock()

def update_dependency_health(service, **kwargs):
    """Update dependency health metrics and persist to shared memory for other workers."""
    with _dependency_health_lock:
        if service in _dependency_health:
            _dependency_health[service].update(kwargs)
            
            # MULTI-WORKER SYNC: Write to shared file in /dev/shm
            # This allows the maintenance worker (which runs the checks) to share status
            # with other web workers handling API requests.
            try:
                import json
                import os
                
                # Snapshot current state
                state_snapshot = {}
                for k, v in _dependency_health.items():
                    # Helper to convert sets/deques to list for JSON
                    val_copy = dict(v)
                    for vk, vv in val_copy.items():
                        if isinstance(vv, (list, tuple, deque)):
                            val_copy[vk] = list(vv)
                    state_snapshot[k] = val_copy
                
                # Write atomically to /dev/shm/phobos_health.json
                # /dev/shm is RAM-based, so this is fast and safe for Docker
                temp_path = '/dev/shm/phobos_health.json.tmp'
                final_path = '/dev/shm/phobos_health.json'
                
                with open(temp_path, 'w') as f:
                    json.dump(state_snapshot, f)
                os.replace(temp_path, final_path)
            except Exception as e:
                # Log but don't fail, we still have local memory state
                # add_app_log(f"Failed to persist health state: {e}", 'DEBUG')
                pass

def get_dependency_health():
    """Get current dependency health status, merging from shared memory if available."""
    import time
    import json
    import os
    
    now = time.time()
    
    # 1. READ FROM SHARED MEMORY (Primary Source)
    # The maintenance worker writes authoritative status here.
    # Web workers should prefer this over their likely-stale local state.
    shared_state = None
    try:
        if os.path.exists('/dev/shm/phobos_health.json'):
            with open('/dev/shm/phobos_health.json', 'r') as f:
                shared_state = json.load(f)
    except Exception:
        pass

    with _dependency_health_lock:
        # If we successfully read shared state, merge it safely
        if shared_state:
            for service, data in shared_state.items():
                if service in _dependency_health:
                    # Update local keys if they exist in shared data
                    for k, v in data.items():
                        if k in _dependency_health[service]:
                            _dependency_health[service][k] = v

        # Construct result from (now updated) local state
        result = {}
        for service, data in _dependency_health.items():
            result[service] = dict(data)
            # Convert deques to lists for JSON
            if 'response_times_ms' in result[service]:
                times = list(result[service]['response_times_ms'])
                result[service]['response_times_ms'] = times
                result[service]['avg_response_ms'] = round(sum(times) / len(times), 1) if times else None
            # Calculate ages
            for key in ['last_check', 'last_query_time', 'last_poll_time', 'last_fetch', 'last_packet_time']:
                if key in result[service] and result[service][key]:
                    result[service][f'{key}_age_sec'] = round(now - result[service][key], 1)
    return result

# ==================== HTTP/API Metrics ====================
# Track HTTP request metrics
_http_metrics = {
    'status_codes': defaultdict(int),  # {200: 1523, 429: 45, 500: 2}
    'methods': defaultdict(int),  # {GET: 2000, POST: 150}
    'concurrent_requests': 0,
    'peak_concurrent': 0,
    'total_requests': 0,
    'total_errors': 0,  # 4xx + 5xx
    'endpoint_errors': defaultdict(int),  # endpoint -> error count
    'request_start_times': {},  # request_id -> start_time (for concurrent tracking)
}
_http_metrics_lock = threading.Lock()

def record_http_request_start(request_id):
    """Record start of HTTP request."""
    import time
    with _http_metrics_lock:
        _http_metrics['request_start_times'][request_id] = time.time()
        _http_metrics['concurrent_requests'] += 1
        if _http_metrics['concurrent_requests'] > _http_metrics['peak_concurrent']:
            _http_metrics['peak_concurrent'] = _http_metrics['concurrent_requests']

def record_http_request_end(request_id, status_code, method, endpoint):
    """Record end of HTTP request."""
    with _http_metrics_lock:
        _http_metrics['total_requests'] += 1
        _http_metrics['status_codes'][status_code] += 1
        _http_metrics['methods'][method] += 1
        if request_id in _http_metrics['request_start_times']:
            del _http_metrics['request_start_times'][request_id]
            _http_metrics['concurrent_requests'] = max(0, _http_metrics['concurrent_requests'] - 1)
        if status_code >= 400:
            _http_metrics['total_errors'] += 1
            _http_metrics['endpoint_errors'][endpoint] += 1

def get_http_metrics():
    """Get HTTP metrics summary."""
    with _http_metrics_lock:
        return {
            'status_codes': dict(_http_metrics['status_codes']),
            'methods': dict(_http_metrics['methods']),
            'concurrent_requests': _http_metrics['concurrent_requests'],
            'peak_concurrent': _http_metrics['peak_concurrent'],
            'total_requests': _http_metrics['total_requests'],
            'total_errors': _http_metrics['total_errors'],
            'error_rate_percent': round(_http_metrics['total_errors'] / _http_metrics['total_requests'] * 100, 2) if _http_metrics['total_requests'] > 0 else 0,
            'endpoint_errors': dict(_http_metrics['endpoint_errors'])
        }

# ==================== Container Metrics ====================
# Track Docker container-specific metrics (from cgroups + Docker API)
_container_metrics = {
    # Memory metrics
    'memory_usage_bytes': None,
    'memory_limit_bytes': None,
    'memory_usage_percent': None,
    'memory_cache_bytes': None,
    'memory_rss_bytes': None,
    
    # CPU metrics
    'cpu_usage_ns': None,
    'cpu_usage_percent': None,
    'cpu_throttled_periods': None,
    'cpu_throttled_time_ns': None,
    
    # OOM tracking
    'oom_kill_count': None,
    
    # Container identity
    'is_containerized': None,
    'container_id': None,
    'container_id_short': None,
    'image_name': None,
    'image_tag': None,
    
    # Container lifecycle
    'container_uptime_seconds': None,
    'container_uptime_formatted': None,
    'container_created': None,
    'container_started': None,
    'restart_count': None,
    
    # Health check
    'health_status': None,  # 'healthy', 'unhealthy', 'starting', None
    'health_last_check': None,
    'health_failing_streak': 0,
    
    # Block I/O
    'blkio_read_bytes': None,
    'blkio_write_bytes': None,
    'blkio_read_ops': None,
    'blkio_write_ops': None,
    
    # Process info
    'pids_current': None,
    'pids_limit': None,
    
    # File descriptors
    'fd_current': None,
    'fd_limit': None,
    
    'last_update': None
}
_container_metrics_lock = threading.Lock()

def get_container_metrics():
    """Get container metrics if running in Docker."""
    with _container_metrics_lock:
        return dict(_container_metrics)
