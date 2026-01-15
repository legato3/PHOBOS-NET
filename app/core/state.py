"""Centralized state management for PROX_NFDUMP application.

This module consolidates all global state variables, locks, and caches
that were previously scattered across phobos_dashboard.py.

Note: Some state remains in specialized modules:
- Performance metrics → app/services/metrics.py
- Threat state → app/services/threats.py
- DNS cache → app/utils/dns.py
- Geo cache → app/utils/geoip.py
- Database locks → app/db/sqlite.py
"""
import threading
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
_lock_compromised = threading.Lock()
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
_stats_compromised_cache = {"data": None, "ts": 0, "key": None}
_server_health_cache = {"data": None, "ts": 0}

# ==================== Data Caches ====================
_mock_data_cache = {"mtime": 0, "rows": [], "output_cache": {}}
_bandwidth_cache = {"data": None, "ts": 0}
_bandwidth_history_cache = {}
_flows_cache = {"data": None, "ts": 0}
_common_data_cache = {}

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
_snmp_prev_sample = {"ts": 0, "wan_in": 0, "wan_out": 0, "lan_in": 0, "lan_out": 0}
_snmp_backoff = {
    "failures": 0,
    "max_failures": 5,
    "base_delay": 2,  # seconds
    "max_delay": 60,  # max backoff delay
    "last_failure": 0
}

# ==================== Application State ====================
_has_nfdump = None  # Cache nfdump availability

# ==================== Thread Pool Executor ====================
_dns_resolver_executor = ThreadPoolExecutor(max_workers=5)
