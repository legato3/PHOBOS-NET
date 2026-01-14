"""Bridge module to access functions and globals from phobos_dashboard.py.

This is a temporary bridge to allow routes to access dependencies
from the original monolithic file. As the refactor progresses,
these dependencies should be moved to proper modules.
"""
import sys
import os

# Get the path to phobos_dashboard.py
_script_dir = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
_sys_path_inserted = False
if _script_dir not in sys.path:
    sys.path.insert(0, _script_dir)
    _sys_path_inserted = True

# Import phobos_dashboard module directly (now that it has a valid Python name)
try:
    import phobos_dashboard as _module
except Exception as e:
    print(f"Warning: Could not load phobos_dashboard bridge: {e}")
    _module = None

# Export commonly needed items
if _module:
    # Decorator
    throttle = getattr(_module, 'throttle', None)
    
    # Helper functions
    load_notify_cfg = getattr(_module, 'load_notify_cfg', None)
    calculate_security_score = getattr(_module, 'calculate_security_score', None)
    load_threatlist = getattr(_module, 'load_threatlist', None)
    format_duration = getattr(_module, 'format_duration', None)
    check_disk_space = getattr(_module, 'check_disk_space', None)
    calculate_cpu_percent_from_stat = getattr(_module, 'calculate_cpu_percent_from_stat', None)
    get_snmp_data = getattr(_module, 'get_snmp_data', None)
    track_performance = getattr(_module, 'track_performance', None)
    track_error = getattr(_module, 'track_error', None)
    _get_bucket_end = getattr(_module, '_get_bucket_end', None)
    _ensure_rollup_for_bucket = getattr(_module, '_ensure_rollup_for_bucket', None)
    _flush_syslog_buffer = getattr(_module, '_flush_syslog_buffer', None)
    
    # Thread functions
    start_threat_thread = getattr(_module, 'start_threat_thread', None)
    start_trends_thread = getattr(_module, 'start_trends_thread', None)
    start_agg_thread = getattr(_module, 'start_agg_thread', None)
    start_syslog_thread = getattr(_module, 'start_syslog_thread', None)
    
else:
    # Fallback: set to None if module couldn't be loaded
    throttle = None
    load_notify_cfg = None
    calculate_security_score = None
    load_threatlist = None
    format_duration = None
    check_disk_space = None
    calculate_cpu_percent_from_stat = None
    get_snmp_data = None
    track_performance = None
    track_error = None
    _get_bucket_end = None
    _ensure_rollup_for_bucket = None
    _flush_syslog_buffer = None
    start_threat_thread = None
    start_trends_thread = None
    start_agg_thread = None
    start_syslog_thread = None

# Function to get globals from the dashboard module
def get_global(name, default=None):
    """Get a global variable from phobos_dashboard.py."""
    if _module:
        return getattr(_module, name, default)
    return default

# Direct access to common globals
# Note: These are accessed at import time, so they won't reflect runtime changes
# For dynamic access, use get_global() function
if _module:
    # Locks
    _lock_summary = getattr(_module, '_lock_summary', None)
    _lock_sources = getattr(_module, '_lock_sources', None)
    _lock_dests = getattr(_module, '_lock_dests', None)
    _lock_ports = getattr(_module, '_lock_ports', None)
    _lock_protocols = getattr(_module, '_lock_protocols', None)
    _lock_alerts = getattr(_module, '_lock_alerts', None)
    _lock_flags = getattr(_module, '_lock_flags', None)
    _lock_asns = getattr(_module, '_lock_asns', None)
    _lock_durations = getattr(_module, '_lock_durations', None)
    _lock_bandwidth = getattr(_module, '_lock_bandwidth', None)
    _lock_flows = getattr(_module, '_lock_flows', None)
    _lock_countries = getattr(_module, '_lock_countries', None)
    _cache_lock = getattr(_module, '_cache_lock', None)
    
    # Caches
    _stats_summary_cache = getattr(_module, '_stats_summary_cache', None)
    _stats_sources_cache = getattr(_module, '_stats_sources_cache', None)
    _stats_dests_cache = getattr(_module, '_stats_dests_cache', None)
    _stats_ports_cache = getattr(_module, '_stats_ports_cache', None)
    _stats_protocols_cache = getattr(_module, '_stats_protocols_cache', None)
    _stats_alerts_cache = getattr(_module, '_stats_alerts_cache', None)
    _stats_flags_cache = getattr(_module, '_stats_flags_cache', None)
    _stats_asns_cache = getattr(_module, '_stats_asns_cache', None)
    _stats_durations_cache = getattr(_module, '_stats_durations_cache', None)
    _stats_pkts_cache = getattr(_module, '_stats_pkts_cache', None)
    _stats_countries_cache = getattr(_module, '_stats_countries_cache', None)
    _stats_talkers_cache = getattr(_module, '_stats_talkers_cache', None)
    _stats_services_cache = getattr(_module, '_stats_services_cache', None)
    _stats_hourly_cache = getattr(_module, '_stats_hourly_cache', None)
    _stats_flow_stats_cache = getattr(_module, '_stats_flow_stats_cache', None)
    _stats_proto_mix_cache = getattr(_module, '_stats_proto_mix_cache', None)
    _stats_net_health_cache = getattr(_module, '_stats_net_health_cache', None)
    _server_health_cache = getattr(_module, '_server_health_cache', None)
    _bandwidth_cache = getattr(_module, '_bandwidth_cache', None)
    _bandwidth_history_cache = getattr(_module, '_bandwidth_history_cache', None)
    _flows_cache = getattr(_module, '_flows_cache', None)
    _mock_data_cache = getattr(_module, '_mock_data_cache', None)
    
    # State
    _threat_status = getattr(_module, '_threat_status', None)
    _threat_timeline = getattr(_module, '_threat_timeline', None)
    _syslog_stats = getattr(_module, '_syslog_stats', None)
    _performance_metrics = getattr(_module, '_performance_metrics', None)
    _metric_http_429 = getattr(_module, '_metric_http_429', None)
    _shutdown_event = getattr(_module, '_shutdown_event', None)
    
    # Other common globals
    _has_nfdump = getattr(_module, '_has_nfdump', None)
else:
    # Set to None if module not loaded
    _lock_summary = _lock_sources = _lock_dests = _lock_ports = _lock_protocols = None
    _lock_alerts = _lock_flags = _lock_asns = _lock_durations = _lock_bandwidth = None
    _lock_flows = _lock_countries = _cache_lock = None
    _stats_summary_cache = _stats_sources_cache = _stats_dests_cache = None
    _stats_ports_cache = _stats_protocols_cache = _stats_alerts_cache = None
    _stats_flags_cache = _stats_asns_cache = _stats_durations_cache = None
    _stats_pkts_cache = _stats_countries_cache = _stats_talkers_cache = None
    _stats_services_cache = _stats_hourly_cache = _stats_flow_stats_cache = None
    _stats_proto_mix_cache = _stats_net_health_cache = _server_health_cache = None
    _bandwidth_cache = _bandwidth_history_cache = _flows_cache = _mock_data_cache = None
    _threat_status = _threat_timeline = _syslog_stats = None
    _performance_metrics = _metric_http_429 = _shutdown_event = _has_nfdump = None
