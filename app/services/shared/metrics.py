"""Performance metrics tracking service for PROX_NFDUMP application."""
import threading
import time
from collections import defaultdict

# Performance metrics state
_performance_metrics = {
    'request_count': 0,
    'total_response_time': 0.0,
    'endpoint_times': defaultdict(list),
    'error_count': 0,
    'cache_hits': 0,
    'cache_misses': 0,
    # Observability metrics
    'subprocess_calls': 0,
    'subprocess_success': 0,
    'subprocess_failures': 0,
    'subprocess_timeouts': 0,
    'subprocess_total_time': 0.0,
    'subprocess_times': [],  # Last 100 subprocess execution times
    'slow_requests': 0,  # Requests exceeding slow threshold
    'service_calls': defaultdict(int),  # Service function call counts
    'service_total_time': defaultdict(float),  # Total time per service
    'service_times': defaultdict(list),  # Last 50 times per service
}
_performance_lock = threading.Lock()


def track_performance(endpoint, duration, cached=False):
    """Track performance metrics for an endpoint."""
    with _performance_lock:
        _performance_metrics['request_count'] += 1
        _performance_metrics['total_response_time'] += duration
        _performance_metrics['endpoint_times'][endpoint].append(duration)
        # Keep only last 100 samples per endpoint
        if len(_performance_metrics['endpoint_times'][endpoint]) > 100:
            _performance_metrics['endpoint_times'][endpoint].pop(0)
        if cached:
            _performance_metrics['cache_hits'] += 1
        else:
            _performance_metrics['cache_misses'] += 1


def track_error():
    """Track error occurrence."""
    with _performance_lock:
        _performance_metrics['error_count'] += 1


def get_performance_metrics():
    """Get a copy of performance metrics."""
    with _performance_lock:
        return dict(_performance_metrics)


def get_performance_lock():
    """Get the performance lock (for internal use)."""
    return _performance_lock


def track_subprocess(duration, success=True, timeout=False):
    """Track subprocess execution metrics (e.g., nfdump calls)."""
    with _performance_lock:
        _performance_metrics['subprocess_calls'] += 1
        _performance_metrics['subprocess_total_time'] += duration
        _performance_metrics['subprocess_times'].append(duration)
        # Keep only last 100 samples
        if len(_performance_metrics['subprocess_times']) > 100:
            _performance_metrics['subprocess_times'].pop(0)
        
        if timeout:
            _performance_metrics['subprocess_timeouts'] += 1
        elif success:
            _performance_metrics['subprocess_success'] += 1
        else:
            _performance_metrics['subprocess_failures'] += 1


def track_service(service_name, duration):
    """Track service function execution metrics (stats aggregation, threat detection, SNMP)."""
    with _performance_lock:
        _performance_metrics['service_calls'][service_name] += 1
        _performance_metrics['service_total_time'][service_name] += duration
        _performance_metrics['service_times'][service_name].append(duration)
        # Keep only last 50 samples per service
        if len(_performance_metrics['service_times'][service_name]) > 50:
            _performance_metrics['service_times'][service_name].pop(0)


def track_slow_request():
    """Track requests that exceed slow threshold."""
    with _performance_lock:
        _performance_metrics['slow_requests'] += 1
