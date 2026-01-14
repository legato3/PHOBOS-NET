"""Performance metrics tracking service for PROX_NFDUMP application."""
import threading
from collections import defaultdict

# Performance metrics state
_performance_metrics = {
    'request_count': 0,
    'total_response_time': 0.0,
    'endpoint_times': defaultdict(list),
    'error_count': 0,
    'cache_hits': 0,
    'cache_misses': 0
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
