"""Decorator utilities for PROX_NFDUMP application."""
import time
from functools import wraps
from flask import jsonify
import threading

# Rate limiting state
_throttle_lock = threading.Lock()
_request_times = defaultdict(list)


def throttle(max_calls=20, time_window=10):
    """Rate limiting decorator for Flask routes."""
    def decorator(func):
        @wraps(func)
        def wrapper(*args, **kwargs):
            start_time = time.time()
            now = start_time
            endpoint = func.__name__
            with _throttle_lock:
                _request_times[endpoint] = [t for t in _request_times[endpoint] if now - t < time_window]
                if len(_request_times[endpoint]) >= max_calls:
                    # Import here to avoid circular dependency
                    import phobos_dashboard as _phobos
                    _metric_http_429 = getattr(_phobos, '_metric_http_429', 0)
                    # Update metric (would need to be handled differently in full refactor)
                    track_error = getattr(_phobos, 'track_error', None)
                    if track_error:
                        track_error()
                    return jsonify({"error": "Rate limit"}), 429
                _request_times[endpoint].append(now)
            try:
                result = func(*args, **kwargs)
                duration = time.time() - start_time
                # Track performance (skip for error responses)
                if isinstance(result, tuple) and len(result) == 2 and isinstance(result[1], int) and result[1] == 200:
                    track_performance = getattr(_phobos, 'track_performance', None)
                    if track_performance:
                        track_performance(endpoint, duration)
                return result
            except Exception as e:
                track_error = getattr(_phobos, 'track_error', None)
                if track_error:
                    track_error()
                raise
        return wrapper
    return decorator
