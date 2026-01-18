"""Decorators for PROX_NFDUMP application.

This module contains decorators extracted from phobos_dashboard.py.
"""
import time
from functools import wraps
from flask import jsonify

# Import state variables
from app.core.app_state import _throttle_lock, _request_times, _metric_http_429


def throttle(max_calls=20, time_window=10):
    """Rate limiting decorator for Flask routes.
    
    Limits the number of calls to a function within a time window.
    Returns HTTP 429 if rate limit is exceeded.
    
    Args:
        max_calls: Maximum number of calls allowed (default: 20)
        time_window: Time window in seconds (default: 10)
    
    Returns:
        Decorator function
    """
    def decorator(func):
        @wraps(func)
        def wrapper(*args, **kwargs):
            global _metric_http_429  # Required for incrementing the counter
            
            # Import metrics functions (avoid circular import)
            try:
                from app.services.shared.metrics import track_performance, track_error
            except ImportError:
                # Fallback if metrics module not available
                def track_performance(*args, **kwargs): pass
                def track_error(*args, **kwargs): pass
            
            start_time = time.time()
            now = start_time
            endpoint = func.__name__
            with _throttle_lock:
                _request_times[endpoint] = [t for t in _request_times[endpoint] if now - t < time_window]
                if len(_request_times[endpoint]) >= max_calls:
                    _metric_http_429 += 1
                    track_error()
                    return jsonify({"error": "Rate limit"}), 429
                _request_times[endpoint].append(now)
            try:
                result = func(*args, **kwargs)
                duration = time.time() - start_time
                # Track performance (skip for error responses)
                if isinstance(result, tuple) and len(result) == 2 and isinstance(result[1], int) and result[1] == 200:
                    track_performance(endpoint, duration, cached=False)
                elif not isinstance(result, tuple):
                    track_performance(endpoint, duration, cached=False)
                return result
            except Exception as e:
                track_error()
                raise
        return wrapper
    return decorator
