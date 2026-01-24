"""Decorators for PHOBOS-NET application.

This module contains decorators extracted from phobos_dashboard.py.
"""
import time
from functools import wraps
from flask import jsonify, request

# Import state variables
from app.core.app_state import _throttle_lock, _request_times, _metric_http_429
from flask_login import current_user
from flask import abort


def login_required(f):
    """Decorator to ensure user is logged in."""
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if not current_user.is_authenticated:
            return jsonify({'status': 'error', 'message': 'Authentication required'}), 401
        return f(*args, **kwargs)
    return decorated_function


def admin_required(f):
    """Decorator to ensure user has admin privileges."""
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if not current_user.is_authenticated:
            return jsonify({'status': 'error', 'message': 'Authentication required'}), 401
        if not getattr(current_user, 'is_admin', False):
            return jsonify({'status': 'error', 'message': 'Administrator privileges required'}), 403
        return f(*args, **kwargs)
    return decorated_function


def cached_endpoint(cache_dict, lock, key_params=None, ttl_seconds=60):
    """Caching decorator for Flask JSON endpoints.

    Caches endpoint responses based on request parameters with a sliding TTL.
    Sliding TTL prevents simultaneous cache misses at minute boundaries.

    Args:
        cache_dict: Dict to store cached data (must have 'data', 'key', 'ts' keys)
        lock: Threading lock for cache access
        key_params: List of request.args param names to include in cache key.
        ttl_seconds: Cache TTL in seconds (default: 60)
    """
    if key_params is None:
        key_params = ['range']

    def decorator(func):
        @wraps(func)
        def wrapper(*args, **kwargs):
            # Build cache key from request params
            key_parts = []
            for param in key_params:
                val = request.args.get(param, '')
                key_parts.append(str(val))
            cache_key = ':'.join(key_parts) if key_parts else 'default'

            now = time.time()

            # Check cache
            with lock:
                cached_data = cache_dict.get("data")
                if (cached_data is not None and
                    cache_dict.get("key") == cache_key and
                    (now - cache_dict.get("ts", 0)) < ttl_seconds):
                    # If we cached a dict-like object, jsonify it.
                    # If we cached a Response object, return it as is.
                    from flask import Response
                    if isinstance(cached_data, Response):
                        return cached_data
                    return jsonify(cached_data)

            # Cache miss - call function
            result = func(*args, **kwargs)

            # Store in cache
            with lock:
                cache_dict["data"] = result
                cache_dict["ts"] = now
                cache_dict["key"] = cache_key

            from flask import Response
            if isinstance(result, Response):
                return result
            return jsonify(result)
        return wrapper
    return decorator


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
