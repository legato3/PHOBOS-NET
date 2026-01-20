"""Decorators for PHOBOS-NET application.

This module contains decorators extracted from phobos_dashboard.py.
"""
import time
from functools import wraps
from flask import jsonify, request

# Import state variables
from app.core.app_state import _throttle_lock, _request_times, _metric_http_429


def cached_endpoint(cache_dict, lock, key_params=None, ttl_minutes=1):
    """Caching decorator for Flask JSON endpoints.

    Caches endpoint responses based on request parameters with minute-window expiry.
    Eliminates duplicate caching boilerplate across routes.

    Args:
        cache_dict: Dict to store cached data (must have 'data', 'key', 'ts', 'win' keys)
        lock: Threading lock for cache access
        key_params: List of request.args param names to include in cache key.
                   If None, uses 'range' param only. Use [] for no params.
        ttl_minutes: Cache TTL in minutes (default: 1)

    Example:
        @bp.route("/api/stats/sources")
        @throttle(5, 10)
        @cached_endpoint(_stats_sources_cache, _lock_sources, key_params=['range', 'limit'])
        def api_stats_sources():
            # Just return the data - caching is handled by decorator
            sources = fetch_sources()
            return {"sources": sources}
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
            win = int(now // (60 * ttl_minutes))

            # Check cache
            with lock:
                if (cache_dict.get("data") and
                    cache_dict.get("key") == cache_key and
                    cache_dict.get("win") == win):
                    return jsonify(cache_dict["data"])

            # Cache miss - call function
            result = func(*args, **kwargs)

            # Store in cache (result should be a dict, not jsonify'd)
            with lock:
                cache_dict["data"] = result
                cache_dict["ts"] = now
                cache_dict["key"] = cache_key
                cache_dict["win"] = win

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
