"""Observability utilities for PHOBOS-NET application.

This module provides lightweight instrumentation for performance monitoring
and guardrails without changing application behavior.
"""

import logging
import time
import functools
from app.config import OBS_NFDUMP_WARN_MS, OBS_CACHE_MISS_RATE_WARN, OBS_SERVICE_SLOW_MS
from app.services.shared.metrics import track_subprocess, track_service

# Configure logger for observability warnings
_logger = logging.getLogger("prox_nfdump.observability")
_logger.setLevel(logging.WARNING)  # Only log warnings/errors by default
if not _logger.handlers:
    handler = logging.StreamHandler()
    handler.setFormatter(
        logging.Formatter(
            "%(asctime)s [OBSERVABILITY] %(levelname)s: %(message)s",
            datefmt="%Y-%m-%d %H:%M:%S",
        )
    )
    _logger.addHandler(handler)


def instrument_subprocess(func):
    """Decorator to instrument subprocess calls (e.g., run_nfdump).

    Tracks execution time, success/failure, and timeouts.
    Logs warnings when execution exceeds threshold.
    """

    @functools.wraps(func)
    def wrapper(*args, **kwargs):
        start_time = time.time()
        success = False
        timeout = False

        try:
            result = func(*args, **kwargs)
            success = True
            return result
        except Exception as e:
            # Check if it's a timeout
            if "timeout" in str(e).lower() or "TimeoutExpired" in str(type(e).__name__):
                timeout = True
            raise
        finally:
            duration = time.time() - start_time
            duration_ms = duration * 1000

            # Track metrics
            track_subprocess(duration, success, timeout)

            # Guardrail: Warn if execution exceeds threshold
            if duration_ms > OBS_NFDUMP_WARN_MS:
                _logger.warning(
                    f"Subprocess {func.__name__} exceeded threshold: {duration_ms:.1f}ms "
                    f"(threshold: {OBS_NFDUMP_WARN_MS}ms)"
                )

    return wrapper


def instrument_service(service_name):
    """Decorator to instrument service functions (stats aggregation, threat detection, SNMP).

    Tracks execution time and call counts.
    Logs warnings when execution exceeds threshold.
    """

    def decorator(func):
        @functools.wraps(func)
        def wrapper(*args, **kwargs):
            start_time = time.time()
            try:
                result = func(*args, **kwargs)
                return result
            finally:
                duration = time.time() - start_time
                duration_ms = duration * 1000

                # Track metrics
                track_service(service_name, duration)

                # Guardrail: Warn if execution exceeds threshold
                if duration_ms > OBS_SERVICE_SLOW_MS:
                    _logger.warning(
                        f"Service {service_name} exceeded threshold: {duration_ms:.1f}ms "
                        f"(threshold: {OBS_SERVICE_SLOW_MS}ms)"
                    )

        return wrapper

    return decorator


def check_cache_miss_rate():
    """Check cache miss rate and warn if it exceeds threshold.

    Should be called periodically (e.g., after every 100 requests).
    """
    from app.services.shared.metrics import get_performance_metrics

    metrics = get_performance_metrics()
    cache_hits = metrics.get("cache_hits", 0)
    cache_misses = metrics.get("cache_misses", 0)
    total = cache_hits + cache_misses

    if total > 0:
        miss_rate = cache_misses / total
        if miss_rate > OBS_CACHE_MISS_RATE_WARN:
            _logger.warning(
                f"High cache miss rate detected: {miss_rate:.1%} "
                f"(threshold: {OBS_CACHE_MISS_RATE_WARN:.1%}, "
                f"hits: {cache_hits}, misses: {cache_misses})"
            )
