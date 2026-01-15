# Observability Implementation Summary

## Overview

Lightweight observability instrumentation has been added to the PROX_NFDUMP codebase to monitor performance and detect regressions without changing application behavior. All instrumentation is **passive**, **thread-safe**, and has **minimal overhead** (<1% typical).

## New Metrics Added

### 1. Subprocess Metrics (`run_nfdump`)
- **Total calls**: Count of all subprocess executions
- **Success/failure/timeout counts**: Breakdown of subprocess outcomes
- **Execution time statistics**: Average, max, p95 execution times
- **Success rate**: Percentage of successful executions

**Location**: `app/services/netflow.py:run_nfdump()`

### 2. Service Function Metrics
- **Call counts**: Number of invocations per service function
- **Execution time**: Average, total, min, max, p95 per service
- **Tracked services**:
  - `calculate_security_score()` - Security score calculation
  - `run_all_detections()` - Threat detection orchestration
  - `get_snmp_data()` - SNMP polling

**Location**: Decorated with `@instrument_service()` in respective service files

### 3. API Request Metrics (Enhanced)
- **Slow request count**: Requests exceeding configurable threshold
- **Per-endpoint statistics**: Already existed, now includes slow request tracking

**Location**: `app/__init__.py` - Flask middleware

### 4. Cache Metrics (Existing, Enhanced)
- Cache hit/miss counts and rates
- Guardrail: Automatic warning when miss rate exceeds threshold

## Metrics Exposure

All metrics are exposed via the existing `/api/performance/metrics` endpoint:

```bash
curl http://localhost:8080/api/performance/metrics
```

### Response Structure

```json
{
  "summary": {
    "total_requests": 1234,
    "avg_response_time_ms": 45.2,
    "slow_requests": 12,
    "cache_hit_rate_percent": 85.3
  },
  "endpoints": { ... },
  "subprocess": {
    "total_calls": 542,
    "success_rate_percent": 99.26,
    "avg_ms": 123.4
  },
  "services": {
    "calculate_security_score": { ... },
    "run_all_detections": { ... },
    "get_snmp_data": { ... }
  }
}
```

## Guardrails

Warning logs are emitted when performance thresholds are exceeded:

### Thresholds (Configurable)

| Guardrail | Default | Environment Variable |
|-----------|---------|---------------------|
| Nfdump execution warning | 5000ms | `OBS_NFDUMP_WARN_MS` |
| Cache miss rate warning | 50% | `OBS_CACHE_MISS_RATE_WARN` |
| Route slow flag | 1000ms | `OBS_ROUTE_SLOW_MS` |
| Route slow warning | 2000ms | `OBS_ROUTE_SLOW_WARN_MS` |
| Service function warning | 500ms | `OBS_SERVICE_SLOW_MS` |

### Warning Format

Warnings are logged to stderr with `[OBSERVABILITY]` prefix:

```
2026-01-15 10:23:45 [OBSERVABILITY] WARNING: Subprocess run_nfdump exceeded threshold: 5234.1ms (threshold: 5000ms)
2026-01-15 10:23:46 [OBSERVABILITY] WARNING: Slow request detected: api_stats_summary took 2345.6ms (threshold: 2000ms) - /api/stats/summary
2026-01-15 10:23:47 [OBSERVABILITY] WARNING: High cache miss rate detected: 52.3% (threshold: 50.0%, hits: 450, misses: 500)
```

## Implementation Details

### Files Modified

1. **app/config.py**: Added observability threshold configuration
2. **app/services/metrics.py**: Extended with subprocess, service, and slow request metrics
3. **app/services/netflow.py**: Instrumented `run_nfdump()` with timing tracking
4. **app/services/stats.py**: Instrumented `calculate_security_score()` with `@instrument_service()`
5. **app/services/threats.py**: Instrumented `run_all_detections()` with `@instrument_service()`
6. **app/services/snmp.py**: Instrumented `get_snmp_data()` with `@instrument_service()`
7. **app/__init__.py**: Added Flask middleware for request duration tracking
8. **app/api/routes.py**: Extended `/api/performance/metrics` endpoint with new metrics
9. **app/utils/observability.py**: New module with instrumentation decorators and guardrails
10. **README.md**: Added observability documentation section

### Thread Safety

All metrics are thread-safe:
- Metrics use `threading.Lock()` for concurrent access
- Flask `g` object used for per-request state (thread-local)
- No race conditions in metrics collection

### Performance Impact

- **Overhead**: <1% typical (measurement overhead minimal)
- **Memory**: Bounded (last 100 subprocess times, last 50 service times per service, last 100 endpoint times)
- **No blocking**: All operations are non-blocking except lock acquisition (microseconds)

## How to Interpret Metrics

### Subprocess Metrics

- **High timeout_count**: nfdump may be under heavy load or network issues
- **High avg_ms**: Consider optimizing nfdump queries or reducing time ranges
- **Low success_rate_percent**: Check nfdump availability and data directory

### Service Metrics

- **High avg_ms for `calculate_security_score`**: Database queries may be slow, check firewall DB
- **High avg_ms for `run_all_detections`**: Large datasets or many detection algorithms triggering
- **High avg_ms for `get_snmp_data`**: SNMP host may be slow or network issues

### API Metrics

- **High slow_requests**: Identify slow endpoints from `endpoints` statistics
- **High cache miss rate**: Cache TTL may be too short or cache invalidation too aggressive
- **High error_rate_percent**: Application errors, check application logs

## Monitoring Recommendations

1. **Dashboard**: Poll `/api/performance/metrics` every 60 seconds
2. **Alerting**: Set up alerts for:
   - Cache miss rate > 70%
   - Subprocess timeout count > 10/hour
   - Slow requests > 5% of total requests
   - Service function avg_ms > 2x baseline
3. **Logs**: Monitor stderr for `[OBSERVABILITY]` warnings
4. **Baseline**: Establish baseline metrics after deployment to detect regressions

## Disabling Observability

Observability is lightweight by design, but can be effectively disabled by:

1. **Raising thresholds** to very high values:
   ```bash
   export OBS_NFDUMP_WARN_MS=999999
   export OBS_ROUTE_SLOW_WARN_MS=999999
   export OBS_SERVICE_SLOW_MS=999999
   ```

2. **Disabling logger output**:
   ```python
   import logging
   logging.getLogger('prox_nfdump.observability').setLevel(logging.CRITICAL)
   ```

Metrics will still be collected but warnings will not be logged.

## Future Enhancements (Not Implemented)

These were explicitly avoided per requirements:
- ❌ Prometheus/OpenTelemetry exporters
- ❌ Heavy logging or per-packet logging
- ❌ Background jobs or async processing
- ❌ External dependencies

Potential future additions (if needed):
- Export metrics to external systems (via webhook)
- Additional service function instrumentation
- Historical trend analysis
