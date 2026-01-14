# Dependency Resolution Plan

## Overview

Routes in `app/api/routes.py` need access to functions and global variables from `netflow-dashboard.py`. This document outlines the dependency resolution strategy.

## Challenge

Python cannot import from files with hyphens in the name (`netflow-dashboard.py`) using normal import syntax. We need to either:
1. Use `importlib` to dynamically import
2. Move all dependencies to importable modules
3. Keep netflow-dashboard.py as a module (rename it)

## Dependencies Required

### 1. Decorator
- `throttle` - Rate limiting decorator (needs `_request_times`, `_throttle_lock`, `_metric_http_429`, `track_error`, `track_performance`)

### 2. Helper Functions
- `load_notify_cfg()` - Load notification configuration
- `calculate_security_score()` - Calculate security score
- `load_threatlist()` - Load threat list (uses `_threat_cache`)
- `format_duration()` - Format duration string (already in utils/formatters.py as `format_duration`)
- `check_disk_space()` - Check disk space
- `calculate_cpu_percent_from_stat()` - Calculate CPU usage
- `get_snmp_data()` - Get SNMP data
- `track_performance()` - Track performance metrics
- `track_error()` - Track errors
- `_get_bucket_end()` - Get bucket end time
- `_ensure_rollup_for_bucket()` - Ensure rollup exists

### 3. Thread Functions
- `start_threat_thread()`
- `start_trends_thread()`
- `start_agg_thread()`
- `start_syslog_thread()`
- `_flush_syslog_buffer()` (used by shutdown handler)

### 4. Global Variables
Routes reference hundreds of global variables including:
- Locks: `_lock_summary`, `_lock_sources`, `_lock_dests`, etc.
- Caches: `_stats_summary_cache`, `_stats_sources_cache`, `_bandwidth_cache`, etc.
- State: `_threat_status`, `_threat_timeline`, `_syslog_stats`, etc.
- Metrics: `_metric_http_429`, `_performance_metrics`, etc.

## Resolution Strategy

### Phase 1: Extract Helper Functions
Extract functions that can be extracted independently to `app/utils/` modules:
- `format_duration` - Already exists in `app/utils/formatters.py`
- `load_notify_cfg` - Extract to `app/utils/config.py` or `app/utils/helpers.py`
- `check_disk_space` - Extract to `app/utils/system.py`
- Other helpers as appropriate

### Phase 2: Extract Throttle Decorator
Create `app/utils/decorators.py` with throttle decorator and its dependencies:
- Extract `track_performance`, `track_error` functions
- Extract `_request_times`, `_throttle_lock`, `_metric_http_429` globals
- Extract `throttle` decorator

### Phase 3: Extract Thread Functions
Create `app/core/threads.py` with thread management:
- Extract thread start functions
- Extract thread-related state

### Phase 4: Handle Global State
Options:
1. **Create `app/core/state.py`** - Move ALL globals to a centralized state module
2. **Use importlib bridge** - Create temporary bridge module using importlib to access netflow-dashboard.py
3. **Keep in main file** - Leave globals in netflow-dashboard.py until full refactor is complete

**Recommendation:** Option 1 (state module) is cleanest long-term, but requires moving all globals.

## Current Status

- Routes extracted ✅
- Dependencies identified ⏭️
- Helper functions extracted ⏭️
- Throttle decorator extracted ⏭️
- Thread functions extracted ⏭️
- Global state handled ⏭️

## Next Steps

1. Extract helper functions to utils modules
2. Extract throttle decorator with dependencies
3. Extract thread functions
4. Decide on global state strategy and implement
5. Update routes.py imports
6. Test that routes work
