# Removing phobos_dashboard.py - Migration Requirements

This document outlines what needs to be done before `phobos_dashboard.py` can be safely removed.

## Current Dependencies

`phobos_dashboard.py` is currently used as a bridge pattern in two places:

1. **`app/api/routes.py`** - Imports via `import phobos_dashboard as _phobos`
2. **`app/main.py`** - Imports thread functions and shutdown handlers

## What Still Needs to be Extracted/Migrated

### 1. Decorators
- ✅ **DONE**: Performance tracking functions → `app/services/metrics.py`
- ✅ **DONE**: `throttle` decorator → `app/utils/decorators.py`
  - Extracted to `app/utils/decorators.py`
  - Updated `routes.py` to import from new module
  - Uses `_throttle_lock` and `_request_times` from `app.core.state`

### 2. Functions Still Imported from Bridge

#### Thread Functions (in `app/main.py`)
- ✅ `start_threat_thread` → `app/core/threads.py`
- ✅ `start_trends_thread` → `app/core/threads.py`
- ✅ `start_agg_thread` → `app/core/threads.py`
- ⏭️ `start_syslog_thread` (still in `phobos_dashboard.py` - complex dependencies)
- ⏭️ `_flush_syslog_buffer` (still in `phobos_dashboard.py` - complex dependencies)
- ✅ `_shutdown_event` → `app/core/state.py`

#### SNMP Functions (in `app/api/routes.py`)
- ⏭️ `calculate_cpu_percent_from_stat` (still in `phobos_dashboard.py`)
- ✅ `get_snmp_data` → `app/services/snmp.py`
- ✅ `start_snmp_thread` → `app/services/snmp.py`

#### Config Functions (in `app/api/routes.py`)
- `load_config`
- `save_config`
- `get_default_config`

### 3. Global Variables (Many!)

#### Locks (13 locks)
- `_lock_summary`, `_lock_sources`, `_lock_dests`, `_lock_ports`, `_lock_protocols`
- `_lock_alerts`, `_lock_flags`, `_lock_asns`, `_lock_durations`
- `_lock_bandwidth`, `_lock_flows`, `_lock_countries`, `_cache_lock`
- Plus: `_firewall_db_lock`, `_trends_db_lock`, `_common_data_lock`, `_snmp_cache_lock`, `_syslog_stats_lock`

#### Caches (20+ cache dictionaries)
- `_stats_*_cache` (summary, sources, dests, ports, protocols, alerts, flags, asns, durations, pkts, countries, talkers, services, hourly, flow_stats, proto_mix, net_health)
- `_server_health_cache`
- `_bandwidth_cache`, `_bandwidth_history_cache`
- `_flows_cache`, `_mock_data_cache`
- `_common_data_cache`, `_snmp_cache`

#### State Variables
- `_threat_status`, `_syslog_stats`
- `_metric_*` counters (http_429, bw_cache_hits, flow_cache_hits, nfdump_calls, stats_cache_hits)
- `_has_nfdump`
- Thread flags (`_threat_thread_started`, `_trends_thread_started`, `_agg_thread_started`, `_syslog_thread_started`, `_snmp_thread_started`)
- `_snmp_prev_sample`, `_snmp_backoff`
- `_dns_cache`, `_geo_cache`
- `_trends_db_connect`, `_flush_syslog_buffer`
- `DEBUG_MODE`

### 4. Flask Routes

`phobos_dashboard.py` still contains Flask routes (e.g., `@app.route("/")`), but these are **NOT used** since the application uses Blueprints from `app/api/routes.py`. However, they prevent the file from being safely removed until the Flask app instance is no longer needed.

## Migration Strategy

### Option 1: Full State Management Module (Recommended)
Create `app/core/state.py` to centralize all global state:
- All locks
- All caches
- All state variables
- Thread management
- This allows clean separation and easier testing

### Option 2: Distributed State (Current Pattern)
Keep state in modules where it's used:
- Database locks → `app/db/sqlite.py`
- Cache locks → with their respective caches
- Metrics → `app/services/metrics.py` (already done)
- Threat state → `app/services/threats.py` (partially done)

### Option 3: Hybrid Approach
- Keep critical state centralized
- Distribute less critical state to modules
- Use dependency injection for thread functions

## Steps to Remove phobos_dashboard.py

1. ✅ **Extract all functions** to appropriate modules (mostly done)
2. ✅ **Extract throttle decorator** to `app/utils/decorators.py`
3. ✅ **Extract thread functions** to `app/core/threads.py` (threat, trends, agg threads)
4. ✅ **Extract SNMP functions** to `app/services/snmp.py` (get_snmp_data, start_snmp_thread)
5. ⏭️ **Extract config functions** to `app/utils/config_helpers.py` (partially done)
6. ⏭️ **Extract CPU stat functions** (`calculate_cpu_percent_from_stat`, `read_cpu_stat`)
7. ⏭️ **Migrate all globals** to state management module(s)
8. ⏭️ **Remove Flask routes** from `phobos_dashboard.py` (not used anyway)
9. ⏭️ **Remove Flask app instance** from `phobos_dashboard.py`
10. ✅ **Update all imports** in `app/api/routes.py` and `app/main.py` (thread functions, SNMP functions, throttle)
11. ⏭️ **Remove `phobos_dashboard.py`** file
12. ⏭️ **Test thoroughly** to ensure nothing breaks

## Estimated Effort

**High Complexity** - This is a significant refactoring because:
- Many global variables are tightly coupled
- Thread functions depend on global state
- Cache/lock pairs need to stay together
- Testing is required to ensure nothing breaks

**Recommended Approach**: 
- Do this incrementally
- Extract one category at a time (e.g., all SNMP-related, then all thread-related)
- Test after each major extraction
- Keep the bridge pattern until everything is migrated

## Current Status

- ✅ Many functions extracted to modules
- ✅ Performance metrics extracted
- ✅ Database functions extracted
- ✅ Threat functions extracted
- ✅ Throttle decorator extracted
- ✅ Thread functions extracted (threat, trends, agg threads)
- ✅ SNMP functions extracted (get_snmp_data, start_snmp_thread)
- ✅ SNMP constants added to `app/config.py`
- ✅ SNMP state initialized in `app/core/state.py`
- ⏭️ Still ~50+ global variables to migrate
- ⏭️ Config functions to extract (load_config, save_config, get_default_config)
- ⏭️ CPU stat functions to extract (calculate_cpu_percent_from_stat, read_cpu_stat)
- ⏭️ Syslog thread functions (complex dependencies, deferred)
- ⏭️ State management to organize

**Conclusion**: `phobos_dashboard.py` cannot be removed yet. It's still providing critical infrastructure via the bridge pattern. Full removal requires significant additional refactoring work.
