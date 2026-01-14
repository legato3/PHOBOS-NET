# Refactoring Status

## Completed

### 1. Directory Structure ✅
- Created `app/` directory with subdirectories:
  - `app/api/` - API routes
  - `app/services/` - Business logic services
  - `app/db/` - Database operations
  - `app/utils/` - Utility functions
- Created `frontend/` directory
- Created `tests/` directory

### 2. Configuration Module ✅
- Created `app/config.py` with:
  - All constants (cache TTLs, thresholds, paths)
  - Environment variable handling
  - Network configuration
  - Port/protocol mappings
  - MITRE ATT&CK mappings
  - Region mappings
  - Default thresholds

### 3. Utilities Module ✅
- Created `app/utils/__init__.py` - Module exports
- Created `app/utils/helpers.py` - Helper functions:
  - `is_internal()` - Check if IP is internal
  - `get_region()` - Get region for IP
  - `flag_from_iso()` - Convert ISO to flag emoji
  - `format_duration()` - Format duration strings
  - `fmt_bytes()` - Format bytes
  - `get_time_range()` - Get nfdump time range
  - `load_list()` - Load text file as list of lines
  - `check_disk_space()` - Check disk space for a path
- Created `app/utils/geoip.py` - GeoIP lookups:
  - `load_city_db()` - Load MaxMind City DB
  - `load_asn_db()` - Load MaxMind ASN DB
  - `lookup_geo()` - Lookup geographic info
- Created `app/utils/dns.py` - DNS resolution:
  - `resolve_hostname()` - Resolve IP to hostname
  - `resolve_ip()` - Cached DNS resolution
- Created `app/utils/formatters.py` - Formatting utilities:
  - `format_duration()` - Format duration strings (alias)
  - `format_time_ago()` - Format timestamp as "time ago" string
  - `format_uptime()` - Format uptime string to human-readable format
- Created `app/utils/config_helpers.py` - Configuration file helpers:
  - `load_notify_cfg()` - Load notification configuration
  - `save_notify_cfg()` - Save notification configuration
  - `load_thresholds()` - Load thresholds configuration
  - `save_thresholds()` - Save thresholds configuration
  - `DEFAULT_THRESHOLDS` - Default threshold values

### 4. NetFlow Service Module ✅
- Created `app/services/__init__.py`
- Created `app/services/netflow.py` with:
  - `run_nfdump()` - Execute nfdump commands with fallback to mock
  - `parse_csv()` - Parse nfdump CSV output with dynamic column detection
  - `mock_nfdump()` - Mock nfdump for development/testing
  - `get_traffic_direction()` - Get upload/download traffic for an IP
  - `get_common_nfdump_data()` - Shared data fetcher for common queries

### 5. Database Module ✅
- Created `app/db/__init__.py`
- Created `app/db/sqlite.py` with:
  - `_trends_db_connect()` - Connect to trends database with WAL mode
  - `_trends_db_init()` - Initialize trends database schema
  - `_firewall_db_connect()` - Connect to firewall database with WAL mode
  - `_firewall_db_init()` - Initialize firewall database schema
  - `_get_firewall_block_stats()` - Query firewall block statistics
  - `_cleanup_old_fw_logs()` - Clean up old firewall logs
  - Database locks preserved (`_trends_db_lock`, `_firewall_db_lock`)
  - Uses configuration from `app.config`

### 6. Threats Service Module ✅
- Created `app/services/threats.py` with:
  - **Phase 1 (Completed)**: Threat feed and watchlist functions
    - `parse_feed_line()` - Parse threat feed line format
    - `fetch_threat_feed()` - Fetch and aggregate multiple threat feeds
    - `get_threat_info()` - Get threat category and MITRE mappings
    - `update_threat_timeline()` - Track threat IP timeline
    - `get_threat_timeline()` - Get threat timeline info
    - `load_watchlist()` - Load custom watchlist IPs
    - `add_to_watchlist()` - Add IP to watchlist
    - `remove_from_watchlist()` - Remove IP from watchlist
  - **Phase 2 (Completed)**: Detection functions
    - `send_security_webhook()` - Send threat data to security webhook
    - `detect_anomalies()` - Main anomaly detection function
    - `detect_port_scan()` - Detect port scanning activity
    - `detect_brute_force()` - Detect brute force attempts
    - `detect_data_exfiltration()` - Detect data exfiltration
    - `detect_dns_anomaly()` - Detect DNS tunneling
    - `detect_new_external()` - Detect new external connections
    - `detect_lateral_movement()` - Detect lateral movement
    - `detect_protocol_anomaly()` - Detect protocol anomalies
    - `detect_off_hours_activity()` - Detect off-hours activity
    - `run_all_detections()` - Run all detection algorithms
  - Detection-related global state variables moved

### 7. Stats Service Module ✅
- Created `app/services/stats.py` (minimal - most statistics computed in API routes)

### 8. API Routes ✅

**Status:** All 68 routes extracted to `app/api/routes.py`

#### app/api/routes.py
- **Total Routes:** 68 routes extracted (4,593 lines)
- **Strategy:** Systematic extraction using Python script
- **Result:** All routes extracted verbatim, `@app.route()` changed to `@bp.route()`
- **Route Categories:**
  1. Main Routes (1)
  2. Stats API Routes (24)
  3. Firewall API Routes (4)
  4. Security API Routes (17)
  5. Trends Routes (2)
  6. General API Routes (17)
  7. System Routes (7)
  8. Forensics Routes (2)
  9. Ollama Routes (2)

**Note:** Routes import functions and globals from `phobos_dashboard.py` using a bridge pattern for backward compatibility.

## In Progress

### 9. Application Initialization ✅

#### app/__init__.py ✅
- ✅ Created Flask app factory (`create_app()`)
- ✅ Configured compression
- ✅ Registered routes blueprint
- ✅ Setup security headers middleware (`set_security_headers`)
- ✅ Created app instance for backward compatibility
- ✅ Configured static and template folders (`frontend/static/`, `frontend/templates/`)

#### app/main.py ✅
- ✅ Created entry point structure
- ✅ Port finding logic (`_find_open_port`)
- ✅ Import thread functions from `phobos_dashboard`
- ✅ Graceful shutdown handler implemented
- ✅ Background services startup
- ✅ Flask app execution

### 10. Frontend Migration ✅
- ✅ Moved `static/` to `frontend/static/`
- ✅ Moved `templates/` to `frontend/templates/`
- ✅ Updated paths in Flask app configuration


## Key Functions to Extract

### NetFlow Service ✅ (COMPLETED)
- `run_nfdump()` - Extracted to `app/services/netflow.py`
- `parse_csv()` - Extracted to `app/services/netflow.py`
- `mock_nfdump()` - Extracted to `app/services/netflow.py`
- `get_common_nfdump_data()` - Extracted to `app/services/netflow.py`
- `get_traffic_direction()` - Extracted to `app/services/netflow.py`

### Threats Service ✅ (COMPLETED)
- `parse_feed_line()` - Extracted to `app/services/threats.py`
- `fetch_threat_feed()` - Extracted to `app/services/threats.py`
- `get_threat_info()` - Extracted to `app/services/threats.py`
- `update_threat_timeline()` - Extracted to `app/services/threats.py`
- `get_threat_timeline()` - Extracted to `app/services/threats.py`
- `load_watchlist()` - Extracted to `app/services/threats.py`
- `add_to_watchlist()` - Extracted to `app/services/threats.py`
- `remove_from_watchlist()` - Extracted to `app/services/threats.py`
- `send_security_webhook()` - Extracted to `app/services/threats.py`
- `detect_anomalies()` - Extracted to `app/services/threats.py`
- `detect_port_scan()` - Extracted to `app/services/threats.py`
- `detect_brute_force()` - Extracted to `app/services/threats.py`
- `detect_data_exfiltration()` - Extracted to `app/services/threats.py`
- `detect_dns_anomaly()` - Extracted to `app/services/threats.py`
- `detect_new_external()` - Extracted to `app/services/threats.py`
- `detect_lateral_movement()` - Extracted to `app/services/threats.py`
- `detect_protocol_anomaly()` - Extracted to `app/services/threats.py`
- `detect_off_hours_activity()` - Extracted to `app/services/threats.py`
- `run_all_detections()` - Extracted to `app/services/threats.py`

### Stats Service ✅ (COMPLETED)
- Minimal module created (most statistics computed in API routes)

### Database ✅ (COMPLETED)
- `_trends_db_connect()` - Extracted to `app/db/sqlite.py`
- `_trends_db_init()` - Extracted to `app/db/sqlite.py`
- `_firewall_db_connect()` - Extracted to `app/db/sqlite.py`
- `_firewall_db_init()` - Extracted to `app/db/sqlite.py`
- `_get_firewall_block_stats()` - Extracted to `app/db/sqlite.py`
- `_cleanup_old_fw_logs()` - Extracted to `app/db/sqlite.py`


## Refactoring Complete

All major refactoring milestones have been completed:
- ✅ Configuration module (`app/config.py`)
- ✅ Utilities module (`app/utils/` - helpers, geoip, dns, formatters)
- ✅ NetFlow service module (`app/services/netflow.py`)
- ✅ Database module (`app/db/sqlite.py`)
- ✅ Threats service module (`app/services/threats.py`) - Phase 1 & 2 complete
- ✅ Stats service module (`app/services/stats.py` - minimal)
- ✅ API Routes module (`app/api/routes.py` - all 68 routes extracted)

**Major Tasks - All Complete:**
- ✅ Extract 68 Flask routes to `app/api/routes.py` (COMPLETED - 4,593 lines)
- ✅ Create `app/__init__.py` (Flask app initialization and Blueprint registration)
- ✅ Create `app/main.py` (WSGI entry point)
- ✅ Resolve route dependencies (routes now import from phobos_dashboard) - Bridge pattern implemented
- ✅ Migrate frontend assets (`static/` and `templates/` to `frontend/`)
- ✅ Rename `netflow-dashboard.py` to `phobos_dashboard.py` for Python imports

**Optional Future Tasks - In Progress:**
- ✅ Further extraction continued:
  - ✅ Created `app/utils/config_helpers.py` (load/save notify config, thresholds)
  - ✅ Added `format_time_ago()`, `format_uptime()` to `app/utils/formatters.py`
  - ✅ Added `load_list()`, `check_disk_space()` to `app/utils/helpers.py`
  - ✅ Updated routes to import `format_duration()` from `app/utils/helpers.py` (was already there)
  - ✅ Routes now import these functions directly instead of from phobos_dashboard
  - ✅ Extracted `load_threatlist()`, `get_feed_label()`, `send_notifications()` (and dependencies) to `app/services/threats.py`
  - ⏭️ Still remaining: `load_config`, `save_config`, `get_default_config` (modify globals, more complex)
  - ⏭️ Other helper functions that can be extracted (e.g., `calculate_security_score`, SNMP functions)
- ⏭️ Create state management module for globals (if desired)
- ⏭️ Remove unused code from `phobos_dashboard.py` (when ready)
- ⏭️ Update deployment documentation

## Summary

All major refactoring milestones have been completed:
- ✅ Modular structure created
- ✅ All routes extracted to Blueprints
- ✅ Services, utilities, and database modules extracted
- ✅ Application initialization structure in place
- ✅ Frontend assets migrated
- ✅ Dependencies resolved via bridge pattern

The application is now organized into a clean, modular architecture following Python best practices. Routes import from `phobos_dashboard.py` (renamed from `netflow-dashboard.py`) to access globals and functions, using a pragmatic bridge pattern that allows the refactoring to work immediately.

The refactoring is complete and ready for testing. See `docs/RUNNING_THE_APP.md` for instructions on running the application.