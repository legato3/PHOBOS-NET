# Running the Refactored Application

## Overview

After the refactoring, the application can be run using the new modular structure. This document explains how to run the application.

## Entry Points

### Option 1: Using the New Modular Structure (Recommended)

```bash
# From the project root
python3 -m app.main
```

Or:

```bash
# From the project root
python3 app/main.py
```


## Application Structure

The refactored application uses:
- **Flask App Factory**: `app/__init__.py` creates the Flask application
- **Entry Point**: `app/main.py` starts background threads and runs the Flask app
- **Blueprint Routes**: All routes are in `app/api/routes.py` as Flask Blueprints
- **Services**: Business logic in `app/services/`
- **Utilities**: Helper functions in `app/utils/`

## Dependencies

The application now runs fully from the modular structure:
- Routes are served from `app/api/routes.py` via a single Blueprint
- Background threads start via `app/core/threads.py` and `app/services/syslog.py`

## Environment Variables

The application respects the same environment variables as before:

```bash
export FLASK_HOST=0.0.0.0
export FLASK_PORT=8080
export FLASK_DEBUG=false
```

## Background Threads

The application starts the following background threads (via `app/main.py`):
- `start_threat_thread()` - Threat feed fetching
- `start_trends_thread()` - Trends aggregation
- `start_agg_thread()` - Data aggregation
- `start_syslog_thread()` - Syslog receiver
- `start_firewall_syslog_thread()` - Isolated firewall syslog listener (UDP/515)

These are imported from `app/core/threads.py` and `app/services/syslog.py`.

## Flask Application

The Flask application is created by `app/__init__.py`:
- Uses Flask Blueprints for routes
- Configured with compression
- Security headers middleware
- Static files served from `frontend/static/`
- Templates loaded from `frontend/templates/`

## Testing the Application

To verify the refactored application works:

```bash
# Start the application
python3 app/main.py

```

The modular entrypoint (`app/main.py`) is the recommended way to run the application.

## Future Migration

The legacy `phobos_dashboard.py` entrypoint has been retired in favor of the modular runtime.
