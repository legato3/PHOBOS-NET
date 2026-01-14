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

### Option 2: Using the Original File (Still Supported)

The original `phobos_dashboard.py` file (renamed from `netflow-dashboard.py`) can still be run directly:

```bash
python3 phobos_dashboard.py
```

## Application Structure

The refactored application uses:
- **Flask App Factory**: `app/__init__.py` creates the Flask application
- **Entry Point**: `app/main.py` starts background threads and runs the Flask app
- **Blueprint Routes**: All routes are in `app/api/routes.py` as Flask Blueprints
- **Services**: Business logic in `app/services/`
- **Utilities**: Helper functions in `app/utils/`

## Dependencies

The application uses a bridge pattern where:
- Routes import functions and globals from `phobos_dashboard.py`
- `app/main.py` imports thread functions from `phobos_dashboard.py`
- This allows the refactored structure to work immediately while maintaining backward compatibility

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

These are imported from `phobos_dashboard.py` using the bridge pattern.

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

# Or using the original file
python3 phobos_dashboard.py
```

Both should work identically as the new structure imports from the original file.

## Future Migration

As the refactoring continues, functions can be gradually moved from `phobos_dashboard.py` to appropriate modules, and the bridge pattern can be phased out.
