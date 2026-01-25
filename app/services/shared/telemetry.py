"""Anonymous telemetry service for PHOBOS-NET usage tracking."""

import os
import time
import hashlib
import threading
import requests
from datetime import datetime
from app.config import DEBUG_MODE

# Telemetry configuration (enabled by default, can be disabled with TELEMETRY_ENABLED=false)
TELEMETRY_ENABLED = os.environ.get("TELEMETRY_ENABLED", "true").lower() == "true"
TELEMETRY_ENDPOINT = os.environ.get(
    "TELEMETRY_ENDPOINT", "https://phobos-telemetry.onrender.com/api/telemetry"
)
TELEMETRY_TIMEOUT = int(os.environ.get("TELEMETRY_TIMEOUT", "5"))

# Generate anonymous instance ID (persistent across restarts)
INSTANCE_ID_FILE = "data/instance_id.txt"


def _get_instance_id():
    """Get or create anonymous instance ID."""
    try:
        os.makedirs("data", exist_ok=True)

        if os.path.exists(INSTANCE_ID_FILE):
            with open(INSTANCE_ID_FILE, "r") as f:
                return f.read().strip()

        # Create new anonymous ID based on system characteristics
        system_info = f"{os.getenv('HOSTNAME', 'unknown')}-{time.time()}"
        instance_id = hashlib.sha256(system_info.encode()).hexdigest()[:16]

        with open(INSTANCE_ID_FILE, "w") as f:
            f.write(instance_id)

        return instance_id
    except Exception:
        # Fallback to session-based ID
        return hashlib.sha256(f"fallback-{time.time()}".encode()).hexdigest()[:16]


INSTANCE_ID = _get_instance_id()


def _send_telemetry_async(data):
    """Send telemetry data asynchronously."""
    if not TELEMETRY_ENABLED or not TELEMETRY_ENDPOINT:
        return

    def send():
        try:
            response = requests.post(
                TELEMETRY_ENDPOINT,
                json=data,
                timeout=TELEMETRY_TIMEOUT,
                headers={"Content-Type": "application/json"},
            )
            if DEBUG_MODE and response.status_code != 200:
                print(f"Telemetry failed: {response.status_code}")
        except Exception as e:
            if DEBUG_MODE:
                print(f"Telemetry error: {e}")

    # Send in background thread to avoid blocking
    thread = threading.Thread(target=send, daemon=True)
    thread.start()


def track_startup(version=None):
    """Track application startup."""
    data = {
        "instance_id": INSTANCE_ID,
        "event_type": "startup",
        "timestamp": datetime.now().isoformat(),
        "version": version,
        "metadata": {"docker": True, "debug_mode": DEBUG_MODE},
    }
    _send_telemetry_async(data)


def track_shutdown():
    """Track application shutdown."""
    data = {
        "instance_id": INSTANCE_ID,
        "event_type": "shutdown",
        "timestamp": datetime.now().isoformat(),
        "metadata": {"docker": True},
    }
    _send_telemetry_async(data)


def track_feature_usage(feature_name, metadata=None):
    """Track feature usage (dashboard tabs, API endpoints)."""
    data = {
        "instance_id": INSTANCE_ID,
        "event_type": "feature_usage",
        "timestamp": datetime.now().isoformat(),
        "metadata": {"feature": feature_name, "docker": True, **(metadata or {})},
    }
    _send_telemetry_async(data)


def track_error(error_type, metadata=None):
    """Track error occurrences (anonymous)."""
    data = {
        "instance_id": INSTANCE_ID,
        "event_type": "error",
        "timestamp": datetime.now().isoformat(),
        "metadata": {"error_type": error_type, "docker": True, **(metadata or {})},
    }
    _send_telemetry_async(data)


def track_performance_metrics():
    """Track aggregated performance metrics."""
    try:
        from app.services.shared.metrics import get_performance_metrics

        metrics = get_performance_metrics()

        # Send only aggregated, anonymous metrics
        data = {
            "instance_id": INSTANCE_ID,
            "event_type": "performance_summary",
            "timestamp": datetime.now().isoformat(),
            "metadata": {
                "request_count": metrics.get("request_count", 0),
                "error_count": metrics.get("error_count", 0),
                "avg_response_time": (
                    metrics["total_response_time"] / max(metrics["request_count"], 1)
                    if metrics.get("total_response_time")
                    else 0
                ),
                "cache_hit_rate": (
                    metrics["cache_hits"]
                    / max(metrics["cache_hits"] + metrics["cache_misses"], 1)
                    if metrics.get("cache_hits") is not None
                    else 0
                ),
                "docker": True,
            },
        }
        _send_telemetry_async(data)
    except Exception:
        pass  # Don't fail if metrics unavailable
