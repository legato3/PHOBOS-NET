"""Formatter utilities."""
import time
from .helpers import fmt_bytes

# Alias for backwards compatibility
format_bytes = fmt_bytes


def format_time_ago(ts):
    """Format timestamp as human-readable time ago string."""
    if not ts:
        return "never"
    diff = time.time() - ts
    if diff < 60:
        return f"{int(diff)}s ago"
    elif diff < 3600:
        return f"{int(diff/60)}m ago"
    elif diff < 86400:
        return f"{int(diff/3600)}h ago"
    else:
        return f"{int(diff/86400)}d ago"


def format_uptime(uptime_str):
    """Convert uptime string '0:17:42:05.92' to human-readable '17h 42m'."""
    parts = uptime_str.split(':')
    if len(parts) >= 3:
        hours = int(parts[1])
        minutes = int(parts[2].split('.')[0])
        return f"{hours}h {minutes}m"
    return uptime_str