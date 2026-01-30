"""Helper utility functions."""

from datetime import datetime, timedelta
from functools import lru_cache
from app.config import INTERNAL_NETS, REGION_MAPPING


import ipaddress

FORBIDDEN_HOSTS = {
    "localhost",
    "metadata.google.internal",
    "instance-data",
    "metadata",
    "169.254.169.254",
}


def is_internal(host_or_ip):
    """Check if host or IP is internal, private, or restricted for SSRF protection."""
    if not host_or_ip:
        return False

    host_lower = str(host_or_ip).lower().strip()

    # Check against known forbidden hostnames/domains
    if host_lower in FORBIDDEN_HOSTS:
        return True

    # Check if it starts with internal net prefixes (legacy fallback/string match)
    if host_lower.startswith(INTERNAL_NETS):
        return True

    return _check_ip_address(host_lower)


@lru_cache(maxsize=10000)
def _check_ip_address(ip_str):
    """Check if an IP string is internal/private (cached)."""
    # Optimized Fast Path for standard IPv4 to avoid ipaddress overhead
    if "." in ip_str and ":" not in ip_str:
        parts = ip_str.split(".")
        if len(parts) == 4:
            # Check for leading zeros (octal ambiguity prevention)
            # ipaddress module strictly forbids leading zeros, so we must too
            if (
                (len(parts[0]) > 1 and parts[0].startswith("0"))
                or (len(parts[1]) > 1 and parts[1].startswith("0"))
                or (len(parts[2]) > 1 and parts[2].startswith("0"))
                or (len(parts[3]) > 1 and parts[3].startswith("0"))
            ):
                pass  # Fallback to ipaddress (which will raise ValueError)
            else:
                try:
                    a = int(parts[0])
                    b = int(parts[1])
                    c = int(parts[2])
                    d = int(parts[3])

                    # Check valid range for all octets first
                    if not (
                        0 <= a <= 255
                        and 0 <= b <= 255
                        and 0 <= c <= 255
                        and 0 <= d <= 255
                    ):
                        return False

                    if a == 10:
                        return True
                    if a == 127:
                        return True
                    if a == 169 and b == 254:
                        return True

                    if a == 172 and 16 <= b <= 31:
                        return True

                    if a == 192:
                        if b == 168:
                            return True
                        if b == 0 and c == 2:
                            return True  # Test-Net-1

                    if a == 198:
                        if 18 <= b <= 19:
                            return True  # Benchmarking
                        if b == 51 and c == 100:
                            return True  # Test-Net-2

                    if a == 203:
                        if b == 0 and c == 113:
                            return True  # Test-Net-3

                    if 224 <= a <= 239:
                        return True  # Multicast
                    if a >= 240:
                        return True  # Class E / Reserved
                    if a == 0:
                        return True  # Unspecified/Current network

                    return False  # Valid Public IPv4
                except ValueError:
                    pass  # Fallback to ipaddress

    # Robust IP address validation (IPv6 and complex cases)
    try:
        ip_obj = ipaddress.ip_address(ip_str)
        return (
            ip_obj.is_private
            or ip_obj.is_loopback
            or ip_obj.is_link_local
            or ip_obj.is_multicast
            or ip_obj.is_unspecified
            or ip_obj.is_reserved
        )
    except ValueError:
        # Not a direct IP address, could be a hostname
        return False


def get_region(ip, country_iso=None):
    """Get region emoji based on country ISO code from GeoIP lookup."""
    if is_internal(ip):
        return "🏠 Local"
    if country_iso:
        return REGION_MAPPING.get(country_iso.upper(), "🌐 Global")
    return "🌐 Global"


def flag_from_iso(iso):
    """Convert ISO country code to flag emoji."""
    if not iso or len(iso) != 2:
        return ""
    return chr(ord(iso[0].upper()) + 127397) + chr(ord(iso[1].upper()) + 127397)


def format_duration(seconds):
    """Format duration in seconds to human-readable string."""
    if seconds < 60:
        return f"{int(seconds)}s"
    elif seconds < 3600:
        return f"{int(seconds) // 60}m"
    else:
        return f"{int(seconds) // 3600}h"


def fmt_bytes(b):
    """Format bytes to human-readable string."""
    if b >= 1024**3:
        return f"{b / 1024**3:.2f} GB"
    elif b >= 1024**2:
        return f"{b / 1024**2:.2f} MB"
    elif b >= 1024:
        return f"{b / 1024:.2f} KB"
    return f"{b} B"


def get_time_range(range_key):
    """Convert range key to nfdump time range string."""
    # Round to minute to improve cache hit rate for nfdump queries
    now = datetime.now().replace(second=0, microsecond=0)
    hours = {
        "15m": 0.25,
        "30m": 0.5,
        "1h": 1,
        "4h": 4,
        "6h": 6,
        "12h": 12,
        "24h": 24,
        "48h": 48,
        "3d": 72,
        "7d": 168,
        "30d": 720,
    }.get(range_key, 1)
    past = now - timedelta(hours=hours)
    return f"{past.strftime('%Y/%m/%d.%H:%M:%S')}-{now.strftime('%Y/%m/%d.%H:%M:%S')}"


def load_list(path):
    """Load a simple text file and return set of lines (stripped, skipping empty lines and comments)."""
    try:
        with open(path, "r") as f:
            return set(
                line.strip() for line in f if line.strip() and not line.startswith("#")
            )
    except FileNotFoundError:
        return set()


def check_disk_space(path="/var/cache/nfdump"):
    """Check disk space usage for a given path. Returns percentage used."""
    try:
        import shutil

        total, used, free = shutil.disk_usage(path)
        percent_used = (used / total) * 100 if total > 0 else 0
        return {
            "percent_used": round(percent_used, 1),
            "total_gb": round(total / (1024**3), 2),
            "used_gb": round(used / (1024**3), 2),
            "free_gb": round(free / (1024**3), 2),
            "status": "critical"
            if percent_used > 90
            else "warning"
            if percent_used > 75
            else "ok",
        }
    except Exception:
        return {"percent_used": 0, "status": "unknown"}


def validate_ip_input(ip):
    """Validate IP/Host input to prevent argument injection.

    Rejects inputs starting with '-' to prevent flag injection.
    Rejects inputs containing shell metacharacters to prevent command chaining.
    """
    if not ip:
        return ip

    ip_str = str(ip).strip()

    # prevent flag injection
    if ip_str.startswith("-"):
        raise ValueError("Invalid IP/Host: Argument injection detected")

    # prevent shell metacharacters (defense in depth)
    forbidden_chars = [";", "&", "|", "`", "$", "(", ")", "<", ">", "!"]
    if any(char in ip_str for char in forbidden_chars):
        raise ValueError("Invalid IP/Host: Shell metacharacters detected")

    return ip_str
