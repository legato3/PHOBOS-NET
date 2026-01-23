"""Helper utility functions."""
import os
from datetime import datetime, timedelta
from app.config import INTERNAL_NETS, REGION_MAPPING


import ipaddress

FORBIDDEN_HOSTS = {
    'localhost', 'metadata.google.internal', 'instance-data', 
    'metadata', '169.254.169.254'
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
        
    # Robust IP address validation (IPv4 and IPv6)
    try:
        ip_obj = ipaddress.ip_address(host_lower)
        return (
            ip_obj.is_private or 
            ip_obj.is_loopback or 
            ip_obj.is_link_local or 
            ip_obj.is_multicast or
            ip_obj.is_unspecified or
            ip_obj.is_reserved
        )
    except ValueError:
        # Not a direct IP address, could be a hostname
        return False


def get_region(ip, country_iso=None):
    """Get region emoji based on country ISO code from GeoIP lookup."""
    if is_internal(ip):
        return "🏠 Local"
    if country_iso:
        return REGION_MAPPING.get(country_iso.upper(), '🌐 Global')
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
    now = datetime.now()
    hours = {"15m": 0.25, "30m": 0.5, "1h": 1, "6h": 6, "24h": 24, "48h": 48}.get(range_key, 1)
    past = now - timedelta(hours=hours)
    return f"{past.strftime('%Y/%m/%d.%H:%M:%S')}-{now.strftime('%Y/%m/%d.%H:%M:%S')}"


def load_list(path):
    """Load a simple text file and return set of lines (stripped, skipping empty lines and comments)."""
    try:
        with open(path, 'r') as f:
            return set(line.strip() for line in f if line.strip() and not line.startswith('#'))
    except FileNotFoundError:
        return set()


def check_disk_space(path='/var/cache/nfdump'):
    """Check disk space usage for a given path. Returns percentage used."""
    try:
        import shutil
        total, used, free = shutil.disk_usage(path)
        percent_used = (used / total) * 100 if total > 0 else 0
        return {
            'percent_used': round(percent_used, 1),
            'total_gb': round(total / (1024**3), 2),
            'used_gb': round(used / (1024**3), 2),
            'free_gb': round(free / (1024**3), 2),
            'status': 'critical' if percent_used > 90 else 'warning' if percent_used > 75 else 'ok'
        }
    except Exception:
        return {'percent_used': 0, 'status': 'unknown'}