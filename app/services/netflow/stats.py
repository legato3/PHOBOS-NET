"""Statistics service for PHOBOS-NET application."""
import time
import threading
from app.db.sqlite import _get_firewall_block_stats
from app.services.shared.observability import instrument_service
# Import threat module to access globals
import app.services.security.threats as threats_module

# Cache for security score calculation (30s TTL to reduce redundant DB queries)
_security_score_cache = {"data": None, "ts": 0}
_security_score_lock = threading.Lock()
_SECURITY_SCORE_CACHE_TTL = 30  # 30 seconds


@instrument_service('calculate_security_observability')
def calculate_security_observability(range_key='1h'):
    """Calculate security observability state based on current threat state and firewall activity.
    
    Returns descriptive state language and contributing factors without scoring.
    """
    now = time.time()
    
    # Map range keys to hours
    range_map = {
        '15m': 0.25, '30m': 0.5, '1h': 1, '6h': 6, '24h': 24, '7d': 168
    }
    hours = range_map.get(range_key, 1)
    range_seconds = hours * 3600
    
    cache_key = f"{range_key}"
    with _security_score_lock:
        if _security_score_cache.get("data") and _security_score_cache.get("key") == cache_key and now - _security_score_cache["ts"] < _SECURITY_SCORE_CACHE_TTL:
            return _security_score_cache["data"]
    
    # Initialize observability state
    overall_state = "UNKNOWN"
    contributing_factors = []
    
    # Get firewall block stats (dynamic range)
    fw_stats = _get_firewall_block_stats(hours=hours)
    
    # PERFORMANCE: Compute active threat count once
    cutoff = now - range_seconds
    threat_count = sum(1 for ip, data in threats_module._threat_timeline.items() 
                      if data.get('last_seen', 0) > cutoff)
    
    # Categorize signals
    protection_signals = []
    exposure_signals = []
    data_quality_signals = []
    
    # Protection signals
    threats_blocked = fw_stats.get('threats_blocked', 0)
    if threats_blocked > 0:
        protection_signals.append(f"Firewall blocked {threats_blocked} known threats")
    
    if fw_stats.get('blocks', 0) > (10 * hours):
        protection_signals.append("Firewall actively blocking attacks")
    
    # Exposure signals
    if threat_count > 0:
        exposure_signals.append(f"{threat_count} active threats detected")
    
    if fw_stats.get('blocks_per_hour', 0) > 100:
        exposure_signals.append(f"High attack rate: {fw_stats['blocks_per_hour']}/hour")
    
    # Data Quality signals
    feeds_ok = sum(1 for f in threats_module._feed_status.values() if f.get('status') == 'ok')
    feeds_total = len(threats_module._feed_status)
    if feeds_total > 0 and feeds_ok < feeds_total:
        data_quality_signals.append(f"{feeds_total - feeds_ok} threat feeds unavailable")
    
    total_ips = threats_module._threat_status.get('size', 0)
    if total_ips < 10000:
        data_quality_signals.append("Limited blocklist coverage")
    elif total_ips >= 50000:
        data_quality_signals.append("Good blocklist coverage")
    
    # Recent critical alerts
    recent_critical = 0
    with threats_module._alert_history_lock:
        for alert in threats_module._alert_history:
            if alert.get('severity') == 'critical' and now - alert.get('ts', 0) < range_seconds:
                recent_critical += 1
    if recent_critical > 0:
        exposure_signals.append(f"{recent_critical} critical alerts in selected range")
    
    # Determine overall state
    if recent_critical > 0 or threat_count > (5 * hours):
        overall_state = "UNDER PRESSURE"
    elif threat_count > 0 or fw_stats.get('blocks_per_hour', 0) > 100:
        overall_state = "DEGRADED"
    elif feeds_ok < feeds_total:
        overall_state = "ELEVATED"
    elif fw_stats.get('blocks', 0) > 0 or threats_blocked > 0:
        overall_state = "STABLE"
    elif total_ips >= 10000:
        overall_state = "STABLE"
    else:
        overall_state = "QUIET"
    
    # Build contributing factors
    if protection_signals: contributing_factors.extend(protection_signals)
    if exposure_signals: contributing_factors.extend(exposure_signals)
    if data_quality_signals: contributing_factors.extend(data_quality_signals)
    
    result = {
        'overall_state': overall_state,
        'contributing_factors': contributing_factors,
        'protection_signals': protection_signals,
        'exposure_signals': exposure_signals,
        'data_quality_signals': data_quality_signals,
        'threats_active': threat_count,
        'feeds_ok': feeds_ok,
        'feeds_total': feeds_total,
        'blocklist_ips': total_ips,
        'firewall': fw_stats,
        'last_updated': time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(now)),
        'range': range_key
    }
    
    with _security_score_lock:
        _security_score_cache["data"] = result
        _security_score_cache["ts"] = now
        _security_score_cache["key"] = cache_key
    
    return result


# Legacy function for backward compatibility
def calculate_security_score(range_key='1h'):
    """Legacy wrapper for backward compatibility."""
    return calculate_security_observability(range_key)
