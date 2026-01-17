"""Statistics service for PROX_NFDUMP application."""
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
def calculate_security_observability():
    """Calculate security observability state based on current threat state and firewall activity.
    
    Returns descriptive state language and contributing factors without scoring.
    
    OBSERVABILITY: Instrumented to track execution time and call frequency.
    """
    # PERFORMANCE: Cache result for 30s to reduce redundant DB queries and timeline iterations
    now = time.time()
    with _security_score_lock:
        if _security_score_cache["data"] and now - _security_score_cache["ts"] < _SECURITY_SCORE_CACHE_TTL:
            return _security_score_cache["data"]
    
    # Initialize observability state
    overall_state = "UNKNOWN"
    contributing_factors = []
    
    # Get firewall block stats (expensive DB query - cached at function level)
    fw_stats = _get_firewall_block_stats(hours=1)
    
    # PERFORMANCE: Compute active threat count once instead of filtering list comprehension each time
    now_ts = time.time()
    hour_ago = now_ts - 3600
    threat_count = sum(1 for ip, data in threats_module._threat_timeline.items() 
                      if data.get('last_seen', 0) > hour_ago)
    
    # Categorize signals
    protection_signals = []
    exposure_signals = []
    data_quality_signals = []
    
    # Protection signals (firewall activity, threats blocked)
    threats_blocked = fw_stats.get('threats_blocked', 0)
    if threats_blocked > 0:
        protection_signals.append(f"Firewall blocked {threats_blocked} known threats")
    
    if fw_stats.get('blocks', 0) > 10:
        protection_signals.append("Firewall actively blocking attacks")
    
    # Exposure signals (external connections, attack rate)
    if threat_count > 0:
        exposure_signals.append(f"{threat_count} active threats detected")
    
    if fw_stats.get('blocks_per_hour', 0) > 100:
        exposure_signals.append(f"High attack rate: {fw_stats['blocks_per_hour']}/hour")
    
    # Data Quality signals (feed health, visibility gaps)
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
            if alert.get('severity') == 'critical' and now_ts - alert.get('ts', 0) < 3600:
                recent_critical += 1
    if recent_critical > 0:
        exposure_signals.append(f"{recent_critical} critical alerts in last hour")
    
    # Determine overall state based on signals
    if recent_critical > 0 or threat_count > 5:
        overall_state = "UNDER PRESSURE"
    elif threat_count > 0 or fw_stats.get('blocks_per_hour', 0) > 100:
        overall_state = "DEGRADED"
    elif feeds_ok < feeds_total or fw_stats.get('blocks', 0) == 0:
        overall_state = "ELEVATED"
    elif threats_blocked > 0 and fw_stats.get('blocks', 0) > 0:
        overall_state = "STABLE"
    else:
        overall_state = "UNKNOWN"
    
    # Build contributing factors
    if protection_signals:
        contributing_factors.extend(protection_signals)
    if exposure_signals:
        contributing_factors.extend(exposure_signals)
    if data_quality_signals:
        contributing_factors.extend(data_quality_signals)
    
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
        'last_updated': time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(now))
    }
    
    # PERFORMANCE: Cache result before returning
    with _security_score_lock:
        _security_score_cache["data"] = result
        _security_score_cache["ts"] = now
    
    return result


# Legacy function for backward compatibility
def calculate_security_score():
    """Legacy wrapper for backward compatibility."""
    return calculate_security_observability()
