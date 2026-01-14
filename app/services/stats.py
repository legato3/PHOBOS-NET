"""Statistics service for PROX_NFDUMP application."""
import time
import threading
from app.db.sqlite import _get_firewall_block_stats
from app.utils.observability import instrument_service
# Import threat module to access globals
import app.services.threats as threats_module

# Cache for security score calculation (30s TTL to reduce redundant DB queries)
_security_score_cache = {"data": None, "ts": 0}
_security_score_lock = threading.Lock()
_SECURITY_SCORE_CACHE_TTL = 30  # 30 seconds


@instrument_service('calculate_security_score')
def calculate_security_score():
    """Calculate 0-100 security score based on current threat state and firewall activity.
    
    OBSERVABILITY: Instrumented to track execution time and call frequency.
    """
    # PERFORMANCE: Cache result for 30s to reduce redundant DB queries and timeline iterations
    now = time.time()
    with _security_score_lock:
        if _security_score_cache["data"] and now - _security_score_cache["ts"] < _SECURITY_SCORE_CACHE_TTL:
            return _security_score_cache["data"]
    
    score = 100
    reasons = []
    
    # Get firewall block stats (expensive DB query - cached at function level)
    fw_stats = _get_firewall_block_stats(hours=1)
    
    # PERFORMANCE: Compute active threat count once instead of filtering list comprehension each time
    now_ts = time.time()
    hour_ago = now_ts - 3600
    threat_count = sum(1 for ip, data in threats_module._threat_timeline.items() 
                      if data.get('last_seen', 0) > hour_ago)
    
    if threat_count > 0:
        penalty = min(40, threat_count * 10)
        score -= penalty
        reasons.append(f"-{penalty}: {threat_count} active threats")
    
    # POSITIVE: Firewall blocking known threats (+5 to +15 points)
    threats_blocked = fw_stats.get('threats_blocked', 0)
    if threats_blocked > 0:
        bonus = min(15, 5 + threats_blocked)
        score = min(100, score + bonus)
        reasons.append(f"+{bonus}: {threats_blocked} known threats blocked")
    
    # POSITIVE: Active firewall protection (+5 if blocking attacks)
    if fw_stats.get('blocks', 0) > 10:
        score = min(100, score + 5)
        reasons.append("+5: Firewall actively blocking")
    
    # WARNING: High attack rate (informational, no penalty if being blocked)
    if fw_stats.get('blocks_per_hour', 0) > 100:
        reasons.append(f"⚠️ High attack rate: {fw_stats['blocks_per_hour']}/hr")
    
    # Feed health penalty (up to -20 points)
    feeds_ok = sum(1 for f in threats_module._feed_status.values() if f.get('status') == 'ok')
    feeds_total = len(threats_module._feed_status)
    if feeds_total > 0:
        feed_ratio = feeds_ok / feeds_total
        if feed_ratio < 1.0:
            penalty = int((1 - feed_ratio) * 20)
            score -= penalty
            reasons.append(f"-{penalty}: {feeds_total - feeds_ok} feeds down")
    
    # Blocklist coverage bonus (+10 if >50K IPs)
    total_ips = threats_module._threat_status.get('size', 0)
    if total_ips >= 50000:
        score = min(100, score + 5)
        reasons.append("+5: Good blocklist coverage")
    elif total_ips < 10000:
        score -= 5
        reasons.append("-5: Low blocklist coverage")
    
    # Recent critical alerts penalty
    # PERFORMANCE: Use already-computed now_ts instead of calling time.time() again
    recent_critical = 0
    with threats_module._alert_history_lock:
        for alert in threats_module._alert_history:
            if alert.get('severity') == 'critical' and now_ts - alert.get('ts', 0) < 3600:
                recent_critical += 1
    if recent_critical > 0:
        penalty = min(30, recent_critical * 5)
        score -= penalty
        reasons.append(f"-{penalty}: {recent_critical} critical alerts")
    
    # Clamp to 0-100
    score = max(0, min(100, score))
    
    # Determine grade
    if score >= 90:
        grade = 'A'
        status = 'excellent'
    elif score >= 75:
        grade = 'B'
        status = 'good'
    elif score >= 60:
        grade = 'C'
        status = 'fair'
    elif score >= 40:
        grade = 'D'
        status = 'poor'
    else:
        grade = 'F'
        status = 'critical'
    
    result = {
        'score': score,
        'grade': grade,
        'status': status,
        'reasons': reasons,
        'threats_active': threat_count,
        'feeds_ok': feeds_ok if 'feeds_ok' in dir() else 0,
        'feeds_total': feeds_total if 'feeds_total' in dir() else 0,
        'blocklist_ips': total_ips,
        'firewall': fw_stats
    }
    
    # PERFORMANCE: Cache result before returning
    with _security_score_lock:
        _security_score_cache["data"] = result
        _security_score_cache["ts"] = now
    
    return result
