
import time
import threading
from app.services.netflow.netflow import get_common_nfdump_data
from app.services.firewall.store import firewall_store
from app.services.shared.snmp import get_snmp_data
from app.services.shared.helpers import get_time_range

# Use a simple cache with TTL
_personality_cache = {"data": None, "ts": 0}
_personality_lock = threading.Lock()
_CACHE_TTL = 60

def generate_personality_profile(window='24h'):
    """
    Generate a 'personality' summary of the network based on aggregates.
    """
    now = time.time()
    
    # Check cache
    with _personality_lock:
        if _personality_cache["data"] and _personality_cache["window"] == window and (now - _personality_cache["ts"] < _CACHE_TTL):
            return _personality_cache["data"]

    # 1. Fetch Aggregates
    # NetFlow: Top Ports, Top Talkers (Sources)
    try:
        top_ports = get_common_nfdump_data('ports', window) # List of dicts {key: "443", bytes: ...}
    except Exception:
        top_ports = []
        
    try:
        top_talkers = get_common_nfdump_data('sources', window)
    except Exception:
        top_talkers = []

    # SNMP utilization (current snapshot, as we don't have historical aggregates easily accessible in this service context without specific DB queries, but user said "use existing aggregates")
    # We can check current utilization from get_snmp_data()
    snmp_data = get_snmp_data()
    
    # Firewall stats
    # firewall_store is in-memory ring buffer, so window might be limited by buffer size
    # We'll use what we have.
    fw_stats = firewall_store.get_counts()
    
    # 2. Analyze Traits
    traits = []
    evidence = {
        "top_ports": [],
        "external_ratio_pct": 0, # Placeholder
        "new_external_rate_per_hr": 0, # Placeholder
        "block_rate_per_min": 0,
        "block_spike_count": 0, # Placeholder
        "talker_churn": "low", # Placeholder
        "iface_saturation_minutes": 0 # Placeholder
    }
    
    # -- Trait: OUTBOUND_WEB_HEAVY --
    # Calculate pct of port 443 + 80
    total_bytes = sum(p.get('bytes', 0) for p in top_ports)
    web_bytes = sum(p.get('bytes', 0) for p in top_ports if p.get('key') in ['443', '80', '8080'])
    web_pct = (web_bytes / total_bytes * 100) if total_bytes > 0 else 0
    
    if web_pct >= 50:
        traits.append({
            "id": "OUTBOUND_WEB_HEAVY",
            "label": f"Web-dominant traffic ({web_pct:.1f}%)",
            "evidence": {"web_pct": web_pct}
        })
        
    # -- Trait: DNS_ACTIVE --
    dns_bytes = sum(p.get('bytes', 0) for p in top_ports if p.get('key') == '53')
    dns_pct = (dns_bytes / total_bytes * 100) if total_bytes > 0 else 0
    if dns_pct >= 5:
        traits.append({
            "id": "DNS_ACTIVE",
            "label": "High DNS activity",
            "evidence": {"dns_pct": dns_pct}
        })

    # -- Trait: FIREWALL_BLOCKS --
    total_blocks = fw_stats.get('by_action', {}).get('block', 0)
    # Estimate rate based on assumed availability of data logic in store (store doesn't give time range directly easily without iteration)
    # detailed iteration is expensive, so we use coarse stats
    if total_blocks < 10:
         traits.append({
            "id": "FIREWALL_QUIET",
            "label": "Firewall quiet",
            "evidence": {"blocks": total_blocks}
        })
    elif total_blocks > 1000:
         traits.append({
            "id": "FIREWALL_BUSY",
            "label": "High block rate",
            "evidence": {"blocks": total_blocks}
        })

    # Evidence Population
    evidence["top_ports"] = [{"port": int(p['key']), "pct": round(p['bytes']/total_bytes*100, 1)} for p in top_ports[:3]] if total_bytes > 0 else []
    evidence["block_rate_per_min"] = round(total_blocks / (24*60), 2) # Rough calc for 24h
    
    # -- Tone --
    if "FIREWALL_BUSY" in [t['id'] for t in traits]:
        tone = "High noise, active defense"
    elif web_pct > 70:
        tone = "Stable, web-focused traffic"
    else:
        tone = "Stable, low-noise network"

    # -- Confidence --
    # Simple heuristic: do we have netflow and snmp?
    has_netflow = len(top_ports) > 0
    has_snmp = snmp_data.get('available', False)
    
    if has_netflow and has_snmp:
        confidence = "high"
    elif has_netflow:
        confidence = "medium"
    else:
        confidence = "low"

    profile = {
        "window_sec": 86400 if window == '24h' else 604800,
        "tone": tone,
        "confidence": confidence,
        "traits": traits,
        "evidence": evidence,
        "generated_at": now
    }
    
    with _personality_lock:
        _personality_cache["data"] = profile
        _personality_cache["ts"] = now
        _personality_cache["window"] = window

    return profile
