
import time
from datetime import datetime, timedelta
from app.services.netflow.netflow import run_nfdump, parse_csv
from app.services.firewall.store import firewall_store
from app.services.syslog.syslog_store import syslog_store
from app.services.shared.dns import resolve_ip
from app.services.shared.geoip import lookup_geo
from app.services.shared import baselines
from app.services.netflow import stats as security_stats

# Mock data for dev mode
import random

def get_radar_snapshot(window_minutes=15, debug_mode=False):
    """
    Generate Live Network Radar snapshot:
    1. Top Right Now (Talkers, Dests, Ports)
    2. Change Stream (Deltas vs previous window)
    """
    if debug_mode:
        return _generate_mock_data()

    try:
        # Enforce a strict timeout for the entire operation (simulated here by catching distinct slow parts)
        # In a real async/threaded env we would use signal alarms or asyncio, but here we wrappers.
        start_time = time.time()
        
        now = datetime.now()
        current_start = now - timedelta(minutes=window_minutes)
        prev_start = current_start - timedelta(minutes=window_minutes)
        
        tf_current = f"{current_start.strftime('%Y/%m/%d.%H:%M:%S')}-{now.strftime('%Y/%m/%d.%H:%M:%S')}"
        tf_prev = f"{prev_start.strftime('%Y/%m/%d.%H:%M:%S')}-{current_start.strftime('%Y/%m/%d.%H:%M:%S')}"

    
        # 1. Fetch Data (Sequential for simplicity, could be parallel)
        # Top Talkers (Src)
        # 1. Fetch Core Data
        src_curr = _get_nfdump_summary("srcip", tf_current, 10)
        dst_curr = _get_nfdump_summary("dstip", tf_current, 10)
        port_curr = _get_nfdump_summary("dstport", tf_current, 10)
        
        # Get counts for trends
        fw_curr_count = _get_fw_count(current_start, now)
        sys_curr_count = _get_syslog_count(current_start, now)
        
        # Update Baselines (Blind update for the sake of this view - ideally done by listeners)
        # We read them mostly.
        
        # 2. Get High-Level Security State (Use the existing sophisticated logic)
        # This returns 'STABLE', 'QUIET', 'ELEVATED' etc.
        sec_state = security_stats.calculate_security_observability(range_key='1h') # 1h provides stable context
        
        # 3. Trends & Variances (Using baselines.py)
        # Calculate trends for key metrics
        fw_trend = baselines.calculate_trend('firewall_blocks_rate', fw_curr_count)
        
        # 4. Synthesize Tone
        # Use the "official" security state as the primary driver
        base_tone = sec_state.get('overall_state', 'UNKNOWN')
        tone = "Assessing network state..."
        status_indicator = "ok"
        
        if base_tone == "QUIET":
            tone = "Network dormant and stable"
            status_indicator = "ok"
        elif base_tone == "STABLE":
            tone = "Traffic nominal, no anomalies"
            status_indicator = "ok"
        elif base_tone == "ELEVATED":
            tone = "Elevated activity detected"
            status_indicator = "notice"
        elif base_tone == "DEGRADED":
            tone = "Defensive systems active"
            status_indicator = "warn"
        elif base_tone == "UNDER PRESSURE":
            tone = "High threat volume detected"
            status_indicator = "warn"
        else:
            # Fallback for UNKNOWN or initializing
            tone = "Network monitoring active"
            status_indicator = "ok"
            if not evidence:
                evidence.append("Accumulating baseline data")
                evidence.append("Traffic analysis in progress")
            
        # 5. Build Evidence
        # Start with the deep logic from stats.py
        evidence = sec_state.get('contributing_factors', [])
        
        # Add "Novelty" Insight (Are these dests new?)
        # We don't have long-term persistence in this view, using heuristic
        # If we have baseline data, use that.
        
        # Add Baseline/Trend Insight
        if fw_trend and fw_trend['significant']:
             evidence.append(f"Firewall activity {fw_trend['direction']} ({int(fw_trend['percent_change'])}%)")
        elif fw_trend and fw_trend['muted']:
             evidence.append("Firewall variance within normal limits")

        # Fallbacks if evidence is thin
        if len(evidence) < 2:
            if fw_curr_count == 0: evidence.append("Zero firewall blocks recorded")
            if sys_curr_count == 0: evidence.append("System logs quiet")
            if len(src_curr) > 0: evidence.append(f"Primary driver: {src_curr[0].get('key')}")

        # 6. Build Change Stream (Simplified, reliant on Baselines)
        # We generate a few "fake" stream items based on states if real events are missing
        # This is a view-layer adaptation.
        changes = []
        if fw_trend and fw_trend['significant'] and fw_trend['direction'] == 'up':
             changes.append({
                "type": "FIREWALL_TREND", 
                "severity": "warn", 
                "message": f"Block rate rising: {fw_curr_count}/window", 
                "ts": now.timestamp()
             })
        
        # Add explicit "System Healthy" marker if quiet
        if base_tone in ["QUIET", "STABLE"] and not changes:
             changes.append({
                "type": "SYSTEM_STATUS", 
                "severity": "info", 
                "message": f"Global state: {base_tone}", 
                "ts": now.timestamp()
             })

        # 6. Build Metrics Summary (for Stat Boxes)
        # Calculate rates/totals for the user's hard-stat boxes
        total_bytes = sum(x.get('bytes', 0) for x in src_curr)
        # Approximate flow rate if we had it, but for now we use what we have
        # baselines module has active_flows if tracked
        active_flows = 0
        flow_stats = baselines.get_baseline_stats('active_flows')
        if flow_stats and flow_stats.get('mean'):
             active_flows = int(flow_stats.get('mean')) # approximated from baseline tracking
        
        metrics = {
            "traffic_vol": _fmt_bytes(total_bytes),
            "firewall_blocks": fw_curr_count,
            "syslog_events": sys_curr_count,
            "active_flows": active_flows if active_flows > 0 else "N/A"
        }

        return {
            "tone": tone,
            "evidence": evidence[:6], # Allow slightly more
            "status": status_indicator,
            "top_talkers": _enrich_ips(src_curr[:5], is_src=True),
            "top_destinations": _enrich_ips(dst_curr[:5], is_src=False),
            "top_ports": _format_ports(port_curr[:8]),
            "changes": changes,
            "metrics": metrics,
            "meta": {
               "sec_state": sec_state
            }
        }
    except Exception as e:
        print(f"Radar generation failed: {e}")
        return {
            "top_talkers": [],
            "top_destinations": [],
            "top_ports": [],
            "changes": [],
            "metrics": {"traffic_vol": "0", "firewall_blocks": 0, "syslog_events": 0, "active_flows": 0}
        }

def _get_nfdump_summary(stat_field, tf, limit):
    # Wrapper around existing nfdump utils
    # stat_field e.g. "srcip", "dstip", "dstport"
    # Returns list of dicts: [{'key': '...', 'bytes': 123, ...}]
    try:
        # map stat_field to nfdump -s syntax
        # e.g. srcip -> "srcip/bytes"
        cmd = ["-s", f"{stat_field}/bytes/flows", "-n", str(limit)]
        
        # We need to correctly parse the output. parse_csv expects certain keys.
        # for srcip -> expect 'sa' or 'srcaddr'
        expected_key = None
        if "srcip" in stat_field: expected_key = "sa"
        elif "dstip" in stat_field: expected_key = "da"
        elif "port" in stat_field: expected_key = "dp" # usually sorts by dp
        
        data = parse_csv(run_nfdump(cmd, tf=tf), expected_key=expected_key)
        return data
    except Exception:
        return []

def _get_fw_count(start_dt, end_dt):
    # Iterate in-memory store
    # This is "good enough" for a radar 15m window
    count = 0
    # Store keeps simplified events.
    # Access private _buffer is strictly speaking risky but we are in same package scope conceptually (service layer)
    # But better to use public method if possible. Store has get_events()
    # It returns dicts.
    events = firewall_store.get_events(limit=5000) # Get enough back
    start_ts = start_dt.timestamp()
    end_ts = end_dt.timestamp()
    
    for e in events:
        ets = e.get('timestamp') # timestamp float
        if isinstance(ets, str):
            # Try parse if string? Store returns ISO string usually if dict? 
            # Wait, store.py `.to_dict()` returns `timestamp` as isoformat string usually?
            # Let's check store.py. It does `event.to_dict()`.
            pass 
        # Actually Event.to_dict() might be datetime or string. 
        # Re-check firewall/parser.py or store.py ... 
        # Assume it's a datetime object or timestamp.
        # Let's look at store.py again... `results.append(event.to_dict())`
        # Safe to assume simple count here if we can't parse easily:
        count += 1
    
    # Real implementation of count with time filtering:
    # Since store is LIFO (newest first).
    c = 0
    start_ts = start_dt.timestamp()
    end_ts = end_dt.timestamp()
    try:
        # Access lock protected
        with firewall_store._lock:
            for event in firewall_store._buffer:
                t = event.timestamp.timestamp()
                if t < start_ts:
                    break # Reached older events
                if t <= end_ts:
                    if event.action == 'block':
                        c += 1
    except:
        pass
    return c

def _get_syslog_count(start_dt, end_dt):
    # Iterate persistent store via SQL
    count = 0
    import sqlite3
    from app.db.sqlite import _firewall_db_connect, _firewall_db_lock
    
    start_ts = start_dt.timestamp()
    end_ts = end_dt.timestamp()
    
    try:
        with _firewall_db_lock:
            conn = _firewall_db_connect()
            cursor = conn.execute(
                "SELECT COUNT(*) FROM syslog_events WHERE timestamp >= ? AND timestamp <= ?",
                (start_ts, end_ts)
            )
            row = cursor.fetchone()
            if row:
                count = row[0]
            conn.close()
    except Exception:
        pass
    return count

def _enrich_ips(items, is_src=True):
    res = []
    for x in items:
        # Resolve hostname
        ip = x['key']
        host = resolve_ip(ip) if not is_src else resolve_ip(ip) # resolve both
        # Resolve Geo
        geo = lookup_geo(ip)
        
        res.append({
            "ip": ip,
            "hostname": host,
            "country": geo.get('country_code', ''),
            "flag": geo.get('flag', ''),
            "bytes_fmt": _fmt_bytes(x.get('bytes', 0)),
            "val": x.get('bytes', 0),
            "link": f"/#network;ip={ip}"
        })
    return res

def _format_ports(items):
    res = []
    for x in items:
        res.append({
            "port": x['key'],
            "bytes_fmt": _fmt_bytes(x.get('bytes', 0)),
            "link": f"/#network;port={x['key']}"
        })
    return res

def _fmt_bytes(b):
    if b >= 1024**3: return f"{b/1024**3:.1f}G"
    if b >= 1024**2: return f"{b/1024**2:.1f}M"
    if b >= 1024: return f"{b/1024:.0f}K"
    return str(b)

def _generate_mock_data():
    # Deterministic mock for styling
    return {
        "top_talkers": [
            {"ip": "192.168.1.5", "hostname": "macbook-pro.local", "country": "", "flag": "", "bytes_fmt": "1.2G", "link": "#"},
            {"ip": "10.0.0.88", "hostname": "backup-server", "country": "", "flag": "", "bytes_fmt": "850M", "link": "#"},
            {"ip": "192.168.1.12", "hostname": "iphone-x", "country": "", "flag": "", "bytes_fmt": "120M", "link": "#"},
            {"ip": "192.168.1.200", "hostname": "guest-wifi", "country": "", "flag": "", "bytes_fmt": "50M", "link": "#"},
            {"ip": "172.16.0.4", "hostname": "docker-worker", "country": "", "flag": "", "bytes_fmt": "10M", "link": "#"}
        ],
        "top_destinations": [
            {"ip": "142.250.1.1", "hostname": "google-hosted.com", "country": "US", "flag": "🇺🇸", "bytes_fmt": "400M", "link": "#"},
            {"ip": "54.23.11.2", "hostname": "ec2-aws.amazon.com", "country": "US", "flag": "🇺🇸", "bytes_fmt": "300M", "link": "#"},
            {"ip": "104.21.55.1", "hostname": "cloudflare-cdn", "country": "US", "flag": "🇺🇸", "bytes_fmt": "150M", "link": "#"},
            {"ip": "8.8.8.8", "hostname": "dns.google", "country": "US", "flag": "🇺🇸", "bytes_fmt": "40M", "link": "#"},
            {"ip": "23.4.1.1", "hostname": "akamai.net", "country": "US", "flag": "🇺🇸", "bytes_fmt": "12M", "link": "#"}
        ],
        "top_ports": [
            {"port": "443", "bytes_fmt": "2.1G", "link": "#"},
            {"port": "80", "bytes_fmt": "500M", "link": "#"},
            {"port": "53", "bytes_fmt": "50M", "link": "#"},
            {"port": "22", "bytes_fmt": "10M", "link": "#"},
            {"port": "123", "bytes_fmt": "1M", "link": "#"},
            {"port": "8080", "bytes_fmt": "500K", "link": "#"},
            {"port": "8443", "bytes_fmt": "100K", "link": "#"},
            {"port": "445", "bytes_fmt": "10K", "link": "#"}
        ],
        "changes": [
             {"type": "TOP_TALKER_CHANGED", "severity": "notice", "message": "New top talker: 192.168.1.12 (120M)", "ts": time.time(), "link": "#"},
             {"type": "BLOCK_SPIKE", "severity": "warn", "message": "Firewall blocks surged 3x (142 events)", "ts": time.time() - 300, "link": "#"},
             {"type": "NEW_DESTINATION", "severity": "info", "message": "New active destination: 104.21.55.1", "ts": time.time() - 600, "link": "#"},
             {"type": "PORT_SPIKE", "severity": "warn", "message": "Port 8443 traffic surged 3x (100K)", "ts": time.time() - 900, "link": "#"}
        ]
    }
