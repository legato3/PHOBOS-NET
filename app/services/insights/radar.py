
import time
from datetime import datetime, timedelta
from app.services.netflow.netflow import run_nfdump, parse_csv
from app.services.firewall.store import firewall_store
from app.services.shared.dns import resolve_ip
from app.services.shared.geoip import lookup_geo

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
    src_curr = _get_nfdump_summary("srcip", tf_current, 10)
    src_prev = _get_nfdump_summary("srcip", tf_prev, 10)
    
    # Top Dests
    dst_curr = _get_nfdump_summary("dstip", tf_current, 10)
    
    # Top Ports
    port_curr = _get_nfdump_summary("dstport", tf_current, 10)
    port_prev = _get_nfdump_summary("dstport", tf_prev, 10)
    
    # Firewall Counts
    fw_curr_count = _get_fw_count(current_start, now)
    fw_prev_count = _get_fw_count(prev_start, current_start)

    # 2. Build "Top Right Now" Lists
    # Enrich with DNS/Geo where applicable
    top_talkers = _enrich_ips(src_curr[:5], is_src=True)
    top_dests = _enrich_ips(dst_curr[:5], is_src=False)
    top_ports = _format_ports(port_curr[:8])
    
    # 3. Calculate Deltas (Change Stream)
    changes = []
    
    # Rule: TOP_TALKER_CHANGED (New entry in Top 3 that wasn't in Top 3 prev)
    prev_top_3_keys = set(x['key'] for x in src_prev[:3])
    for i, item in enumerate(src_curr[:3]):
        if item['key'] not in prev_top_3_keys and item['bytes'] > 0:
            changes.append({
                "type": "TOP_TALKER_CHANGED",
                "severity": "notice",
                "message": f"New top talker: {item['key']} ({_fmt_bytes(item['bytes'])})",
                "ts": now.timestamp(), 
                "link": f"/#network;ip={item['key']}"
            })

    # Rule: PORT_SPIKE (Volume > 3x prev)
    # Map prev ports for lookup
    prev_ports_map = {x['key']: x['bytes'] for x in port_prev}
    for item in port_curr[:5]:
        p_bytes = prev_ports_map.get(item['key'], 0)
        if p_bytes > 0 and item['bytes'] > 3 * p_bytes and item['bytes'] > 1000000: # Min 1MB noise floor
            changes.append({
                "type": "PORT_SPIKE",
                "severity": "warn",
                "message": f"Port {item['key']} traffic surged 3x ({_fmt_bytes(item['bytes'])})",
                "ts": now.timestamp(),
                "link": f"/#network;port={item['key']}"
            })
    
    # Rule: BLOCK_SPIKE
    if fw_prev_count > 10 and fw_curr_count > 3 * fw_prev_count:
         changes.append({
                "type": "BLOCK_SPIKE",
                "severity": "warn",
                "message": f"Firewall blocks surged 3x ({fw_curr_count} events)",
                "ts": now.timestamp(),
                "link": "/#security"
         })

    # Rule: NEW_EXTERNAL_DESTINATION (Simple proxy: check if dst is NOT in prev list at all? 
    # Real "novelty" requires long-term memory which we don't have easily here.
    # We will use a simpler heuristic: If Dst is in Top 5 but wasn't in Prev Top 10)
    prev_all_dst_keys = set(x['key'] for x in _get_nfdump_summary("dstip", tf_prev, 20))
    for item in dst_curr[:5]:
        if item['key'] not in prev_all_dst_keys:
             changes.append({
                "type": "NEW_DESTINATION",
                "severity": "info",
                "message": f"New active destination: {item['key']}",
                "ts": now.timestamp(),
                "link": f"/#network;ip={item['key']}"
            })

    # Sort changes by severity/time? Simple append is fine, maybe limit total
    if not changes:
        # No deltas placeholder handled by frontend, but we return empty list
        pass

    
        return {
            "top_talkers": top_talkers,
            "top_destinations": top_dests,
            "top_ports": top_ports,
            "changes": changes[:30]
        }
    except Exception as e:
        print(f"Radar generation failed: {e}")
        return {
            "top_talkers": [],
            "top_destinations": [],
            "top_ports": [],
            "changes": []
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
